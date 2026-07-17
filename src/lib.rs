pub mod device_flow;
#[cfg(feature = "napi")]
pub use crate::napi::*;
#[cfg(feature = "napi")]
mod napi;
pub mod token_store;
pub mod types;

use anyhow::{anyhow, Result};
use types::AuthState as CoreAuthState;

pub use device_flow::DeviceFlow;
pub use token_store::TokenStore;
pub use types::{DeviceCodeResponse, LogoutResult, TokenSet, UserProfile};

/// Run the full device login flow and store the token.
/// `base_url` — account origin, e.g. "https://account.sabishii.me"
/// `client_id` — e.g. "sabishii-account-cli" or "sabishii-chat-cli"
pub async fn login(base_url: &str, client_id: &str) -> Result<CoreAuthState> {
    let flow = DeviceFlow::new(base_url, client_id)?;
    let store = TokenStore::new(base_url, client_id)?;

    println!("Requesting device code...");
    let device = flow.request_device_code().await?;

    println!("\nOpen this URL to authorize this device:\n");
    if let Some(ref complete) = device.verification_uri_complete {
        println!("  {complete}");
    } else {
        println!("  {}", device.verification_uri);
        println!("\nEnter code: {}", device.user_code);
    }
    println!("\nWaiting for authorization...");

    let token = flow.poll_for_token(&device).await?;
    let state = make_auth_state(token);
    store.save(&state)?;

    println!("\nLogged in successfully.");
    Ok(state)
}

/// Revoke the refresh token when possible, then clear the local keychain entry.
pub async fn logout(base_url: &str, client_id: &str) -> Result<LogoutResult> {
    let store = TokenStore::new(base_url, client_id)?;
    let refresh_token = store.load()?.and_then(|state| state.token.refresh_token);

    // Local logout is authoritative for this installation and must not wait on
    // the network. Capture the refresh token, clear the keyring, then attempt
    // best-effort remote revocation with the bounded HTTP client.
    store.clear()?;
    let remote_revoked = if let Some(refresh_token) = refresh_token {
        let flow = DeviceFlow::new(base_url, client_id)?;
        flow.revoke_token(&refresh_token).await.is_ok()
    } else {
        false
    };

    Ok(LogoutResult {
        local_cleared: true,
        remote_revoked,
    })
}

/// Refresh the stored access token using the stored refresh token.
pub async fn refresh(base_url: &str, client_id: &str) -> Result<()> {
    let store = TokenStore::new(base_url, client_id)?;
    let state = store.load()?.ok_or_else(|| anyhow!("Not logged in."))?;

    let refresh_token = state
        .token
        .refresh_token
        .ok_or_else(|| anyhow!("No refresh token stored."))?;

    let flow = DeviceFlow::new(base_url, client_id)?;
    let token = flow.refresh_token(&refresh_token).await?;
    let new_state = make_auth_state(token);
    store.save(&new_state)?;

    println!("Token refreshed. Expires at: {}", new_state.expires_at);
    Ok(())
}

/// Load the current auth state — returns None if not logged in.
pub fn load_state(base_url: &str, client_id: &str) -> Result<Option<CoreAuthState>> {
    TokenStore::new(base_url, client_id)?.load()
}

/// Check if a stored token is expired. Malformed expiry values fail closed.
pub fn is_token_expired(state: &CoreAuthState) -> bool {
    chrono::DateTime::parse_from_rfc3339(&state.expires_at)
        .map(|expires_at| expires_at <= chrono::Utc::now())
        .unwrap_or(true)
}

/// Fetch the full user profile from the canonical account endpoint.
/// `base_url` — account origin, e.g. "https://account.sabishii.me".
pub async fn get_user_profile(base_url: &str, client_id: &str) -> Result<types::UserProfile> {
    let state = TokenStore::new(base_url, client_id)?
        .load()?
        .ok_or_else(|| anyhow!("Not logged in."))?;
    let profile_url = user_profile_url(base_url)?;

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|_| anyhow!("Failed to initialize the authentication client"))?;
    let resp = client
        .get(&profile_url)
        .bearer_auth(&state.token.access_token)
        .send()
        .await
        .map_err(|_| anyhow!("Failed to fetch user profile due to a network error"))?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Failed to fetch user profile (HTTP {})",
            resp.status().as_u16()
        ));
    }

    #[derive(serde::Deserialize)]
    struct UserResponse {
        user: types::UserProfile,
    }
    let response: UserResponse = resp
        .json()
        .await
        .map_err(|_| anyhow!("User profile response was invalid"))?;
    Ok(response.user)
}

fn user_profile_url(base_url: &str) -> Result<String> {
    Ok(format!(
        "{}/user",
        device_flow::normalize_base_url(base_url)?
    ))
}

/// Get just the user ID from the auth service.
pub async fn get_user_id(base_url: &str, client_id: &str) -> Result<String> {
    Ok(get_user_profile(base_url, client_id).await?.id)
}

fn make_auth_state(token: types::TokenSet) -> CoreAuthState {
    let expires_at = {
        let secs = token.expires_in.unwrap_or(3600);
        let received = chrono::DateTime::parse_from_rfc3339(&token.received_at)
            .unwrap_or_else(|_| chrono::Utc::now().into());
        (received + chrono::Duration::seconds(secs as i64)).to_rfc3339()
    };
    CoreAuthState { token, expires_at }
}

#[cfg(test)]
mod tests {
    use super::{is_token_expired, user_profile_url};
    use crate::types::{AuthState, TokenSet};

    fn state(expires_at: &str) -> AuthState {
        AuthState {
            token: TokenSet {
                access_token: "synthetic-access-marker".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: Some(60),
                refresh_token: None,
                scope: None,
                received_at: chrono::Utc::now().to_rfc3339(),
            },
            expires_at: expires_at.to_string(),
        }
    }

    #[test]
    fn malformed_expiry_fails_closed() {
        assert!(is_token_expired(&state("not-a-timestamp")));
    }

    #[test]
    fn profile_uses_the_canonical_user_route() {
        assert_eq!(
            user_profile_url("https://account.sabishii.me/").unwrap(),
            "https://account.sabishii.me/user"
        );
    }

    #[test]
    fn future_and_past_offsets_are_compared_as_instants() {
        let future = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        let past = (chrono::Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        assert!(!is_token_expired(&state(&future)));
        assert!(is_token_expired(&state(&past)));
    }
}
