pub mod device_flow;
pub mod token_store;
pub mod types;

use anyhow::{anyhow, Result};
use types::AuthState;

pub use device_flow::DeviceFlow;
pub use token_store::TokenStore;
pub use types::{DeviceCodeResponse, TokenSet, UserProfile};

/// Run the full device login flow and store the token.
/// `base_url` — e.g. "https://account.sabishii.me/auth"
/// `client_id` — e.g. "sabishii-me-cli" or "sabishii-chat-cli"
/// `app_name`  — keychain namespace, same as client_id
pub async fn login(base_url: &str, client_id: &str, app_name: &str) -> Result<AuthState> {
    let flow = DeviceFlow::new(base_url, client_id);
    let store = TokenStore::new(app_name);

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

/// Logout — revoke refresh token server-side and clear keychain.
pub async fn logout(base_url: &str, client_id: &str, app_name: &str) -> Result<()> {
    let store = TokenStore::new(app_name);

    if let Some(state) = store.load()? {
        if let Some(refresh_token) = state.token.refresh_token {
            let flow = DeviceFlow::new(base_url, client_id);
            if let Err(e) = flow.revoke_token(&refresh_token).await {
                eprintln!("Warning: server revocation failed: {e}");
            }
        }
    }

    store.clear()?;
    println!("Logged out.");
    Ok(())
}

/// Refresh the stored access token using the stored refresh token.
pub async fn refresh(base_url: &str, client_id: &str, app_name: &str) -> Result<()> {
    let store = TokenStore::new(app_name);
    let state = store.load()?.ok_or_else(|| anyhow!("Not logged in."))?;

    let refresh_token = state
        .token
        .refresh_token
        .ok_or_else(|| anyhow!("No refresh token stored."))?;

    let flow = DeviceFlow::new(base_url, client_id);
    let token = flow.refresh_token(&refresh_token).await?;
    let new_state = make_auth_state(token);
    store.save(&new_state)?;

    println!("Token refreshed. Expires at: {}", new_state.expires_at);
    Ok(())
}

/// Load the current auth state — returns None if not logged in.
pub fn load_state(app_name: &str) -> Result<Option<AuthState>> {
    TokenStore::new(app_name).load()
}

/// Check if stored token is expired.
pub fn is_token_expired(state: &AuthState) -> bool {
    let now = chrono::Utc::now().to_rfc3339();
    state.expires_at < now
}

/// Fetch the full user profile from the auth service.
/// `base_url` — e.g. "https://account.sabishii.me/auth" (base, /me is at parent)
pub async fn get_user_profile(base_url: &str, app_name: &str) -> Result<types::UserProfile> {
    let state = TokenStore::new(app_name)
        .load()?
        .ok_or_else(|| anyhow!("Not logged in."))?;

    // /me is at the parent of /auth — strip the trailing path segment
    let me_url = base_url.trim_end_matches("/auth").to_string() + "/me";

    let client = reqwest::Client::new();
    let resp = client
        .get(&me_url)
        .bearer_auth(&state.token.access_token)
        .send()
        .await?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("Failed to fetch user profile: {body}"));
    }

    #[derive(serde::Deserialize)]
    struct MeResponse { user: types::UserProfile }
    let me: MeResponse = resp.json().await?;
    Ok(me.user)
}

/// Get just the user ID from the auth service.
pub async fn get_user_id(base_url: &str, app_name: &str) -> Result<String> {
    Ok(get_user_profile(base_url, app_name).await?.id)
}

fn make_auth_state(token: types::TokenSet) -> AuthState {
    let expires_at = {
        let secs = token.expires_in.unwrap_or(3600);
        let received = chrono::DateTime::parse_from_rfc3339(&token.received_at)
            .unwrap_or_else(|_| chrono::Utc::now().into());
        (received + chrono::Duration::seconds(secs as i64)).to_rfc3339()
    };
    AuthState { token, expires_at }
}
