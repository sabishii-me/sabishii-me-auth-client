pub mod device_flow;
pub mod token_store;
pub mod types;

use anyhow::{anyhow, Result};
use types::AuthState;

pub use device_flow::DeviceFlow;
pub use token_store::TokenStore;
pub use types::{DeviceCodeResponse, TokenSet};

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

/// Extract the user ID from the stored access token (decoded from JWT `sub` claim).
pub fn get_user_id(app_name: &str) -> Result<String> {
    let state = TokenStore::new(app_name)
        .load()?
        .ok_or_else(|| anyhow!("Not logged in."))?;
    user_id_from_token(&state.token.access_token)
}

/// Decode a JWT access token and extract the `sub` claim as user ID.
pub fn user_id_from_token(access_token: &str) -> Result<String> {
    let parts: Vec<&str> = access_token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid JWT format"));
    }

    // Base64url decode the payload (no signature verification needed — we trust our own token)
    let payload = parts[1];
    let padded = match payload.len() % 4 {
        2 => format!("{payload}=="),
        3 => format!("{payload}="),
        _ => payload.to_string(),
    };
    let decoded = base64_decode(&padded)?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|e| anyhow!("Failed to parse JWT claims: {e}"))?;

    // Try common claim names for user ID
    let user_id = claims["sub"]
        .as_str()
        .or_else(|| claims["userId"].as_str())
        .or_else(|| claims["user_id"].as_str())
        .ok_or_else(|| anyhow!("No user ID claim found in token (tried sub, userId, user_id)"))?;

    Ok(user_id.to_string())
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    // base64url → standard base64
    let std_b64 = s.replace('-', "+").replace('_', "/");
    let mut out = Vec::new();
    let bytes = std_b64.as_bytes();
    let mut i = 0;
    while i + 3 < bytes.len() {
        let b = [
            b64_char(bytes[i])?,
            b64_char(bytes[i + 1])?,
            b64_char(bytes[i + 2])?,
            b64_char(bytes[i + 3])?,
        ];
        out.push((b[0] << 2) | (b[1] >> 4));
        if bytes[i + 2] != b'=' { out.push((b[1] << 4) | (b[2] >> 2)); }
        if bytes[i + 3] != b'=' { out.push((b[2] << 6) | b[3]); }
        i += 4;
    }
    Ok(out)
}

fn b64_char(c: u8) -> Result<u8> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        b'=' => Ok(0),
        _ => Err(anyhow!("Invalid base64 character: {c}")),
    }
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
