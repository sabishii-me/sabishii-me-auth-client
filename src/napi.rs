use napi::bindgen_prelude::*;
use napi_derive::napi;
use crate::{device_flow::DeviceFlow, token_store::TokenStore, types};

#[napi(object)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: i64,
    pub interval: Option<i64>,
}

#[napi(object)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: Option<i64>,
    pub scope: Option<String>,
    pub received_at: String,
}

#[napi(object)]
pub struct AuthState {
    pub token: TokenSet,
    pub expires_at: String,
}

#[napi(object)]
pub struct UserProfile {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub image: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<types::DeviceCodeResponse> for DeviceCodeResponse {
    fn from(r: types::DeviceCodeResponse) -> Self {
        Self {
            device_code: r.device_code,
            user_code: r.user_code,
            verification_uri: r.verification_uri,
            verification_uri_complete: r.verification_uri_complete,
            expires_in: r.expires_in as i64,
            interval: r.interval.map(|i| i as i64),
        }
    }
}

impl From<types::TokenSet> for TokenSet {
    fn from(t: types::TokenSet) -> Self {
        Self {
            access_token: t.access_token,
            refresh_token: t.refresh_token,
            token_type: t.token_type,
            expires_in: t.expires_in.map(|e| e as i64),
            scope: t.scope,
            received_at: t.received_at,
        }
    }
}

impl From<types::AuthState> for AuthState {
    fn from(s: types::AuthState) -> Self {
        Self {
            token: s.token.into(),
            expires_at: s.expires_at,
        }
    }
}

impl From<types::UserProfile> for UserProfile {
    fn from(p: types::UserProfile) -> Self {
        Self {
            id: p.id,
            email: p.email,
            email_verified: p.email_verified,
            name: Some(p.name),
            image: p.image,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[napi]
pub struct SabishiiAuth {
    base_url: String,
    client_id: String,
}

#[napi]
impl SabishiiAuth {
    #[napi(constructor)]
    pub fn new(base_url: String, client_id: String) -> Self {
        Self { base_url, client_id }
    }

    /// Request a device code to start the device authorization flow.
    #[napi]
    pub async fn request_device_code(&self) -> Result<DeviceCodeResponse> {
        let flow = DeviceFlow::new(&self.base_url, &self.client_id);
        let response = flow.request_device_code()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(response.into())
    }

    /// Poll for token after user authorizes the device.
    #[napi]
    pub async fn poll_for_token(&self, device_code: String) -> Result<TokenSet> {
        let flow = DeviceFlow::new(&self.base_url, &self.client_id);
        
        // Create minimal DeviceCodeResponse for polling
        let device = types::DeviceCodeResponse {
            device_code,
            user_code: String::new(),
            verification_uri: String::new(),
            verification_uri_complete: None,
            expires_in: 600,
            interval: Some(5),
        };

        let token = flow.poll_for_token(&device)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        
        // Save token to keychain
        let store = TokenStore::new(&self.base_url, &self.client_id);
        let state = crate::make_auth_state(token.clone());
        store.save(&state).map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(token.into())
    }

    /// Refresh the access token using a stored refresh token.
    #[napi]
    pub async fn refresh_token(&self) -> Result<TokenSet> {
        let store = TokenStore::new(&self.base_url, &self.client_id);
        let state = store.load()
            .map_err(|e| Error::from_reason(e.to_string()))?
            .ok_or_else(|| Error::from_reason("Not logged in"))?;

        let refresh_token = state.token.refresh_token
            .ok_or_else(|| Error::from_reason("No refresh token available"))?;

        let flow = DeviceFlow::new(&self.base_url, &self.client_id);
        let token = flow.refresh_token(&refresh_token)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        // Save new token to keychain
        let new_state = crate::make_auth_state(token.clone());
        store.save(&new_state).map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(token.into())
    }

    /// Revoke the refresh token and clear stored credentials.
    #[napi]
    pub async fn logout(&self) -> Result<()> {
        let store = TokenStore::new(&self.base_url, &self.client_id);

        if let Some(state) = store.load().map_err(|e| Error::from_reason(e.to_string()))? {
            if let Some(refresh_token) = state.token.refresh_token {
                let flow = DeviceFlow::new(&self.base_url, &self.client_id);
                // Ignore revocation errors — clear local state regardless
                let _ = flow.revoke_token(&refresh_token).await;
            }
        }

        store.clear().map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(())
    }

    /// Load the currently stored auth state from keychain.
    #[napi]
    pub fn load_state(&self) -> Result<Option<AuthState>> {
        let store = TokenStore::new(&self.base_url, &self.client_id);
        let state = store.load().map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(state.map(|s| s.into()))
    }

    /// Check if the stored token is expired.
    #[napi]
    pub fn is_token_expired(&self) -> Result<bool> {
        let store = TokenStore::new(&self.base_url, &self.client_id);
        let state = store.load()
            .map_err(|e| Error::from_reason(e.to_string()))?
            .ok_or_else(|| Error::from_reason("Not logged in"))?;

        let now = chrono::Utc::now().to_rfc3339();
        Ok(state.expires_at < now)
    }

    /// Get the current user's profile.
    #[napi]
    pub async fn get_user_profile(&self) -> Result<UserProfile> {
        let profile = crate::get_user_profile(&self.base_url, &self.client_id)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(profile.into())
    }

    /// Get just the user ID.
    #[napi]
    pub async fn get_user_id(&self) -> Result<String> {
        crate::get_user_id(&self.base_url, &self.client_id)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}

/// Standalone function for full device login flow.
#[napi]
pub async fn device_login(
    base_url: String,
    client_id: String,
) -> Result<AuthState> {
    let state = crate::login(&base_url, &client_id)
        .await
        .map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(state.into())
}

/// Standalone function to logout.
#[napi]
pub async fn device_logout(
    base_url: String,
    client_id: String,
) -> Result<()> {
    crate::logout(&base_url, &client_id)
        .await
        .map_err(|e| Error::from_reason(e.to_string()))
}
