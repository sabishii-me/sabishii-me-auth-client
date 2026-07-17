use crate::{
    device_flow::{normalize_base_url, DeviceFlow},
    token_store::TokenStore,
    types,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;

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
pub struct LogoutResult {
    pub local_cleared: bool,
    pub remote_revoked: bool,
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

impl TryFrom<DeviceCodeResponse> for types::DeviceCodeResponse {
    type Error = Error;

    fn try_from(r: DeviceCodeResponse) -> Result<Self> {
        Ok(Self {
            device_code: r.device_code,
            user_code: r.user_code,
            verification_uri: r.verification_uri,
            verification_uri_complete: r.verification_uri_complete,
            expires_in: u64::try_from(r.expires_in)
                .map_err(|_| Error::from_reason("Device code expiry is invalid"))?,
            interval: r
                .interval
                .map(u64::try_from)
                .transpose()
                .map_err(|_| Error::from_reason("Device polling interval is invalid"))?,
        })
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

impl From<types::LogoutResult> for LogoutResult {
    fn from(result: types::LogoutResult) -> Self {
        Self {
            local_cleared: result.local_cleared,
            remote_revoked: result.remote_revoked,
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
    storage_url: String,
    client_id: String,
}

#[napi]
impl SabishiiAuth {
    #[napi(constructor)]
    pub fn new(base_url: String, client_id: String) -> Result<Self> {
        if client_id.trim().is_empty() {
            return Err(Error::from_reason("Client ID must not be empty"));
        }
        let storage_url = base_url.trim().to_string();
        let base_url =
            normalize_base_url(&storage_url).map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(Self {
            base_url,
            storage_url,
            client_id,
        })
    }

    /// Request a device code to start the device authorization flow.
    #[napi]
    pub async fn request_device_code(&self) -> Result<DeviceCodeResponse> {
        let flow = DeviceFlow::new(&self.base_url, &self.client_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let response = flow
            .request_device_code()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(response.into())
    }

    /// Poll using only a device code. Deprecated; use pollForDeviceToken so
    /// server-provided expiry and interval values are preserved.
    #[napi]
    pub async fn poll_for_token(&self, device_code: String) -> Result<TokenSet> {
        let device = types::DeviceCodeResponse {
            device_code,
            user_code: String::new(),
            verification_uri: String::new(),
            verification_uri_complete: None,
            expires_in: 30 * 60,
            interval: Some(5),
        };
        self.poll_and_store(device).await
    }

    /// Poll for a token using the complete server-provided device response.
    #[napi]
    pub async fn poll_for_device_token(&self, device: DeviceCodeResponse) -> Result<TokenSet> {
        self.poll_and_store(types::DeviceCodeResponse::try_from(device)?)
            .await
    }

    /// Refresh the access token using a stored single-use refresh token.
    #[napi]
    pub async fn refresh_token(&self) -> Result<TokenSet> {
        let store = TokenStore::new(&self.storage_url, &self.client_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let state = store
            .load()
            .map_err(|e| Error::from_reason(e.to_string()))?
            .ok_or_else(|| Error::from_reason("Not logged in"))?;

        let refresh_token = state
            .token
            .refresh_token
            .ok_or_else(|| Error::from_reason("No refresh token available"))?;

        let flow = DeviceFlow::new(&self.base_url, &self.client_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let token = flow
            .refresh_token(&refresh_token)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let new_state = crate::make_auth_state(token.clone());
        store
            .save(&new_state)
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(token.into())
    }

    /// Clear local credentials and report whether remote revocation succeeded.
    #[napi]
    pub async fn logout(&self) -> Result<LogoutResult> {
        crate::logout(&self.storage_url, &self.client_id)
            .await
            .map(Into::into)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Load the currently stored auth state from keychain.
    #[napi]
    pub fn load_state(&self) -> Result<Option<AuthState>> {
        let store = TokenStore::new(&self.storage_url, &self.client_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let state = store
            .load()
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(state.map(Into::into))
    }

    /// Check if the stored token is expired.
    #[napi]
    pub fn is_token_expired(&self) -> Result<bool> {
        let store = TokenStore::new(&self.storage_url, &self.client_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let state = store
            .load()
            .map_err(|e| Error::from_reason(e.to_string()))?
            .ok_or_else(|| Error::from_reason("Not logged in"))?;
        Ok(crate::is_token_expired(&state))
    }

    /// Get the current user's profile.
    #[napi]
    pub async fn get_user_profile(&self) -> Result<UserProfile> {
        crate::get_user_profile(&self.storage_url, &self.client_id)
            .await
            .map(Into::into)
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Get just the user ID.
    #[napi]
    pub async fn get_user_id(&self) -> Result<String> {
        crate::get_user_id(&self.storage_url, &self.client_id)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }
}

impl SabishiiAuth {
    async fn poll_and_store(&self, device: types::DeviceCodeResponse) -> Result<TokenSet> {
        let flow = DeviceFlow::new(&self.base_url, &self.client_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let token = flow
            .poll_for_token(&device)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        let store = TokenStore::new(&self.storage_url, &self.client_id)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        let state = crate::make_auth_state(token.clone());
        store
            .save(&state)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        Ok(token.into())
    }
}

/// Standalone function for the full interactive device login flow.
#[napi]
pub async fn device_login(base_url: String, client_id: String) -> Result<AuthState> {
    crate::login(&base_url, &client_id)
        .await
        .map(Into::into)
        .map_err(|e| Error::from_reason(e.to_string()))
}

/// Standalone function to clear local credentials and attempt remote revocation.
#[napi]
pub async fn device_logout(base_url: String, client_id: String) -> Result<LogoutResult> {
    crate::logout(&base_url, &client_id)
        .await
        .map(Into::into)
        .map_err(|e| Error::from_reason(e.to_string()))
}
