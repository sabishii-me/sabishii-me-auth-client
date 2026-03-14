use anyhow::{anyhow, Result};
use reqwest::Client;
use tokio::time::{sleep, Duration};

use crate::types::{DeviceCodeResponse, TokenErrorResponse, TokenSet};

const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

pub struct DeviceFlow {
    client: Client,
    base_url: String,
    client_id: String,
}

impl DeviceFlow {
    pub fn new(base_url: &str, client_id: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.to_string(),
            client_id: client_id.to_string(),
        }
    }

    /// Step 1 — request a device code
    pub async fn request_device_code(&self) -> Result<DeviceCodeResponse> {
        let resp = self
            .client
            .post(format!("{}/device/code", self.base_url))
            .json(&serde_json::json!({ "client_id": self.client_id }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Device code request failed: {body}"));
        }

        Ok(resp.json::<DeviceCodeResponse>().await?)
    }

    /// Step 2 — poll until approved or expired
    pub async fn poll_for_token(&self, device: &DeviceCodeResponse) -> Result<TokenSet> {
        let interval_secs = device.interval.unwrap_or(DEFAULT_POLL_INTERVAL_SECS);
        let expires_at = std::time::Instant::now() + Duration::from_secs(device.expires_in);

        loop {
            sleep(Duration::from_secs(interval_secs)).await;

            if std::time::Instant::now() >= expires_at {
                return Err(anyhow!("Device code expired. Please login again."));
            }

            let resp = self
                .client
                .post(format!("{}/device/token", self.base_url))
                .json(&serde_json::json!({
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": &device.device_code,
                    "client_id": self.client_id,
                }))
                .send()
                .await?;

            if resp.status().is_success() {
                let mut token = resp.json::<TokenSet>().await?;
                token.received_at = chrono::Utc::now().to_rfc3339();
                return Ok(token);
            }

            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            if status.as_u16() == 202 || body.is_empty() {
                continue;
            }

            let err: TokenErrorResponse = serde_json::from_str(&body)
                .map_err(|e| anyhow!("Unexpected response: {e}\nbody: {body}"))?;

            match err.error.as_str() {
                "authorization_pending" => continue,
                "slow_down" => { sleep(Duration::from_secs(5)).await; continue; }
                "expired_token" => return Err(anyhow!("Device code expired. Please login again.")),
                "access_denied"  => return Err(anyhow!("Authorization was denied.")),
                other => {
                    let desc = err.error_description.unwrap_or_default();
                    return Err(anyhow!("Token error: {other} — {desc}"));
                }
            }
        }
    }

    /// Refresh an access token using a refresh token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenSet> {
        let resp = self
            .client
            .post(format!("{}/device/refresh", self.base_url))
            .json(&serde_json::json!({
                "client_id": self.client_id,
                "refresh_token": refresh_token,
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Token refresh failed: {body}"));
        }

        let mut token = resp.json::<TokenSet>().await?;
        token.received_at = chrono::Utc::now().to_rfc3339();
        Ok(token)
    }

    /// Revoke a refresh token server-side
    pub async fn revoke_token(&self, refresh_token: &str) -> Result<()> {
        let resp = self
            .client
            .post(format!("{}/device/revoke", self.base_url))
            .json(&serde_json::json!({
                "client_id": self.client_id,
                "token": refresh_token,
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("Token revocation failed: {body}"));
        }

        Ok(())
    }
}
