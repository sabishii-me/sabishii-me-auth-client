use anyhow::{anyhow, Result};
use reqwest::{Client, StatusCode, Url};
use tokio::time::{sleep, Duration, Instant};

use crate::types::{DeviceCodeResponse, TokenErrorResponse, TokenSet};

const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
const SLOW_DOWN_INCREMENT_SECS: u64 = 5;
const CONNECT_TIMEOUT_SECS: u64 = 5;
const REQUEST_TIMEOUT_SECS: u64 = 20;

pub struct DeviceFlow {
    client: Client,
    base_url: String,
    client_id: String,
}

impl DeviceFlow {
    pub fn new(base_url: &str, client_id: &str) -> Result<Self> {
        if client_id.trim().is_empty() {
            return Err(anyhow!("Client ID must not be empty"));
        }

        let client = Client::builder()
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .map_err(|_| anyhow!("Failed to initialize the authentication client"))?;

        Ok(Self {
            client,
            base_url: normalize_base_url(base_url)?,
            client_id: client_id.to_string(),
        })
    }

    /// Step 1 — request a device code.
    pub async fn request_device_code(&self) -> Result<DeviceCodeResponse> {
        let resp = self
            .client
            .post(self.endpoint("/auth/device/code"))
            .json(&serde_json::json!({ "client_id": self.client_id }))
            .send()
            .await
            .map_err(|_| anyhow!("Device code request failed due to a network error"))?;

        if !resp.status().is_success() {
            return Err(safe_http_error("Device code request failed", resp.status()));
        }

        resp.json::<DeviceCodeResponse>()
            .await
            .map_err(|_| anyhow!("Device code response was invalid"))
    }

    /// Step 2 — poll until approved or expired.
    pub async fn poll_for_token(&self, device: &DeviceCodeResponse) -> Result<TokenSet> {
        if device.expires_in == 0 {
            return Err(anyhow!("Device code expired. Please login again."));
        }

        let mut interval_secs = device.interval.unwrap_or(DEFAULT_POLL_INTERVAL_SECS).max(1);
        let expires_at = Instant::now() + Duration::from_secs(device.expires_in);

        loop {
            let now = Instant::now();
            if now >= expires_at {
                return Err(anyhow!("Device code expired. Please login again."));
            }

            sleep(Duration::from_secs(interval_secs).min(expires_at - now)).await;
            if Instant::now() >= expires_at {
                return Err(anyhow!("Device code expired. Please login again."));
            }

            let resp = self
                .client
                .post(self.endpoint("/auth/device/token"))
                .json(&serde_json::json!({
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": &device.device_code,
                    "client_id": self.client_id,
                }))
                .send()
                .await
                .map_err(|_| {
                    anyhow!("Device authorization polling failed due to a network error")
                })?;

            if resp.status().is_success() {
                let mut token = resp
                    .json::<TokenSet>()
                    .await
                    .map_err(|_| anyhow!("Device token response was invalid"))?;
                token.received_at = chrono::Utc::now().to_rfc3339();
                return Ok(token);
            }

            let status = resp.status();
            let error = resp
                .json::<TokenErrorResponse>()
                .await
                .map_err(|_| safe_http_error("Unexpected device token response", status))?;

            // OAuth device errors are defined as HTTP 400 responses. Never
            // turn a forged 5xx or redirect response into an endless retry.
            if status != StatusCode::BAD_REQUEST {
                return Err(safe_http_error("Unexpected device token response", status));
            }

            match error.error.as_str() {
                "authorization_pending" => continue,
                "slow_down" => {
                    interval_secs = next_poll_interval(interval_secs);
                    continue;
                }
                "expired_token" => return Err(anyhow!("Device code expired. Please login again.")),
                "access_denied" => return Err(anyhow!("Authorization was denied.")),
                "invalid_request" => {
                    return Err(anyhow!("Device authorization request was invalid."))
                }
                "invalid_client" => {
                    return Err(anyhow!("Device authorization client was rejected."))
                }
                "invalid_grant" => return Err(anyhow!("Device authorization grant was rejected.")),
                "server_error" => {
                    return Err(anyhow!(
                        "The account service could not complete device authorization."
                    ))
                }
                _ => return Err(safe_http_error("Unexpected device token response", status)),
            }
        }
    }

    /// Refresh an access token using a single-use refresh token.
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenSet> {
        let resp = self
            .client
            .post(self.endpoint("/auth/device/refresh"))
            .json(&serde_json::json!({
                "client_id": self.client_id,
                "refresh_token": refresh_token,
            }))
            .send()
            .await
            .map_err(|_| anyhow!("Token refresh failed due to a network error"))?;

        if !resp.status().is_success() {
            return Err(safe_http_error("Token refresh failed", resp.status()));
        }

        let mut token = resp
            .json::<TokenSet>()
            .await
            .map_err(|_| anyhow!("Token refresh response was invalid"))?;
        token.received_at = chrono::Utc::now().to_rfc3339();
        Ok(token)
    }

    /// Revoke a refresh token server-side.
    pub async fn revoke_token(&self, refresh_token: &str) -> Result<()> {
        let resp = self
            .client
            .post(self.endpoint("/auth/device/revoke"))
            .json(&serde_json::json!({
                "client_id": self.client_id,
                "token": refresh_token,
                "token_type_hint": "refresh_token",
            }))
            .send()
            .await
            .map_err(|_| anyhow!("Token revocation failed due to a network error"))?;

        if !resp.status().is_success() {
            return Err(safe_http_error("Token revocation failed", resp.status()));
        }

        Ok(())
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

pub fn normalize_base_url(base_url: &str) -> Result<String> {
    let mut url =
        Url::parse(base_url.trim()).map_err(|_| anyhow!("Account service URL is invalid"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("Account service URL must include a host"))?;

    let local_http = url.scheme() == "http"
        && (host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1");
    if url.scheme() != "https" && !local_http {
        return Err(anyhow!(
            "Account service URL must use HTTPS unless it is a loopback address"
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(anyhow!("Account service URL must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(anyhow!(
            "Account service URL must not contain a query or fragment"
        ));
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err(anyhow!(
            "Account service URL must be an origin without a path"
        ));
    }

    url.set_path("");
    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn next_poll_interval(current: u64) -> u64 {
    current.saturating_add(SLOW_DOWN_INCREMENT_SECS)
}

fn safe_http_error(operation: &str, status: StatusCode) -> anyhow::Error {
    anyhow!("{operation} (HTTP {})", status.as_u16())
}

#[cfg(test)]
mod tests {
    use super::{next_poll_interval, normalize_base_url, DeviceFlow};
    use crate::types::DeviceCodeResponse;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        thread,
    };

    fn spawn_server(responses: Vec<(&'static str, &'static str)>) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = Arc::clone(&requests);
        thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 4096];
                let _ = stream.read(&mut buffer);
                request_count.fetch_add(1, Ordering::SeqCst);
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ).unwrap();
                stream.flush().unwrap();
            }
        });
        (format!("http://{address}"), requests)
    }

    #[test]
    fn normalizes_account_origins() {
        assert_eq!(
            normalize_base_url("https://account.sabishii.me/").unwrap(),
            "https://account.sabishii.me"
        );
        assert_eq!(
            normalize_base_url("http://localhost:6001/").unwrap(),
            "http://localhost:6001"
        );
        assert_eq!(
            normalize_base_url("http://127.0.0.1:6001").unwrap(),
            "http://127.0.0.1:6001"
        );
    }

    #[test]
    fn rejects_unsafe_or_ambiguous_origins() {
        for value in [
            "http://account.sabishii.me",
            "https://user:password@account.sabishii.me",
            "https://account.sabishii.me/auth",
            "https://account.sabishii.me?token=secret",
            "not-a-url",
        ] {
            assert!(normalize_base_url(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn slow_down_increase_is_persistent_and_saturating() {
        assert_eq!(next_poll_interval(5), 10);
        assert_eq!(next_poll_interval(10), 15);
        assert_eq!(next_poll_interval(u64::MAX), u64::MAX);
    }

    #[tokio::test]
    async fn parses_server_device_timing() {
        let body = r#"{"device_code":"synthetic-device","user_code":"ABCD-EFGH","verification_uri":"https://account.example/device","verification_uri_complete":"https://account.example/device?user_code=ABCD-EFGH","expires_in":1800,"interval":7}"#;
        let (base_url, requests) = spawn_server(vec![("200 OK", body)]);
        let flow = DeviceFlow::new(&base_url, "test-client").unwrap();
        let response = flow.request_device_code().await.unwrap();
        assert_eq!(response.expires_in, 1800);
        assert_eq!(response.interval, Some(7));
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn polling_honors_server_expiry_before_a_longer_interval() {
        let (base_url, requests) = spawn_server(vec![]);
        let flow = DeviceFlow::new(&base_url, "test-client").unwrap();
        let device = DeviceCodeResponse {
            device_code: "synthetic-device".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            verification_uri: "https://account.example/device".to_string(),
            verification_uri_complete: None,
            expires_in: 1,
            interval: Some(10),
        };
        let error = flow.poll_for_token(&device).await.unwrap_err().to_string();
        assert!(error.contains("expired"));
        assert_eq!(requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn response_bodies_are_not_copied_into_errors() {
        let marker = "synthetic-secret-marker-that-must-not-leak";
        let (base_url, _) = spawn_server(vec![("500 Internal Server Error", marker)]);
        let flow = DeviceFlow::new(&base_url, "test-client").unwrap();
        let error = flow.request_device_code().await.unwrap_err().to_string();
        assert!(error.contains("HTTP 500"));
        assert!(!error.contains(marker));
    }

    #[tokio::test]
    async fn does_not_retry_pending_codes_from_server_errors() {
        let body = r#"{"error":"authorization_pending"}"#;
        let (base_url, requests) = spawn_server(vec![("500 Internal Server Error", body)]);
        let flow = DeviceFlow::new(&base_url, "test-client").unwrap();
        let device = DeviceCodeResponse {
            device_code: "synthetic-device".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            verification_uri: "https://account.example/device".to_string(),
            verification_uri_complete: None,
            expires_in: 5,
            interval: Some(1),
        };
        let error = flow.poll_for_token(&device).await.unwrap_err().to_string();
        assert!(error.contains("HTTP 500"));
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }
}
