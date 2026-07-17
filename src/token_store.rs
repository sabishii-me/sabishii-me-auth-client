use anyhow::{anyhow, Result};
use keyring::Entry;

use crate::{device_flow::normalize_base_url, types::AuthState};

pub struct TokenStore {
    service: String,
    legacy_service: Option<String>,
    username: String,
}

impl TokenStore {
    /// Create a store isolated by normalized service origin and client ID.
    /// A differently spelled valid origin (for example, a trailing slash) is
    /// retained only to migrate an SDK 0.1 keyring entry on first load/clear.
    pub fn new(base_url: &str, client_id: &str) -> Result<Self> {
        if client_id.trim().is_empty() {
            return Err(anyhow!("Client ID must not be empty"));
        }
        let original = base_url.trim().to_string();
        let service = normalize_base_url(&original)?;
        let legacy_service = (original != service).then_some(original);
        Ok(Self {
            service,
            legacy_service,
            username: client_id.to_string(),
        })
    }

    pub fn save(&self, state: &AuthState) -> Result<()> {
        let json = serde_json::to_string(state)?;
        let entry = Entry::new(&self.service, &self.username)?;
        entry.set_password(&json)?;
        Ok(())
    }

    pub fn load(&self) -> Result<Option<AuthState>> {
        let entry = Entry::new(&self.service, &self.username)?;
        match entry.get_password() {
            Ok(json) => Ok(Some(serde_json::from_str(&json)?)),
            Err(keyring::Error::NoEntry) => self.load_legacy(),
            Err(e) => Err(anyhow!("Keychain error: {e}")),
        }
    }

    fn load_legacy(&self) -> Result<Option<AuthState>> {
        let Some(legacy_service) = &self.legacy_service else {
            return Ok(None);
        };
        let legacy = Entry::new(legacy_service, &self.username)?;
        match legacy.get_password() {
            Ok(json) => {
                let state = serde_json::from_str(&json)?;
                self.save(&state)?;
                match legacy.delete_password() {
                    Ok(()) | Err(keyring::Error::NoEntry) => Ok(Some(state)),
                    Err(e) => Err(anyhow!("Keychain error: {e}")),
                }
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow!("Keychain error: {e}")),
        }
    }

    pub fn clear(&self) -> Result<()> {
        self.clear_service(&self.service)?;
        if let Some(legacy_service) = &self.legacy_service {
            self.clear_service(legacy_service)?;
        }
        Ok(())
    }

    fn clear_service(&self, service: &str) -> Result<()> {
        let entry = Entry::new(service, &self.username)?;
        match entry.delete_password() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow!("Keychain error: {e}")),
        }
    }
}
