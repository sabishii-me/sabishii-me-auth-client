use anyhow::{anyhow, Result};
use keyring::Entry;

use crate::types::AuthState;

pub struct TokenStore {
    service: String,
    username: String,
}

impl TokenStore {
    /// Create a store namespaced by app name (e.g. "sabishii-me-cli", "sabishii-chat-cli")
    pub fn new(app_name: &str) -> Self {
        Self {
            service: app_name.to_string(),
            username: "auth-state".to_string(),
        }
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
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow!("Keychain error: {e}")),
        }
    }

    pub fn clear(&self) -> Result<()> {
        let entry = Entry::new(&self.service, &self.username)?;
        match entry.delete_password() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow!("Keychain error: {e}")),
        }
    }
}
