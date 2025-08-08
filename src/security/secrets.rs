// src/security/secrets.rs
use std::collections::HashMap;
use anyhow::{Result, Context};
use serde_json::Value;
use crate::error::SecurityMonitoringError;

pub trait SecretsManager: Send + Sync {
    async fn get_secret(&self, key: &str) -> Result<String>;
    async fn set_secret(&self, key: &str, value: &str) -> Result<()>;
    async fn delete_secret(&self, key: &str) -> Result<()>;
    async fn list_secrets(&self) -> Result<Vec<String>>;
}

pub struct VaultSecretsManager {
    client: vault::Client,
    mount_path: String,
}

impl VaultSecretsManager {
    pub async fn new(url: &str, token: &str, mount_path: &str) -> Result<Self> {
        let client = vault::Client::new(url, token)?;
        
        Ok(Self {
            client,
            mount_path: mount_path.to_string(),
        })
    }
}

#[async_trait::async_trait]
impl SecretsManager for VaultSecretsManager {
    async fn get_secret(&self, key: &str) -> Result<String> {
        let path = format!("{}/{}", self.mount_path, key);
        let secret = self.client.read_secret(&path).await?;
        
        secret.get("value")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| SecurityMonitoringError::Configuration(
                format!("Secret '{}' not found or invalid format", key)
            ))
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        let path = format!("{}/{}", self.mount_path, key);
        let mut data = HashMap::new();
        data.insert("value".to_string(), Value::String(value.to_string()));
        
        self.client.write_secret(&path, &data).await
            .map_err(|e| SecurityMonitoringError::Internal(
                format!("Failed to set secret '{}': {}", key, e)
            ))?;
        
        Ok(())
    }

    async fn delete_secret(&self, key: &str) -> Result<()> {
        let path = format!("{}/{}", self.mount_path, key);
        self.client.delete_secret(&path).await
            .map_err(|e| SecurityMonitoringError::Internal(
                format!("Failed to delete secret '{}': {}", key, e)
            ))?;
        
        Ok(())
    }

    async fn list_secrets(&self) -> Result<Vec<String>> {
        let secrets = self.client.list_secrets(&self.mount_path).await?;
        Ok(secrets)
    }
}

pub struct EnvironmentSecretsManager {
    prefix: String,
}

impl EnvironmentSecretsManager {
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl SecretsManager for EnvironmentSecretsManager {
    async fn get_secret(&self, key: &str) -> Result<String> {
        let env_key = format!("{}_{}", self.prefix, key.to_uppercase());
        std::env::var(&env_key)
            .map_err(|_| SecurityMonitoringError::Configuration(
                format!("Environment variable '{}' not found", env_key)
            ))
    }

    async fn set_secret(&self, _key: &str, _value: &str) -> Result<()> {
        Err(SecurityMonitoringError::Configuration(
            "Cannot set secrets in environment variables".to_string()
        ))
    }

    async fn delete_secret(&self, _key: &str) -> Result<()> {
        Err(SecurityMonitoringError::Configuration(
            "Cannot delete secrets from environment variables".to_string()
        ))
    }

    async fn list_secrets(&self) -> Result<Vec<String>> {
        let prefix = format!("{}_", self.prefix.to_uppercase());
        let secrets: Vec<String> = std::env::vars()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(k, _)| k[prefix.len()..].to_lowercase())
            .collect();
        
        Ok(secrets)
    }
}

pub struct SecretsManagerFactory;

impl SecretsManagerFactory {
    pub async fn create(config: &crate::security::SecretsConfig) -> Result<Arc<dyn SecretsManager>> {
        match config.provider.as_str() {
            "vault" => {
                let vault_url = config.vault_url.as_ref()
                    .ok_or_else(|| SecurityMonitoringError::Configuration(
                        "Vault URL not configured".to_string()
                    ))?;
                let vault_token = config.vault_token.as_ref()
                    .ok_or_else(|| SecurityMonitoringError::Configuration(
                        "Vault token not configured".to_string()
                    ))?;
                
                let manager = VaultSecretsManager::new(vault_url, vault_token, "secret").await?;
                Ok(Arc::new(manager))
            }
            "environment" => {
                let manager = EnvironmentSecretsManager::new("APP");
                Ok(Arc::new(manager))
            }
            _ => {
                Err(SecurityMonitoringError::Configuration(
                    format!("Unsupported secrets provider: {}", config.provider)
                ))
            }
        }
    }
}
