// src/security/mod.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::{Result, Context};
use crate::error::SecurityMonitoringError;

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub authentication: AuthConfig,
    pub authorization: AuthorizationConfig,
    pub encryption: EncryptionConfig,
    pub network: NetworkSecurityConfig,
    pub audit: AuditConfig,
    pub secrets: SecretsConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_expiry_hours: u64,
    pub refresh_token_expiry_hours: u64,
    pub mfa_enabled: bool,
    pub mfa_methods: Vec<MfaMethod>,
    pub max_login_attempts: u32,
    pub lockout_duration_minutes: u32,
    pub password_policy: PasswordPolicy,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MfaMethod {
    TOTP,
    SMS,
    Email,
    HardwareToken,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: u32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_special_chars: bool,
    pub prevent_reuse: u32,
    pub expiry_days: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationConfig {
    pub rbac_enabled: bool,
    pub default_role: String,
    pub roles: HashMap<String, Role>,
    pub permissions: HashMap<String, Permission>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub inherits: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Permission {
    pub name: String,
    pub description: String,
    pub resource: String,
    pub actions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub enabled: bool,
    pub algorithm: String,
    pub key_rotation_days: u32,
    pub sensitive_fields: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkSecurityConfig {
    pub allowed_origins: Vec<String>,
    pub rate_limiting: RateLimitConfig,
    pub cors: CorsConfig,
    pub tls: TlsConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst_size: u32,
    pub by_ip: bool,
    pub by_user: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub exposed_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age_seconds: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
    pub min_version: String,
    pub cipher_suites: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditConfig {
    pub enabled: bool,
    pub log_security_events: bool,
    pub log_auth_events: bool,
    pub log_data_access: bool,
    pub retention_days: u32,
    pub sensitive_data_masking: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretsConfig {
    pub provider: String,
    pub vault_url: Option<String>,
    pub vault_token: Option<String>,
    pub aws_region: Option<String>,
    pub azure_vault_url: Option<String>,
}

impl SecurityConfig {
    pub fn load() -> Result<Self> {
        // Load from environment variables with fallback to config file
        let config_path = std::env::var("SECURITY_CONFIG_PATH")
            .unwrap_or_else(|_| "config/security.yaml".to_string());

        let config_content = std::fs::read_to_string(&config_path)
            .context("Failed to read security configuration")?;

        let mut config: Self = serde_yaml::from_str(&config_content)
            .context("Failed to parse security configuration")?;

        // Override with environment variables
        if let Ok(jwt_secret) = std::env::var("JWT_SECRET") {
            config.authentication.jwt_secret = jwt_secret;
        }

        if let Ok(vault_url) = std::env::var("VAULT_URL") {
            config.secrets.vault_url = Some(vault_url);
        }

        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.authentication.jwt_secret.is_empty() {
            return Err(SecurityMonitoringError::Configuration(
                "JWT secret is required".to_string()
            ));
        }

        if self.authentication.jwt_secret.len() < 32 {
            return Err(SecurityMonitoringError::Configuration(
                "JWT secret must be at least 32 characters".to_string()
            ));
        }

        if self.authorization.rbac_enabled && self.authorization.roles.is_empty() {
            return Err(SecurityMonitoringError::Configuration(
                "RBAC enabled but no roles defined".to_string()
            ));
        }

        Ok(())
    }
}
