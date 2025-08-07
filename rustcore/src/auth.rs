use crate::error::{AuthError, AppResult};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
}

pub struct AuthService {
    encoding_key: HmacSha256,
    token_expiry: Duration,
}

impl AuthService {
    pub fn new(secret: &str, token_expiry_hours: u64) -> Result<Self, AuthError> {
        let encoding_key = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|_| AuthError::InvalidToken)?;
        
        Ok(Self {
            encoding_key,
            token_expiry: Duration::hours(token_expiry_hours as i64),
        })
    }

    pub fn generate_token(&self, user_id: &str, role: &str) -> String {
        let claims = Claims {
            sub: user_id.to_string(),
            role: role.to_string(),
            exp: (Utc::now() + self.token_expiry).timestamp() as usize,
        };

        claims.sign_with_key(&self.encoding_key).unwrap()
    }

    pub fn verify_token(&self, token: &str) -> AppResult<Claims> {
        let claims: Claims = token
            .verify_with_key(&self.encoding_key)
            .map_err(|_| AuthError::InvalidToken)?;
        
        // Check expiration
        if claims.exp < Utc::now().timestamp() as usize {
            return Err(AuthError::ExpiredToken.into());
        }
        
        Ok(claims)
    }

    pub fn check_permission(&self, token: &str, required_role: &str) -> AppResult<()> {
        let claims = self.verify_token(token)?;
        
        // Simple role-based authorization
        match (claims.role.as_str(), required_role) {
            ("admin", _) => Ok(()),
            ("analyst", "analyst" | "viewer") => Ok(()),
            ("viewer", "viewer") => Ok(()),
            _ => Err(AuthError::InsufficientPermissions.into()),
        }
    }
}