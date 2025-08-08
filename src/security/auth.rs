// src/security/auth.rs
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use chrono::{Duration, Utc};
use uuid::Uuid;
use crate::error::{SecurityMonitoringError, Result};
use crate::security::SecurityConfig;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Subject (user ID)
    pub exp: usize, // Expiration time
    pub iat: usize, // Issued at
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub mfa_verified: bool,
    pub session_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub roles: Vec<String>,
    pub is_active: bool,
    pub mfa_enabled: bool,
    pub last_login: Option<chrono::DateTime<Utc>>,
    pub failed_login_attempts: u32,
    pub locked_until: Option<chrono::DateTime<Utc>>,
}

pub struct AuthService {
    config: SecurityConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl AuthService {
    pub fn new(config: SecurityConfig) -> Result<Self> {
        let encoding_key = EncodingKey::from_secret(config.authentication.jwt_secret.as_ref());
        let decoding_key = DecodingKey::from_secret(config.authentication.jwt_secret.as_ref());

        Ok(Self {
            config,
            encoding_key,
            decoding_key,
        })
    }

    pub fn generate_token(&self, user: &User) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.config.authentication.jwt_expiry_hours);
        
        let claims = Claims {
            sub: user.id.to_string(),
            exp: exp.timestamp() as usize,
            iat: now.timestamp() as usize,
            roles: user.roles.clone(),
            permissions: self.get_user_permissions(&user.roles),
            mfa_verified: !user.mfa_enabled,
            session_id: Uuid::new_v4().to_string(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| SecurityMonitoringError::Authentication(format!("Failed to generate token: {}", e)))
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        let validation = Validation::new(Algorithm::HS256);
        
        decode::<Claims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| SecurityMonitoringError::Authentication(format!("Invalid token: {}", e)))
    }

    pub fn check_permission(&self, claims: &Claims, resource: &str, action: &str) -> Result<()> {
        let permission = format!("{}:{}", resource, action);
        
        if claims.permissions.contains(&permission) {
            Ok(())
        } else {
            Err(SecurityMonitoringError::Authorization(
                format!("Insufficient permissions for {} on {}", action, resource)
            ))
        }
    }

    pub fn check_role(&self, claims: &Claims, required_role: &str) -> Result<()> {
        if claims.roles.contains(&required_role.to_string()) {
            Ok(())
        } else {
            Err(SecurityMonitoringError::Authorization(
                format!("Required role '{}' not found", required_role)
            ))
        }
    }

    fn get_user_permissions(&self, roles: &[String]) -> Vec<String> {
        let mut permissions = HashSet::new();
        
        for role in roles {
            if let Some(role_config) = self.config.authorization.roles.get(role) {
                for perm_name in &role_config.permissions {
                    if let Some(permission) = self.config.authorization.permissions.get(perm_name) {
                        for action in &permission.actions {
                            permissions.insert(format!("{}:{}", permission.resource, action));
                        }
                    }
                }
            }
        }
        
        permissions.into_iter().collect()
    }
}

pub struct AuthMiddleware {
    auth_service: Arc<AuthService>,
}

impl AuthMiddleware {
    pub fn new(auth_service: Arc<AuthService>) -> Self {
        Self { auth_service }
    }

    pub async fn authenticate<B>(
        &self,
        req: axum::extract::Request<B>,
    ) -> Result<axum::extract::Request<B>, axum::response::Response> {
        let auth_header = req.headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok());

        let token = match auth_header {
            Some(header) if header.starts_with("Bearer ") => {
                header[7..].to_string()
            }
            _ => {
                return Err(axum::response::Response::builder()
                    .status(axum::http::StatusCode::UNAUTHORIZED)
                    .body(axum::body::Body::from("Missing or invalid authorization header"))
                    .unwrap());
            }
        };

        match self.auth_service.validate_token(&token) {
            Ok(claims) => {
                // Add claims to request extensions for later use
                let mut req = req;
                req.extensions_mut().insert(claims);
                Ok(req)
            }
            Err(e) => {
                Err(axum::response::Response::builder()
                    .status(axum::http::StatusCode::UNAUTHORIZED)
                    .body(axum::body::Body::from(format!("Authentication failed: {}", e)))
                    .unwrap())
            }
        }
    }

    pub async fn authorize<B>(
        &self,
        req: axum::extract::Request<B>,
        resource: &str,
        action: &str,
    ) -> Result<axum::extract::Request<B>, axum::response::Response> {
        let claims = req.extensions().get::<Claims>()
            .ok_or_else(|| {
                axum::response::Response::builder()
                    .status(axum::http::StatusCode::UNAUTHORIZED)
                    .body(axum::body::Body::from("No authentication claims found"))
                    .unwrap()
            })?;

        match self.auth_service.check_permission(claims, resource, action) {
            Ok(_) => Ok(req),
            Err(e) => {
                Err(axum::response::Response::builder()
                    .status(axum::http::StatusCode::FORBIDDEN)
                    .body(axum::body::Body::from(format!("Authorization failed: {}", e)))
                    .unwrap())
            }
        }
    }
}
