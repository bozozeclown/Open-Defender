// src/error/mod.rs

$ErrorMod = "src\error\mod.rs"
if (-Not (Test-Path $ErrorMod)) {
    Write-Host "ERROR: $ErrorMod missing. Please create or attach it and re-run."
    exit
}
$Content = Get-Content $ErrorMod -Raw
if ($Content -notmatch "pub use SecurityMonitoringError as AppError") {
    Add-Content $ErrorMod "`n// Backwards-compatibility aliases`npub use SecurityMonitoringError as AppError;`npub type AppResult<T> = Result<T, SecurityMonitoringError>;`n"
    Write-Host "AppError/AppResult aliases added to $ErrorMod"
} else {
    Write-Host "AppError/AppResult aliases already present in $ErrorMod"
}

use thiserror::Error;
use std::fmt;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Error, Debug)]
pub enum SecurityMonitoringError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Authorization error: {0}")]
    Authorization(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Circuit breaker open: {0}")]
    CircuitBreakerOpen(String),
}

impl SecurityMonitoringError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            SecurityMonitoringError::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
            SecurityMonitoringError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            SecurityMonitoringError::Redis(_) => StatusCode::INTERNAL_SERVER_ERROR,
            SecurityMonitoringError::Network(_) => StatusCode::SERVICE_UNAVAILABLE,
            SecurityMonitoringError::Authentication(_) => StatusCode::UNAUTHORIZED,
            SecurityMonitoringError::Authorization(_) => StatusCode::FORBIDDEN,
            SecurityMonitoringError::Validation(_) => StatusCode::BAD_REQUEST,
            SecurityMonitoringError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            SecurityMonitoringError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            SecurityMonitoringError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            SecurityMonitoringError::CircuitBreakerOpen(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            SecurityMonitoringError::Configuration(_) => "CONFIGURATION_ERROR",
            SecurityMonitoringError::Database(_) => "DATABASE_ERROR",
            SecurityMonitoringError::Redis(_) => "REDIS_ERROR",
            SecurityMonitoringError::Network(_) => "NETWORK_ERROR",
            SecurityMonitoringError::Authentication(_) => "AUTHENTICATION_ERROR",
            SecurityMonitoringError::Authorization(_) => "AUTHORIZATION_ERROR",
            SecurityMonitoringError::Validation(_) => "VALIDATION_ERROR",
            SecurityMonitoringError::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            SecurityMonitoringError::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            SecurityMonitoringError::Internal(_) => "INTERNAL_ERROR",
            SecurityMonitoringError::CircuitBreakerOpen(_) => "CIRCUIT_BREAKER_OPEN",
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            SecurityMonitoringError::Network(_)
                | SecurityMonitoringError::Database(_)
                | SecurityMonitoringError::Redis(_)
                | SecurityMonitoringError::ServiceUnavailable(_)
        )
    }
}

impl IntoResponse for SecurityMonitoringError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_response = json!({
            "error": {
                "code": self.error_code(),
                "message": self.to_string(),
                "retryable": self.is_retryable()
            }
        });

        (status, Json(error_response)).into_response()
    }
}

pub type Result<T> = std::result::Result<T, SecurityMonitoringError>;

// Helper macros for error handling
#[macro_export]
macro_rules! security_error {
    (Configuration, $msg:expr) => {
        $crate::error::SecurityMonitoringError::Configuration($msg.to_string())
    };
    (Network, $msg:expr) => {
        $crate::error::SecurityMonitoringError::Network($msg.to_string())
    };
    (Authentication, $msg:expr) => {
        $crate::error::SecurityMonitoringError::Authentication($msg.to_string())
    };
    (Authorization, $msg:expr) => {
        $crate::error::SecurityMonitoringError::Authorization($msg.to_string())
    };
    (Validation, $msg:expr) => {
        $crate::error::SecurityMonitoringError::Validation($msg.to_string())
    };
    (ServiceUnavailable, $msg:expr) => {
        $crate::error::SecurityMonitoringError::ServiceUnavailable($msg.to_string())
    };
    (Internal, $msg:expr) => {
        $crate::error::SecurityMonitoringError::Internal($msg.to_string())
    };
}

#[macro_export]
macro_rules! security_result {
    ($expr:expr) => {
        $expr.map_err(|e| $crate::error::SecurityMonitoringError::from(e))
    };
}
