// src/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] anyhow::Error),
    
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Authentication error: {0}")]
    Authentication(String),
    
    #[error("Authorization error: {0}")]
    Authorization(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

pub type AppResult<T> = Result<T, AppError>;

// Conversion helpers for common error types
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::Database(anyhow::anyhow!("Database error: {}", err))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::Validation(format!("JSON error: {}", err))
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Internal(format!("IO error: {}", err))
    }
}

impl From<env::VarError> for AppError {
    fn from(err: env::VarError) -> Self {
        AppError::Configuration(format!("Environment variable error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = AppError::NotFound("Resource not found".to_string());
        assert_eq!(error.to_string(), "Not found: Resource not found");
    }

    #[test]
    fn test_error_conversion() {
        let db_error = sqlx::Error::RowNotFound;
        let app_error: AppError = db_error.into();
        assert!(matches!(app_error, AppError::Database(_)));
    }
}