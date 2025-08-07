use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Detection error: {0}")]
    Detection(#[from] DetectionError),
    
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),
}

#[derive(Error, Debug)]
pub enum DetectionError {
    #[error("ML model not trained")]
    ModelNotTrained,
    
    #[error("Feature extraction failed: {0}")]
    FeatureExtraction(String),
    
    #[error("Threat intelligence unavailable")]
    ThreatIntelUnavailable,
    
    #[error("Invalid detection rule: {0}")]
    InvalidRule(String),
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Missing configuration: {0}")]
    Missing(String),
    
    #[error("Invalid configuration value: {0}")]
    InvalidValue(String),
}

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid token")]
    InvalidToken,
    
    #[error("Expired token")]
    ExpiredToken,
    
    #[error("Insufficient permissions")]
    InsufficientPermissions,
}