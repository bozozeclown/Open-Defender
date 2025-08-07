use serde::Deserialize;
use std::env;

#[derive(Deserialize, Debug)]
pub struct AppConfig {
    pub database: DatabaseConfig,
    pub analytics: AnalyticsConfig,
    pub api: ApiConfig,
    pub auth: AuthConfig,
}

#[derive(Deserialize, Debug)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Deserialize, Debug)]
pub struct AnalyticsConfig {
    pub event_buffer_size: usize,
    pub port_scan_threshold: u32,
    pub data_exfiltration_threshold: u64,
    pub suspicious_processes: Vec<String>,
    pub system_metrics_interval: u64,
    pub ml: MlConfig,
}

#[derive(Deserialize, Debug)]
pub struct MlConfig {
    pub kmeans_clusters: u32,
    pub isolation_trees: usize,
    pub anomaly_threshold: f64,
}

#[derive(Deserialize, Debug)]
pub struct ApiConfig {
    pub graphql_endpoint: String,
    pub cors_origins: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub token_expiry_hours: u64,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let mut cfg = config::Config::new();
        
        // Load from .env file
        cfg.merge(config::Environment::default())?;
        
        // Override with environment variables
        cfg.set_default("database.max_connections", 10)?;
        cfg.set_default("analytics.event_buffer_size", 10000)?;
        cfg.set_default("analytics.port_scan_threshold", 50)?;
        cfg.set_default("analytics.data_exfiltration_threshold", 10485760)?;
        cfg.set_default("analytics.ml.kmeans_clusters", 5)?;
        cfg.set_default("analytics.ml.isolation_trees", 100)?;
        cfg.set_default("analytics.ml.anomaly_threshold", 0.8)?;
        cfg.set_default("auth.token_expiry_hours", 24)?;
        
        cfg.try_into()
    }
}