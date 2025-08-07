// src/config.rs
use serde::Deserialize;
use std::env;

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub database: DatabaseConfig,
    pub analytics: AnalyticsConfig,
    pub api: ApiConfig,
    pub collaboration: CollaborationConfig,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Deserialize)]
pub struct AnalyticsConfig {
    pub event_buffer_size: usize,
    pub port_scan_threshold: u32,
    pub data_exfiltration_threshold: u64,
    pub suspicious_processes: Vec<String>,
    pub system_metrics_interval_seconds: u64,
}

#[derive(Debug, Deserialize)]
pub struct ApiConfig {
    pub graphql: GraphqlConfig,
    pub jwt_secret: String,
    pub cors_origins: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct GraphqlConfig {
    pub endpoint: String,
}

#[derive(Debug, Deserialize)]
pub struct CollaborationConfig {
    pub websocket_endpoint: String,
    pub redis_url: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, env::VarError> {
        Ok(Self {
            database: DatabaseConfig {
                url: env::var("DATABASE_URL")?,
                max_connections: env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()
                    .map_err(|_| env::VarError::NotPresent("Invalid DB_MAX_CONNECTIONS".to_string()))?,
            },
            analytics: AnalyticsConfig {
                event_buffer_size: env::var("EVENT_BUFFER_SIZE")
                    .unwrap_or_else(|_| "10000".to_string())
                    .parse()
                    .map_err(|_| env::VarError::NotPresent("Invalid EVENT_BUFFER_SIZE".to_string()))?,
                port_scan_threshold: env::var("PORT_SCAN_THRESHOLD")
                    .unwrap_or_else(|_| "50".to_string())
                    .parse()
                    .map_err(|_| env::VarError::NotPresent("Invalid PORT_SCAN_THRESHOLD".to_string()))?,
                data_exfiltration_threshold: env::var("DATA_EXFILTRATION_THRESHOLD")
                    .unwrap_or_else(|_| "10485760".to_string()) // 10MB
                    .parse()
                    .map_err(|_| env::VarError::NotPresent("Invalid DATA_EXFILTRATION_THRESHOLD".to_string()))?,
                suspicious_processes: env::var("SUSPICIOUS_PROCESSES")
                    .unwrap_or_else(|_| "powershell.exe,cmd.exe,wscript.exe,cscript.exe,rundll32.exe,regsvr32.exe".to_string())
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
                system_metrics_interval_seconds: env::var("SYSTEM_METRICS_INTERVAL")
                    .unwrap_or_else(|_| "60".to_string())
                    .parse()
                    .map_err(|_| env::VarError::NotPresent("Invalid SYSTEM_METRICS_INTERVAL".to_string()))?,
            },
            api: ApiConfig {
                graphql: GraphqlConfig {
                    endpoint: env::var("GRAPHQL_ENDPOINT")
                        .unwrap_or_else(|_| "127.0.0.1:8000".to_string()),
                },
                jwt_secret: env::var("JWT_SECRET")?,
                cors_origins: env::var("CORS_ORIGINS")
                    .unwrap_or_else(|_| "*".to_string())
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
            },
            collaboration: CollaborationConfig {
                websocket_endpoint: env::var("WEBSOCKET_ENDPOINT")
                    .unwrap_or_else(|_| "127.0.0.1:8001".to_string()),
                redis_url: env::var("REDIS_URL")?,
            },
        })
    }

    pub fn from_env_or_default() -> Self {
        Self {
            database: DatabaseConfig {
                url: env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://localhost/security_monitoring".to_string()),
                max_connections: env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()
                    .unwrap_or(10),
            },
            analytics: AnalyticsConfig {
                event_buffer_size: env::var("EVENT_BUFFER_SIZE")
                    .unwrap_or_else(|_| "10000".to_string())
                    .parse()
                    .unwrap_or(10000),
                port_scan_threshold: env::var("PORT_SCAN_THRESHOLD")
                    .unwrap_or_else(|_| "50".to_string())
                    .parse()
                    .unwrap_or(50),
                data_exfiltration_threshold: env::var("DATA_EXFILTRATION_THRESHOLD")
                    .unwrap_or_else(|_| "10485760".to_string())
                    .parse()
                    .unwrap_or(10485760),
                suspicious_processes: env::var("SUSPICIOUS_PROCESSES")
                    .unwrap_or_else(|_| "powershell.exe,cmd.exe,wscript.exe,cscript.exe,rundll32.exe,regsvr32.exe".to_string())
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
                system_metrics_interval_seconds: env::var("SYSTEM_METRICS_INTERVAL")
                    .unwrap_or_else(|_| "60".to_string())
                    .parse()
                    .unwrap_or(60),
            },
            api: ApiConfig {
                graphql: GraphqlConfig {
                    endpoint: env::var("GRAPHQL_ENDPOINT")
                        .unwrap_or_else(|_| "127.0.0.1:8000".to_string()),
                },
                jwt_secret: env::var("JWT_SECRET").unwrap_or_else(|_| "default-jwt-secret-change-in-production".to_string()),
                cors_origins: env::var("CORS_ORIGINS")
                    .unwrap_or_else(|_| "*".to_string())
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
            },
            collaboration: CollaborationConfig {
                websocket_endpoint: env::var("WEBSOCKET_ENDPOINT")
                    .unwrap_or_else(|_| "127.0.0.1:8001".to_string()),
                redis_url: env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_env_or_default() {
        // This test ensures the default configuration is valid
        let config = AppConfig::from_env_or_default();
        
        // Check database config
        assert!(!config.database.url.is_empty());
        assert!(config.database.max_connections > 0);
        
        // Check analytics config
        assert!(config.analytics.event_buffer_size > 0);
        assert!(config.analytics.port_scan_threshold > 0);
        assert!(config.analytics.data_exfiltration_threshold > 0);
        assert!(!config.analytics.suspicious_processes.is_empty());
        assert!(config.analytics.system_metrics_interval_seconds > 0);
        
        // Check API config
        assert!(!config.api.graphql.endpoint.is_empty());
        assert!(!config.api.jwt_secret.is_empty());
        assert!(!config.api.cors_origins.is_empty());
        
        // Check collaboration config
        assert!(!config.collaboration.websocket_endpoint.is_empty());
        assert!(!config.collaboration.redis_url.is_empty());
    }

    #[test]
    fn test_suspicious_processes_parsing() {
        // Test that suspicious processes are parsed correctly
        let config = AppConfig::from_env_or_default();
        
        assert!(config.analytics.suspicious_processes.contains(&"powershell.exe".to_string()));
        assert!(config.analytics.suspicious_processes.contains(&"cmd.exe".to_string()));
        assert!(config.analytics.suspicious_processes.contains(&"wscript.exe".to_string()));
    }

    #[test]
    fn test_cors_origins_parsing() {
        // Test that CORS origins are parsed correctly
        let config = AppConfig::from_env_or_default();
        
        // Default should be "*" (allow all)
        assert_eq!(config.api.cors_origins, vec!["*".to_string()]);
    }
}