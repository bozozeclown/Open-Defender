// src/config/mod.rs
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::env;
use regex::Regex;
use anyhow::{Context, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub collector: CollectorConfig,
    pub ml: MlConfig,
    pub database: DatabaseConfig,
    pub dashboard: DashboardConfig,
    pub clustering: ClusteringConfig,
    pub report: ReportConfig,
    pub sysmon: SysmonConfig,
    pub email: EmailConfig,
    pub webhook: WebhookConfig,
    pub alert: AlertConfig,
    pub feature_extractor: FeatureExtractorConfig,
    pub dataset: DatasetConfig,
    pub testing: TestingConfig,
    pub threat_intel: ThreatIntelConfig,
    pub controller: ControllerConfig,
    pub cve_manager: CveManagerConfig,
    pub software_inventory: SoftwareInventoryConfig,
    pub vulnerability_scanner: VulnerabilityScannerConfig,
    pub patch_manager: PatchManagerConfig,
    pub response: ResponseConfig,
    pub incident_response: IncidentResponseConfig,
    pub collaboration: CollaborationConfig,
    pub api: ApiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorConfig {
    pub etw_providers: Vec<EtwProvider>,
    pub collection_duration: f64,
    pub network_packet_count: u32,
    pub network_timeout: f64,
    pub network_filter: String,
    pub polling_interval: f64,
    pub event_types: Vec<String>,
    pub monitor_dir: PathBuf,
    pub event_log_path: PathBuf,
    pub batch_size: u32,
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwProvider {
    pub name: String,
    pub guid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlConfig {
    pub input_dim: usize,
    pub anomaly_threshold: f64,
    pub epochs: usize,
    pub batch_size: usize,
    pub max_features: usize,
    pub min_features_train: usize,
    pub model_path: PathBuf,
    pub feedback_enabled: bool,
    pub feedback_batch_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: PathBuf,
    pub encryption_key: String,
    pub max_connections: u32,
    pub timeout: f64,
}

// Implement other config structs...

impl Config {
    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        
        let mut config: Config = serde_yaml::from_str(&content)
            .context("Failed to parse YAML config")?;
        
        // Substitute environment variables
        config.substitute_env_vars()?;
        
        Ok(config)
    }
    
    fn substitute_env_vars(&mut self) -> Result<()> {
        let re = Regex::new(r"\$\{([^:]+)(?::([^}]+))?\}").unwrap();
        
        // Helper function to substitute in a string
        let substitute_string = |s: &str| -> String {
            re.replace_all(s, |caps: &regex::Captures| {
                let var = &caps[1];
                let default = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                env::var(var).unwrap_or_else(|_| default.to_string())
            }).to_string()
        };
        
        // Substitute in database path
        self.database.path = PathBuf::from(substitute_string(&self.database.path.to_string_lossy()));
        
        // Substitute in encryption key
        self.database.encryption_key = substitute_string(&self.database.encryption_key);
        
        // Substitute in email configuration
        self.email.smtp_server = substitute_string(&self.email.smtp_server);
        self.email.smtp_port = substitute_string(&self.email.smtp_port);
        self.email.sender_email = substitute_string(&self.email.sender_email);
        self.email.sender_password = substitute_string(&self.email.sender_password);
        self.email.recipient_email = substitute_string(&self.email.recipient_email);
        
        // Substitute in webhook configuration
        self.webhook.url = substitute_string(&self.webhook.url);
        
        // Substitute in threat intelligence API keys
        self.threat_intel.api_keys.virustotal = substitute_string(&self.threat_intel.api_keys.virustotal);
        
        // Substitute in other configurations as needed...
        
        Ok(())
    }
}