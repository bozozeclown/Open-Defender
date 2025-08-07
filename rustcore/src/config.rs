// src/config.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CollectorConfig {
    pub etw_providers: Vec<EtwProvider>,
    pub collection_duration: f64,
    pub network_packet_count: u32,
    pub network_timeout: f64,
    pub network_filter: String,
    pub polling_interval: f64,
    pub event_types: Vec<String>,
    pub monitor_dir: String,
    pub event_log_path: String,
    pub batch_size: u32,
    pub log_level: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EtwProvider {
    pub name: String,
    pub guid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MlConfig {
    pub input_dim: usize,
    pub anomaly_threshold: f64,
    pub epochs: u32,
    pub batch_size: u32,
    pub max_features: usize,
    pub min_features_train: usize,
    pub model_path: String,
    pub feedback_enabled: bool,
    pub feedback_batch_size: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
    pub encryption_key: Option<String>,
    pub max_connections: u32,
    pub timeout: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DashboardConfig {
    pub max_events: usize,
    pub max_features: usize,
    pub metadata_fields: Vec<String>,
    pub refresh_interval: f64,
    pub log_level: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClusteringConfig {
    pub algorithm: String,
    pub n_clusters: usize,
    pub cluster_range: [usize; 2],
    pub random_state: u32,
    pub max_iter: usize,
    pub n_init: usize,
    pub tol: f64,
    pub normalize_features: bool,
    pub batch_size: usize,
    pub eps: f64,
    pub min_samples: usize,
    pub log_level: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportConfig {
    pub output_dir: String,
    pub max_data_length: usize,
    pub max_features_length: usize,
    pub min_anomalies: usize,
    pub chunk_size: usize,
    pub log_level: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SysmonConfig {
    pub enabled: bool,
    pub log_name: String,
    pub max_events: usize,
    pub config_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailConfig {
    pub enabled: bool,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub sender_email: String,
    pub sender_password: String,
    pub recipient_email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub enabled: bool,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AlertConfig {
    pub max_retries: u32,
    pub retry_delay: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FeatureExtractorConfig {
    pub cache_size: usize,
    pub log_level: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatasetConfig {
    pub enabled: bool,
    pub api_url: String,
    pub malwarebazaar_api_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestingConfig {
    pub test_mode: bool,
    pub mock_db_path: String,
    pub mock_model_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    pub api_keys: ThreatIntelApiKeys,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatIntelApiKeys {
    pub virustotal: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ControllerConfig {
    pub poll_interval: f64,
    pub report_interval: f64,
    pub batch_size: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CveManagerConfig {
    pub update_interval: u32,
    pub sources: Vec<String>,
    pub max_cve_age: u32,
    pub cvss_threshold: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SoftwareInventoryConfig {
    pub scan_interval: u32,
    pub include_system_components: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VulnerabilityScannerConfig {
    pub scan_interval: u32,
    pub auto_remediate: bool,
    pub notification_threshold: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PatchManagerConfig {
    pub auto_download: bool,
    pub deployment_window: String,
    pub rollback_enabled: bool,
    pub test_environment: bool,
    pub max_concurrent_installs: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseConfig {
    pub automation_enabled: bool,
    pub response_timeout: u32,
    pub email: EmailConfig,
    pub webhook: WebhookConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IncidentResponseConfig {
    pub enabled: bool,
    pub recovery_time_hours: u32,
    pub auto_escalation: bool,
    pub escalation_timeout_minutes: u32,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let config_str = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        
        let config: Config = serde_yaml::from_str(&config_str)
            .context("Failed to parse YAML config")?;
        
        Ok(config)
    }
}