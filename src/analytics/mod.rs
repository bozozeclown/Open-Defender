// src/analytics/mod.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn, instrument};

use crate::collectors::DataEvent;
use crate::config::AnalyticsConfig;
use crate::error::AppError;
use crate::observability::{increment_counter, record_histogram, trace_function};
use crate::utils::database::DatabaseManager;
use crate::utils::telemetry::{HealthCheck, HealthStatus};

pub struct AnalyticsManager {
    db: DatabaseManager,
    event_buffer: Arc<RwLock<VecDeque<DataEvent>>>,
    metrics: Arc<RwLock<AnalyticsMetrics>>,
    alerts: Arc<RwLock<Vec<AnalyticsAlert>>>,
    patterns: Arc<RwLock<HashMap<String, AttackPattern>>>,
    config: AnalyticsConfig,
    last_metrics_update: Arc<RwLock<Instant>>,
    recent_alert_hashes: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsMetrics {
    pub events_processed: u64,
    pub anomalies_detected: u64,
    pub incidents_created: u64,
    pub response_actions: u64,
    pub false_positives: u64,
    pub true_positives: u64,
    pub detection_rate: f64,
    pub false_positive_rate: f64,
    pub average_response_time: f64,
    pub system_load: SystemLoad,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemLoad {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_usage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsAlert {
    pub id: String,
    pub alert_type: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub acknowledged: bool,
    pub resolved: bool,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern_type: String,
    pub indicators: Vec<String>,
    pub confidence: f64,
    pub last_seen: DateTime<Utc>,
    pub frequency: u32,
}

impl AnalyticsManager {
    pub fn new(db: DatabaseManager, config: AnalyticsConfig) -> Result<Self> {
        Ok(Self {
            db,
            event_buffer: Arc::new(RwLock::new(VecDeque::with_capacity(config.event_buffer_size))),
            metrics: Arc::new(RwLock::new(AnalyticsMetrics {
                events_processed: 0,
                anomalies_detected: 0,
                incidents_created: 0,
                response_actions: 0,
                false_positives: 0,
                true_positives: 0,
                detection_rate: 0.0,
                false_positive_rate: 0.0,
                average_response_time: 0.0,
                system_load: SystemLoad {
                    cpu_usage: 0.0,
                    memory_usage: 0.0,
                    disk_usage: 0.0,
                    network_usage: 0.0,
                },
                last_updated: Utc::now(),
            })),
            alerts: Arc::new(RwLock::new(Vec::new())),
            patterns: Arc::new(RwLock::new(HashMap::new())),
            config,
            last_metrics_update: Arc::new(RwLock::new(Instant::now())),
            recent_alert_hashes: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    #[instrument(skip(self, event))]
    pub async fn process_event(&self, event: DataEvent) -> Result<()> {
        trace_function!("process_event");
        let start = Instant::now();
        
        // Add event to buffer
        {
            let mut buffer = self.event_buffer.write().await;
            buffer.push_back(event.clone());
            
            // Maintain buffer size
            if buffer.len() > self.config.event_buffer_size {
                buffer.pop_front();
            }
        }

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.events_processed += 1;
            metrics.last_updated = Utc::now();
        }

        // Analyze event patterns
        self.analyze_patterns(&event).await?;

        // Detect anomalies in event stream
        self.detect_stream_anomalies().await?;

        // Update system metrics only if interval has passed (60 seconds)
        {
            let last_update = self.last_metrics_update.read().await;
            if last_update.elapsed() >= Duration::from_secs(60) {
                drop(last_update);
                self.update_system_metrics().await?;
                *self.last_metrics_update.write().await = Instant::now();
            }
        }

        // Record metrics
        let duration = start.elapsed();
        increment_counter!("events_processed");
        record_histogram!("event_processing_duration_ms", duration.as_millis() as f64);

        Ok(())
    }

    #[instrument(skip(self, event))]
    pub async fn record_anomaly(&self, event: &DataEvent, score: f64) -> Result<()> {
        trace_function!("record_anomaly");
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.anomalies_detected += 1;
            
            // Update detection rates (simplified)
            if score > 0.8 {
                metrics.true_positives += 1;
            } else {
                metrics.false_positives += 1;
            }
            
            let total = metrics.true_positives + metrics.false_positives;
            if total > 0 {
                metrics.detection_rate = metrics.true_positives as f64 / total as f64;
                metrics.false_positive_rate = metrics.false_positives as f64 / total as f64;
            }
        }

        // Check for high-frequency anomalies
        self.check_anomaly_frequency(event).await?;

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn record_incident(&self, incident_id: &str) -> Result<()> {
        trace_function!("record_incident");
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.incidents_created += 1;
        }

        // Create analytics alert
        let alert = AnalyticsAlert {
            id: uuid::Uuid::new_v4().to_string(),
            alert_type: "incident_created".to_string(),
            severity: "medium".to_string(),
            title: "New Security Incident".to_string(),
            description: format!("Incident {} has been created", incident_id),
            timestamp: Utc::now(),
            acknowledged: false,
            resolved: false,
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("incident_id".to_string(), serde_json::Value::String(incident_id.to_string()));
                meta
            },
        };

        self.create_alert_if_unique(alert).await?;

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn record_response_action(&self, action_type: &str, duration_ms: u64) -> Result<()> {
        trace_function!("record_response_action");
        
        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.response_actions += 1;
            
            // Update average response time
            if metrics.average_response_time > 0.0 {
                metrics.average_response_time = (metrics.average_response_time + duration_ms as f64) / 2.0;
            } else {
                metrics.average_response_time = duration_ms as f64;
            }
        }

        Ok(())
    }

    #[instrument(skip(self, event))]
    async fn analyze_patterns(&self, event: &DataEvent) -> Result<()> {
        trace_function!("analyze_patterns");
        
        // Analyze event for attack patterns
        match &event.data {
            crate::collectors::EventData::Network { src_ip, dst_ip, protocol, .. } => {
                // Check for port scanning
                if protocol == "TCP" || protocol == "UDP" {
                    self.detect_port_scan(src_ip, dst_ip).await?;
                }
                
                // Check for data exfiltration
                self.detect_data_exfiltration(event).await?;
            }
            crate::collectors::EventData::Process { name, cmd, .. } => {
                // Check for suspicious processes
                self.detect_suspicious_process(name, cmd).await?;
            }
            crate::collectors::EventData::File { path, operation, .. } => {
                // Check for suspicious file operations
                self.detect_suspicious_file_activity(path, operation).await?;
            }
            _ => {}
        }

        Ok(())
    }

    #[instrument(skip(self, src_ip, dst_ip))]
    async fn detect_port_scan(&self, src_ip: &str, dst_ip: &str) -> Result<()> {
        trace_function!("detect_port_scan");
        let start = Instant::now();
        
        let buffer = self.event_buffer.read().await;
        
        // Count connections from same source IP in the last minute
        let one_minute_ago = Utc::now() - Duration::minutes(1);
        let connection_count = buffer.iter()
            .filter(|e| {
                if let crate::collectors::EventData::Network { 
                    src_ip: event_src_ip, 
                    dst_ip: event_dst_ip, 
                    .. 
                } = &e.data {
                    event_src_ip == src_ip && 
                    event_dst_ip == dst_ip && 
                    e.timestamp > one_minute_ago
                } else {
                    false
                }
            })
            .count();

        // Use configurable threshold
        if connection_count > self.config.port_scan_threshold {
            let pattern_id = format!("port_scan_{}", src_ip);
            
            {
                let mut patterns = self.patterns.write().await;
                patterns.insert(pattern_id.clone(), AttackPattern {
                    id: pattern_id,
                    name: "Port Scan".to_string(),
                    description: format!("Port scan detected from {}", src_ip),
                    pattern_type: "network".to_string(),
                    indicators: vec![src_ip.to_string()],
                    confidence: 0.9,
                    last_seen: Utc::now(),
                    frequency: connection_count as u32,
                });
            }

            // Create alert
            let alert = AnalyticsAlert {
                id: uuid::Uuid::new_v4().to_string(),
                alert_type: "port_scan".to_string(),
                severity: "high".to_string(),
                title: "Port Scan Detected".to_string(),
                description: format!("Port scan detected from {} to {}", src_ip, dst_ip),
                timestamp: Utc::now(),
                acknowledged: false,
                resolved: false,
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("src_ip".to_string(), serde_json::Value::String(src_ip.to_string()));
                    meta.insert("dst_ip".to_string(), serde_json::Value::String(dst_ip.to_string()));
                    meta.insert("connection_count".to_string(), serde_json::Value::Number(serde_json::Number::from(connection_count)));
                    meta
                },
            };

            self.create_alert_if_unique(alert).await?;
            
            // Record metrics
            increment_counter!("port_scans_detected", &[("src_ip", src_ip)]);
        }
        
        // Record metrics
        let duration = start.elapsed();
        record_histogram!("port_scan_detection_duration_ms", duration.as_millis() as f64);

        Ok(())
    }

    #[instrument(skip(self, event))]
    async fn detect_data_exfiltration(&self, event: &DataEvent) -> Result<()> {
        trace_function!("detect_data_exfiltration");
        
        if let crate::collectors::EventData::Network { 
            packet_size, 
            dst_ip, 
            .. 
        } = &event.data {
            // Use configurable threshold
            if *packet_size > self.config.data_exfiltration_threshold {
                let alert = AnalyticsAlert {
                    id: uuid::Uuid::new_v4().to_string(),
                    alert_type: "data_exfiltration".to_string(),
                    severity: "high".to_string(),
                    title: "Potential Data Exfiltration".to_string(),
                    description: format!("Large data transfer detected to {}", dst_ip),
                    timestamp: Utc::now(),
                    acknowledged: false,
                    resolved: false,
                    metadata: {
                        let mut meta = HashMap::new();
                        meta.insert("dst_ip".to_string(), serde_json::Value::String(dst_ip.to_string()));
                        meta.insert("packet_size".to_string(), serde_json::Value::Number(serde_json::Number::from(*packet_size)));
                        meta
                    },
                };

                self.create_alert_if_unique(alert).await?;
                
                // Record metrics
                increment_counter!("data_exfiltration_detected", &[("dst_ip", dst_ip)]);
            }
        }

        Ok(())
    }

    #[instrument(skip(self, name, cmd))]
    async fn detect_suspicious_process(&self, name: &str, cmd: &[String]) -> Result<()> {
        trace_function!("detect_suspicious_process");
        
        // Check for suspicious process names using config
        if self.config.suspicious_processes.contains(&name.to_lowercase()) {
            // Check for suspicious command line arguments
            let cmd_str = cmd.join(" ").to_lowercase();
            let suspicious_args = vec![
                "-enc",
                "-nop",
                "-w hidden",
                "bypass",
                "downloadstring",
                "iex",
            ];

            if suspicious_args.iter().any(|arg| cmd_str.contains(arg)) {
                let alert = AnalyticsAlert {
                    id: uuid::Uuid::new_v4().to_string(),
                    alert_type: "suspicious_process".to_string(),
                    severity: "high".to_string(),
                    title: "Suspicious Process Detected".to_string(),
                    description: format!("Suspicious process with suspicious arguments: {} {}", name, cmd_str),
                    timestamp: Utc::now(),
                    acknowledged: false,
                    resolved: false,
                    metadata: {
                        let mut meta = HashMap::new();
                        meta.insert("process_name".to_string(), serde_json::Value::String(name.to_string()));
                        meta.insert("command_line".to_string(), serde_json::Value::String(cmd_str));
                        meta
                    },
                };

                self.create_alert_if_unique(alert).await?;
                
                // Record metrics
                increment_counter!("suspicious_process_detected", &[("process_name", name)]);
            }
        }

        Ok(())
    }

    #[instrument(skip(self, path, operation))]
    async fn detect_suspicious_file_activity(&self, path: &str, operation: &str) -> Result<()> {
        trace_function!("detect_suspicious_file_activity");
        
        // Check for suspicious file extensions
        let suspicious_extensions = vec![
            ".exe",
            ".dll",
            ".sys",
            ".scr",
            ".bat",
            ".cmd",
            ".ps1",
            ".vbs",
            ".js",
        ];

        if suspicious_extensions.iter().any(|ext| path.to_lowercase().ends_with(ext)) {
            // Check for suspicious operations
            if operation == "create" || operation == "modify" {
                let alert = AnalyticsAlert {
                    id: uuid::Uuid::new_v4().to_string(),
                    alert_type: "suspicious_file".to_string(),
                    severity: "medium".to_string(),
                    title: "Suspicious File Activity".to_string(),
                    description: format!("Suspicious file operation: {} on {}", operation, path),
                    timestamp: Utc::now(),
                    acknowledged: false,
                    resolved: false,
                    metadata: {
                        let mut meta = HashMap::new();
                        meta.insert("file_path".to_string(), serde_json::Value::String(path.to_string()));
                        meta.insert("operation".to_string(), serde_json::Value::String(operation.to_string()));
                        meta
                    },
                };

                self.create_alert_if_unique(alert).await?;
                
                // Record metrics
                increment_counter!("suspicious_file_activity", &[("operation", operation)]);
            }
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn detect_stream_anomalies(&self) -> Result<()> {
        trace_function!("detect_stream_anomalies");
        
        // Analyze event stream for anomalies using statistical methods
        let buffer = self.event_buffer.read().await;
        
        if buffer.len() < 100 {
            return Ok(());
        }

        // Calculate event rate (events per second)
        let time_window = Duration::minutes(5);
        let cutoff_time = Utc::now() - time_window;
        let recent_events: Vec<_> = buffer.iter()
            .filter(|e| e.timestamp > cutoff_time)
            .collect();
        
        let event_rate = recent_events.len() as f64 / time_window.num_seconds() as f64;
        
        // If event rate is unusually high, create alert
        if event_rate > 100.0 {
            let alert = AnalyticsAlert {
                id: uuid::Uuid::new_v4().to_string(),
                alert_type: "high_event_rate".to_string(),
                severity: "medium".to_string(),
                title: "High Event Rate Detected".to_string(),
                description: format!("Event rate of {:.2} events/sec detected", event_rate),
                timestamp: Utc::now(),
                acknowledged: false,
                resolved: false,
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("event_rate".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(event_rate).unwrap()));
                    meta.insert("time_window".to_string(), serde_json::Value::String(format!("{:?}", time_window)));
                    meta
                },
            };

            self.create_alert_if_unique(alert).await?;
        }

        Ok(())
    }

    #[instrument(skip(self, event))]
    async fn check_anomaly_frequency(&self, event: &DataEvent) -> Result<()> {
        trace_function!("check_anomaly_frequency");
        
        // Check for high frequency of anomalies from same source
        let buffer = self.event_buffer.read().await;
        
        let time_window = Duration::minutes(1);
        let cutoff_time = Utc::now() - time_window;
        
        let recent_anomalies: Vec<_> = buffer.iter()
            .filter(|e| {
                e.timestamp > cutoff_time &&
                match &e.data {
                    crate::collectors::EventData::Process { pid, .. } => {
                        if let crate::collectors::EventData::Process { pid: event_pid, .. } = &event.data {
                            pid == event_pid
                        } else {
                            false
                        }
                    }
                    crate::collectors::EventData::Network { src_ip, .. } => {
                        if let crate::collectors::EventData::Network { src_ip: event_src_ip, .. } = &event.data {
                            src_ip == event_src_ip
                        } else {
                            false
                        }
                    }
                    _ => false,
                }
            })
            .collect();

        // If more than 10 anomalies in a minute from same source, create alert
        if recent_anomalies.len() > 10 {
            let alert = AnalyticsAlert {
                id: uuid::Uuid::new_v4().to_string(),
                alert_type: "high_anomaly_frequency".to_string(),
                severity: "high".to_string(),
                title: "High Anomaly Frequency".to_string(),
                description: format!("{} anomalies detected from same source in the last minute", recent_anomalies.len()),
                timestamp: Utc::now(),
                acknowledged: false,
                resolved: false,
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("anomaly_count".to_string(), serde_json::Value::Number(serde_json::Number::from(recent_anomalies.len())));
                    meta.insert("time_window".to_string(), serde_json::Value::String("1 minute".to_string()));
                    meta
                },
            };

            self.create_alert_if_unique(alert).await?;
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn update_system_metrics(&self) -> Result<()> {
        trace_function!("update_system_metrics");
        use sysinfo::{System, SystemExt, ProcessExt, CpuExt};

        let mut sys = System::new_all();
        sys.refresh_all();

        let cpu_usage = sys.global_cpu_info().cpu_usage();
        let total_memory = sys.total_memory();
        let used_memory = sys.used_memory();
        let memory_usage = (used_memory as f64 / total_memory as f64) * 100.0;

        // Get disk usage (simplified)
        let disk_usage = 0.0; // Would need to implement disk usage calculation

        // Get network usage (simplified)
        let network_usage = 0.0; // Would need to implement network usage calculation

        {
            let mut metrics = self.metrics.write().await;
            metrics.system_load = SystemLoad {
                cpu_usage,
                memory_usage,
                disk_usage,
                network_usage,
            };
        }

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn get_metrics(&self) -> AnalyticsMetrics {
        self.metrics.read().await.clone()
    }

    #[instrument(skip(self))]
    pub async fn get_alerts(&self) -> Vec<AnalyticsAlert> {
        self.alerts.read().await.clone()
    }

    #[instrument(skip(self))]
    pub async fn get_patterns(&self) -> Vec<AttackPattern> {
        self.patterns.read().await.values().cloned().collect()
    }

    #[instrument(skip(self))]
    pub async fn acknowledge_alert(&self, alert_id: &str) -> Result<(), AppError> {
        let mut alerts = self.alerts.write().await;
        
        if let Some(alert) = alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.acknowledged = true;
            Ok(())
        } else {
            Err(AppError::NotFound(format!("Alert not found: {}", alert_id)))
        }
    }

    #[instrument(skip(self))]
    pub async fn resolve_alert(&self, alert_id: &str) -> Result<(), AppError> {
        let mut alerts = self.alerts.write().await;
        
        if let Some(alert) = alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.resolved = true;
            Ok(())
        } else {
            Err(AppError::NotFound(format!("Alert not found: {}", alert_id)))
        }
    }

    #[instrument(skip(self))]
    pub async fn generate_report(&self) -> Result<AnalyticsReport> {
        trace_function!("generate_report");
        
        let metrics = self.get_metrics().await;
        let alerts = self.get_alerts().await;
        let patterns = self.get_patterns().await;

        // Calculate summary statistics
        let total_alerts = alerts.len();
        let acknowledged_alerts = alerts.iter().filter(|a| a.acknowledged).count();
        let resolved_alerts = alerts.iter().filter(|a| a.resolved).count();
        
        let high_severity_alerts = alerts.iter().filter(|a| a.severity == "high").count();
        let medium_severity_alerts = alerts.iter().filter(|a| a.severity == "medium").count();
        let low_severity_alerts = alerts.iter().filter(|a| a.severity == "low").count();

        // Group alerts by type
        let mut alert_types = HashMap::new();
        for alert in &alerts {
            *alert_types.entry(&alert.alert_type).or_insert(0) += 1;
        }

        Ok(AnalyticsReport {
            generated_at: Utc::now(),
            metrics,
            alert_summary: AlertSummary {
                total_alerts,
                acknowledged_alerts,
                resolved_alerts,
                high_severity_alerts,
                medium_severity_alerts,
                low_severity_alerts,
                alert_types,
            },
            top_patterns: patterns.into_iter()
                .take(10)
                .collect(),
            recent_alerts: alerts.into_iter()
                .take(20)
                .collect(),
        })
    }

    #[instrument(skip(self))]
    pub async fn get_health_status(&self) -> HealthStatus {
        let metrics = self.get_metrics().await;
        
        // Simple health check based on system load
        if metrics.system_load.cpu_usage > 90.0 || metrics.system_load.memory_usage > 90.0 {
            HealthStatus::Unhealthy
        } else if metrics.system_load.cpu_usage > 70.0 || metrics.system_load.memory_usage > 70.0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }

    #[instrument(skip(self))]
    pub async fn get_health_checks(&self) -> Vec<HealthCheck> {
        let metrics = self.get_metrics().await;
        let mut checks = Vec::new();
        
        checks.push(HealthCheck {
            name: "cpu_usage".to_string(),
            status: if metrics.system_load.cpu_usage < 90.0 { "healthy" } else { "unhealthy" }.to_string(),
            value: metrics.system_load.cpu_usage,
            message: format!("CPU usage: {:.1}%", metrics.system_load.cpu_usage),
        });
        
        checks.push(HealthCheck {
            name: "memory_usage".to_string(),
            status: if metrics.system_load.memory_usage < 90.0 { "healthy" } else { "unhealthy" }.to_string(),
            value: metrics.system_load.memory_usage,
            message: format!("Memory usage: {:.1}%", metrics.system_load.memory_usage),
        });
        
        checks
    }

    #[instrument(skip(self, alert))]
    async fn create_alert_if_unique(&self, alert: AnalyticsAlert) -> Result<()> {
        // Create a hash for alert deduplication
        let alert_key = format!("{}:{}:{}", 
            alert.alert_type, 
            alert.metadata.get("src_ip").map_or("", |v| v.as_str().unwrap_or("")),
            alert.metadata.get("dst_ip").map_or("", |v| v.as_str().unwrap_or(""))
        );
        
        let mut recent_hashes = self.recent_alert_hashes.write().await;
        
        // Check if similar alert was created in the last 5 minutes
        if let Some(last_time) = recent_hashes.get(&alert_key) {
            if *last_time > Utc::now() - Duration::minutes(5) {
                return Ok(()); // Skip duplicate alert
            }
        }
        
        // Add alert and update hash
        recent_hashes.insert(alert_key, Utc::now());
        
        // Clean up old entries
        recent_hashes.retain(|_, time| *time > Utc::now() - Duration::minutes(10));
        
        // Add the alert
        let mut alerts = self.alerts.write().await;
        alerts.push(alert);
        
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsReport {
    pub generated_at: DateTime<Utc>,
    pub metrics: AnalyticsMetrics,
    pub alert_summary: AlertSummary,
    pub top_patterns: Vec<AttackPattern>,
    pub recent_alerts: Vec<AnalyticsAlert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSummary {
    pub total_alerts: usize,
    pub acknowledged_alerts: usize,
    pub resolved_alerts: usize,
    pub high_severity_alerts: usize,
    pub medium_severity_alerts: usize,
    pub low_severity_alerts: usize,
    pub alert_types: HashMap<String, usize>,
}
