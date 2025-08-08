// src/utils/telemetry.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

pub struct TelemetryManager {
    metrics: Arc<RwLock<TelemetryMetrics>>,
    events: Arc<RwLock<Vec<TelemetryEvent>>>,
    health_checks: Arc<RwLock<HashMap<String, HealthCheck>>>,
    config: TelemetryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryMetrics {
    pub system_metrics: SystemMetrics,
    pub application_metrics: ApplicationMetrics,
    pub business_metrics: BusinessMetrics,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_io: NetworkIo,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIo {
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub packets_received: u64,
    pub packets_sent: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationMetrics {
    pub events_processed: u64,
    pub anomalies_detected: u64,
    pub incidents_created: u64,
    pub response_actions: u64,
    pub average_processing_time_ms: f64,
    pub error_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessMetrics {
    pub threats_blocked: u64,
    pub systems_protected: u32,
    pub compliance_score: f64,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub category: String,
    pub message: String,
    pub severity: String,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub status: HealthStatus,
    pub last_checked: DateTime<Utc>,
    pub duration_ms: u64,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub export_metrics: bool,
    pub export_traces: bool,
    pub metrics_endpoint: Option<String>,
    pub traces_endpoint: Option<String>,
}

impl TelemetryManager {
    pub async fn new() -> Result<Self> {
        let config = TelemetryConfig {
            enabled: true,
            export_metrics: true,
            export_traces: true,
            metrics_endpoint: Some("http://localhost:9090/metrics".to_string()),
            traces_endpoint: Some("http://localhost:4318/v1/traces".to_string()),
        };

        Ok(Self {
            metrics: Arc::new(RwLock::new(TelemetryMetrics {
                system_metrics: SystemMetrics {
                    cpu_usage: 0.0,
                    memory_usage: 0.0,
                    disk_usage: 0.0,
                    network_io: NetworkIo {
                        bytes_received: 0,
                        bytes_sent: 0,
                        packets_received: 0,
                        packets_sent: 0,
                    },
                    uptime_seconds: 0,
                },
                application_metrics: ApplicationMetrics {
                    events_processed: 0,
                    anomalies_detected: 0,
                    incidents_created: 0,
                    response_actions: 0,
                    average_processing_time_ms: 0.0,
                    error_rate: 0.0,
                },
                business_metrics: BusinessMetrics {
                    threats_blocked: 0,
                    systems_protected: 0,
                    compliance_score: 100.0,
                    risk_score: 0.0,
                },
                last_updated: Utc::now(),
            })),
            events: Arc::new(RwLock::new(Vec::new())),
            health_checks: Arc::new(RwLock::new(HashMap::new())),
            config,
        })
    }

    pub async fn record_event(&self, event_type: String, category: String, message: String, severity: String) -> Result<()> {
        let event = TelemetryEvent {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            category,
            message,
            severity,
            metadata: HashMap::new(),
        };

        {
            let mut events = self.events.write().await;
            events.push(event.clone());
            
            // Keep only last 1000 events
            if events.len() > 1000 {
                events.remove(0);
            }
        }

        // Log the event
        match severity.as_str() {
            "error" => error!("{}", message),
            "warn" => warn!("{}", message),
            "info" => info!("{}", message),
            "debug" => debug!("{}", message),
            _ => info!("{}", message),
        }

        Ok(())
    }

    pub async fn increment_counter(&self, counter_name: &str, value: u64) -> Result<()> {
        let mut metrics = self.metrics.write().await;
        
        match counter_name {
            "events_processed" => metrics.application_metrics.events_processed += value,
            "anomalies_detected" => metrics.application_metrics.anomalies_detected += value,
            "incidents_created" => metrics.application_metrics.incidents_created += value,
            "response_actions" => metrics.application_metrics.response_actions += value,
            "threats_blocked" => metrics.business_metrics.threats_blocked += value,
            _ => warn!("Unknown counter: {}", counter_name),
        }
        
        metrics.last_updated = Utc::now();
        Ok(())
    }

    pub async fn record_timing(&self, operation: &str, duration_ms: u64) -> Result<()> {
        let mut metrics = self.metrics.write().await;
        
        // Update average processing time
        if metrics.application_metrics.average_processing_time_ms > 0.0 {
            metrics.application_metrics.average_processing_time_ms = 
                (metrics.application_metrics.average_processing_time_ms + duration_ms as f64) / 2.0;
        } else {
            metrics.application_metrics.average_processing_time_ms = duration_ms as f64;
        }
        
        metrics.last_updated = Utc::now();
        Ok(())
    }

    pub async fn update_system_metrics(&self) -> Result<()> {
        use sysinfo::{System, SystemExt, ProcessExt, CpuExt, NetworkExt};

        let mut sys = System::new_all();
        sys.refresh_all();

        let cpu_usage = sys.global_cpu_info().cpu_usage();
        let total_memory = sys.total_memory();
        let used_memory = sys.used_memory();
        let memory_usage = (used_memory as f64 / total_memory as f64) * 100.0;

        // Get disk usage (simplified)
        let disk_usage = 0.0; // Would need to implement disk usage calculation

        // Get network IO
        let network_io = sys.networks();
        let mut total_bytes_received = 0;
        let mut total_bytes_sent = 0;
        let mut total_packets_received = 0;
        let mut total_packets_sent = 0;

        for (_, network) in network_io {
            total_bytes_received += network.total_received();
            total_bytes_sent += network.total_transmitted();
            total_packets_received += network.total_packets_received();
            total_packets_sent += network.total_packets_transmitted();
        }

        {
            let mut metrics = self.metrics.write().await;
            metrics.system_metrics = SystemMetrics {
                cpu_usage,
                memory_usage,
                disk_usage,
                network_io: NetworkIo {
                    bytes_received: total_bytes_received,
                    bytes_sent: total_bytes_sent,
                    packets_received: total_packets_received,
                    packets_sent: total_packets_sent,
                },
                uptime_seconds: sys.uptime(),
            };
            metrics.last_updated = Utc::now();
        }

        Ok(())
    }

    pub async fn update_health_check(&self, name: String, status: HealthStatus, duration_ms: u64, message: Option<String>) -> Result<()> {
        let mut health_checks = self.health_checks.write().await;
        
        health_checks.insert(name.clone(), HealthCheck {
            name,
            status,
            last_checked: Utc::now(),
            duration_ms,
            message,
        });

        Ok(())
    }

    pub async fn get_metrics(&self) -> TelemetryMetrics {
        self.metrics.read().await.clone()
    }

    pub async fn get_events(&self, limit: usize) -> Vec<TelemetryEvent> {
        let events = self.events.read().await;
        events.iter().rev().take(limit).cloned().collect()
    }

    pub async fn get_health_checks(&self) -> Vec<HealthCheck> {
        let health_checks = self.health_checks.read().await;
        health_checks.values().cloned().collect()
    }

    pub async fn get_health_status(&self) -> HealthStatus {
        let health_checks = self.health_checks.read().await;
        
        let mut unhealthy_count = 0;
        let mut degraded_count = 0;
        
        for check in health_checks.values() {
            match check.status {
                HealthStatus::Unhealthy => unhealthy_count += 1,
                HealthStatus::Degraded => degraded_count += 1,
                HealthStatus::Healthy => {}
            }
        }

        if unhealthy_count > 0 {
            HealthStatus::Unhealthy
        } else if degraded_count > 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }

    pub async fn export_metrics(&self) -> Result<String> {
        let metrics = self.get_metrics().await;
        
        let mut prometheus_metrics = String::new();
        
        // System metrics
        prometheus_metrics.push_str(&format!(
            "exploit_detector_cpu_usage {}\n",
            metrics.system_metrics.cpu_usage
        ));
        prometheus_metrics.push_str(&format!(
            "exploit_detector_memory_usage {}\n",
            metrics.system_metrics.memory_usage
        ));
        prometheus_metrics.push_str(&format!(
            "exploit_detector_disk_usage {}\n",
            metrics.system_metrics.disk_usage
        ));
        prometheus_metrics.push_str(&format!(
            "exploit_detector_uptime_seconds {}\n",
            metrics.system_metrics.uptime_seconds
        ));
        
        // Application metrics
        prometheus_metrics.push_str(&format!(
            "exploit_detector_events_processed_total {}\n",
            metrics.application_metrics.events_processed
        ));
        prometheus_metrics.push_str(&format!(
            "exploit_detector_anomalies_detected_total {}\n",
            metrics.application_metrics.anomalies_detected
        ));
        prometheus_metrics.push_str(&format!(
            "exploit_detector_incidents_created_total {}\n",
            metrics.application_metrics.incidents_created
        ));
        prometheus_metrics.push_str(&format!(
            "exploit_detector_response_actions_total {}\n",
            metrics.application_metrics.response_actions
        ));
        prometheus_metrics.push_str(&format!(
            "exploit_detector_average_processing_time_ms {}\n",
            metrics.application_metrics.average_processing_time_ms
        ));
        prometheus_metrics.push_str(&format!(
            "exploit_detector_error_rate {}\n",
            metrics.application_metrics.error_rate
        ));
        
        // Business metrics
        prometheus_metrics.push_str(&format!(
            "exploit_detector_threats_blocked_total {}\n",
            metrics.business_metrics.threats_blocked
        ));
        prometheus_metrics.push_str(&format!(
            "exploit_detector_systems_protected {}\n",
            metrics.business_metrics.systems_protected
        ));
        prometheus_metrics.push_str(&format!(
            "exploit_detector_compliance_score {}\n",
            metrics.business_metrics.compliance_score
        ));
        prometheus_metrics.push_str(&format!(
            "exploit_detector_risk_score {}\n",
            metrics.business_metrics.risk_score
        ));

        Ok(prometheus_metrics)
    }

    pub async fn run_health_checks(&self) -> Result<()> {
        // Database health check
        let start = std::time::Instant::now();
        // Simulate database check
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let duration = start.elapsed();
        
        self.update_health_check(
            "database".to_string(),
            HealthStatus::Healthy,
            duration.as_millis() as u64,
            None,
        ).await?;

        // Threat intelligence health check
        let start = std::time::Instant::now();
        // Simulate threat intelligence check
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        let duration = start.elapsed();
        
        self.update_health_check(
            "threat_intelligence".to_string(),
            HealthStatus::Healthy,
            duration.as_millis() as u64,
            None,
        ).await?;

        // ML model health check
        let start = std::time::Instant::now();
        // Simulate ML model check
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        let duration = start.elapsed();
        
        self.update_health_check(
            "ml_model".to_string(),
            HealthStatus::Healthy,
            duration.as_millis() as u64,
            None,
        ).await?;

        // Integration health check
        let start = std::time::Instant::now();
        // Simulate integration check
        tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
        let duration = start.elapsed();
        
        self.update_health_check(
            "integrations".to_string(),
            HealthStatus::Healthy,
            duration.as_millis() as u64,
            None,
        ).await?;

        Ok(())
    }
}
