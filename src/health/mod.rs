// src/health/mod.rs
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use crate::error::{SecurityMonitoringError, Result};
use crate::resilience::circuit_breaker::CircuitBreakerMetrics;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub status: HealthStatus,
    pub details: Option<String>,
    pub duration_ms: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    pub name: String,
    pub timeout: Duration,
    pub interval: Duration,
    pub critical: bool,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            timeout: Duration::from_secs(5),
            interval: Duration::from_secs(30),
            critical: true,
        }
    }
}

pub trait HealthCheckable: Send + Sync {
    fn name(&self) -> &str;
    async fn check_health(&self) -> Result<()>;
    fn is_critical(&self) -> bool;
}

pub struct HealthChecker {
    checks: HashMap<String, Arc<dyn HealthCheckable>>,
    results: Arc<RwLock<HashMap<String, HealthCheck>>>,
    circuit_breakers: Arc<RwLock<HashMap<String, CircuitBreakerMetrics>>>,
}

impl HealthChecker {
    pub fn new() -> Self {
        Self {
            checks: HashMap::new(),
            results: Arc::new(RwLock::new(HashMap::new())),
            circuit_breakers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register_check(&mut self, check: Arc<dyn HealthCheckable>) {
        self.checks.insert(check.name().to_string(), check);
    }

    pub fn register_circuit_breaker_metrics(&self, name: String, metrics: CircuitBreakerMetrics) {
        tokio::spawn({
            let circuit_breakers = self.circuit_breakers.clone();
            async move {
                let mut breakers = circuit_breakers.write().await;
                breakers.insert(name, metrics);
            }
        });
    }

    pub async fn start_monitoring(&self) {
        let checks = self.checks.clone();
        let results = self.results.clone();

        tokio::spawn(async move {
            loop {
                let mut results_guard = results.write().await;
                
                for (name, check) in &checks {
                    let start = std::time::Instant::now();
                    let status = match check.check_health().await {
                        Ok(_) => HealthStatus::Healthy,
                        Err(e) => {
                            if check.is_critical() {
                                HealthStatus::Unhealthy
                            } else {
                                HealthStatus::Degraded
                            }
                        }
                    };
                    
                    let duration = start.elapsed();
                    
                    results_guard.insert(name.clone(), HealthCheck {
                        name: name.clone(),
                        status,
                        details: None,
                        duration_ms: duration.as_millis() as u64,
                        timestamp: chrono::Utc::now(),
                    });
                }
                
                drop(results_guard);
                
                // Sleep for the minimum interval
                let min_interval = checks.values()
                    .map(|c| c.is_critical())
                    .map(|critical| if critical { Duration::from_secs(10) } else { Duration::from_secs(30) })
                    .min()
                    .unwrap_or(Duration::from_secs(30));
                
                tokio::time::sleep(min_interval).await;
            }
        });
    }

    pub async fn get_health_status(&self) -> SystemHealth {
        let results = self.results.read().await;
        let circuit_breakers = self.circuit_breakers.read().await;

        let checks = results.values().cloned().collect();
        let circuit_breaker_metrics = circuit_breakers.values().cloned().collect();

        let overall_status = if checks.iter().any(|c| c.status == HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else if checks.iter().any(|c| c.status == HealthStatus::Degraded) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        SystemHealth {
            status: overall_status,
            checks,
            circuit_breakers: circuit_breaker_metrics,
            timestamp: chrono::Utc::now(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemHealth {
    pub status: HealthStatus,
    pub checks: Vec<HealthCheck>,
    pub circuit_breakers: Vec<CircuitBreakerMetrics>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

// Database health check
pub struct DatabaseHealthCheck {
    pool: sqlx::PgPool,
    config: HealthCheckConfig,
}

impl DatabaseHealthCheck {
    pub fn new(pool: sqlx::PgPool, config: HealthCheckConfig) -> Self {
        Self { pool, config }
    }
}

#[async_trait::async_trait]
impl HealthCheckable for DatabaseHealthCheck {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn check_health(&self) -> Result<()> {
        tokio::time::timeout(self.config.timeout, async {
            sqlx::query("SELECT 1")
                .fetch_one(&self.pool)
                .await
                .map_err(|e| SecurityMonitoringError::Database(e))?;
            Ok(())
        })
        .await
        .map_err(|_| SecurityMonitoringError::ServiceUnavailable("Database health check timeout".to_string()))?
    }

    fn is_critical(&self) -> bool {
        self.config.critical
    }
}

// Redis health check
pub struct RedisHealthCheck {
    client: redis::Client,
    config: HealthCheckConfig,
}

impl RedisHealthCheck {
    pub fn new(client: redis::Client, config: HealthCheckConfig) -> Self {
        Self { client, config }
    }
}

#[async_trait::async_trait]
impl HealthCheckable for RedisHealthCheck {
    fn name(&self) -> &str {
        &self.config.name
    }

    async fn check_health(&self) -> Result<()> {
        tokio::time::timeout(self.config.timeout, async {
            let mut conn = self.client.get_async_connection().await
                .map_err(|e| SecurityMonitoringError::Redis(e))?;
            redis::cmd("PING").query_async::<_, String>(&mut conn).await
                .map_err(|e| SecurityMonitoringError::Redis(e))?;
            Ok(())
        })
        .await
        .map_err(|_| SecurityMonitoringError::ServiceUnavailable("Redis health check timeout".to_string()))?
    }

    fn is_critical(&self) -> bool {
        self.config.critical
    }
}
