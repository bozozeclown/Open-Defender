use crate::analytics::detection::DetectionEngine;
use crate::cache::DetectionCache;
use crate::config::AppConfig;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug)]
pub struct HealthStatus {
    pub overall: HealthState,
    pub checks: Vec<HealthCheck>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug)]
pub struct HealthCheck {
    pub name: String,
    pub status: HealthState,
    pub message: String,
    pub duration_ms: u64,
}

pub struct HealthChecker {
    config: Arc<AppConfig>,
    db_pool: PgPool,
    detection_engine: Arc<dyn DetectionEngine>,
    cache: Arc<DetectionCache>,
}

impl HealthChecker {
    pub fn new(
        config: Arc<AppConfig>,
        db_pool: PgPool,
        detection_engine: Arc<dyn DetectionEngine>,
        cache: Arc<DetectionCache>,
    ) -> Self {
        Self {
            config,
            db_pool,
            detection_engine,
            cache,
        }
    }

    pub async fn check_health(&self) -> HealthStatus {
        let mut checks = Vec::new();
        
        // Database check
        checks.push(self.check_database().await);
        
        // Detection engine check
        checks.push(self.check_detection_engine().await);
        
        // Cache check
        checks.push(self.check_cache().await);
        
        // Determine overall status
        let overall = if checks.iter().all(|c| c.status == HealthState::Healthy) {
            HealthState::Healthy
        } else if checks.iter().any(|c| c.status == HealthState::Unhealthy) {
            HealthState::Unhealthy
        } else {
            HealthState::Degraded
        };
        
        HealthStatus { overall, checks }
    }

    async fn check_database(&self) -> HealthCheck {
        let start = std::time::Instant::now();
        
        match sqlx::query("SELECT 1").fetch_one(&self.db_pool).await {
            Ok(_) => HealthCheck {
                name: "database".to_string(),
                status: HealthState::Healthy,
                message: "Database connection successful".to_string(),
                duration_ms: start.elapsed().as_millis() as u64,
            },
            Err(e) => HealthCheck {
                name: "database".to_string(),
                status: HealthState::Unhealthy,
                message: format!("Database connection failed: {}", e),
                duration_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    async fn check_detection_engine(&self) -> HealthCheck {
        let start = std::time::Instant::now();
        
        // Create a test event
        let test_event = crate::collectors::DataEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            event_type: "test".to_string(),
            source: "health_check".to_string(),
            data: crate::collectors::EventData::System {
                host: "test_host".to_string(),
                cpu_usage: 50.0,
                memory_usage: 60.0,
                disk_usage: 70.0,
            },
        };
        
        match self.detection_engine.analyze(&test_event).await {
            Ok(_) => HealthCheck {
                name: "detection_engine".to_string(),
                status: HealthState::Healthy,
                message: "Detection engine operational".to_string(),
                duration_ms: start.elapsed().as_millis() as u64,
            },
            Err(e) => HealthCheck {
                name: "detection_engine".to_string(),
                status: HealthState::Degraded,
                message: format!("Detection engine issue: {}", e),
                duration_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    async fn check_cache(&self) -> HealthCheck {
        let start = std::time::Instant::now();
        
        // Test cache operations
        let test_key = "health_check_test";
        let test_value = crate::cache::ThreatIntelEntry {
            value: "test_value".to_string(),
            threat_type: "test".to_string(),
            confidence: 1.0,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };
        
        self.cache.put_threat_intel(test_key.to_string(), test_value.clone()).await;
        let retrieved = self.cache.get_threat_intel(test_key).await;
        
        match retrieved {
            Some(_) => HealthCheck {
                name: "cache".to_string(),
                status: HealthState::Healthy,
                message: "Cache operations successful".to_string(),
                duration_ms: start.elapsed().as_millis() as u64,
            },
            None => HealthCheck {
                name: "cache".to_string(),
                status: HealthState::Unhealthy,
                message: "Cache operations failed".to_string(),
                duration_ms: start.elapsed().as_millis() as u64,
            },
        }
    }
}