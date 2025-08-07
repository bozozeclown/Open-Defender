pub mod ml_models;
pub mod signature;
pub mod threat_intel;
pub mod behavioral;
pub mod parallel;

use crate::analytics::{AnalyticsAlert, AttackPattern};
use crate::cache::DetectionCache;
use crate::collectors::DataEvent;
use crate::config::AppConfig;
use crate::error::AppResult;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[async_trait]
pub trait DetectionEngine: Send + Sync {
    async fn analyze(&self, event: &DataEvent) -> AppResult<Vec<DetectionResult>>;
    async fn initialize(&self) -> AppResult<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub id: String,
    pub detection_type: String,
    pub confidence: f64,
    pub severity: String,
    pub description: String,
    pub metadata: HashMap<String, String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub struct AdvancedDetectionEngine {
    ml_engine: Arc<dyn MlDetectionEngine>,
    signature_engine: Arc<SignatureEngine>,
    threat_intel: Arc<ThreatIntelEngine>,
    behavioral_engine: Arc<BehavioralEngine>,
    cache: Arc<DetectionCache>,
    db_pool: PgPool,
    config: Arc<AppConfig>,
}

impl AdvancedDetectionEngine {
    pub fn new(
        config: Arc<AppConfig>,
        db_pool: PgPool,
        cache: Arc<DetectionCache>,
    ) -> Self {
        let ml_engine = Arc::new(KMeansAnomalyDetector::new(config.analytics.ml.anomaly_threshold));
        let signature_engine = Arc::new(SignatureEngine::new());
        let threat_intel = Arc::new(ThreatIntelEngine::new(cache.clone()));
        let behavioral_engine = Arc::new(BehavioralEngine::new(30, 0.7)); // 30 days, 0.7 threshold

        Self {
            ml_engine,
            signature_engine,
            threat_intel,
            behavioral_engine,
            cache,
            db_pool,
            config,
        }
    }

    pub async fn initialize(&self) -> AppResult<()> {
        // Start threat intelligence updates
        let threat_intel_clone = self.threat_intel.clone();
        tokio::spawn(async move {
            threat_intel_clone.start_updates().await;
        });

        Ok(())
    }

    async fn extract_features(&self, event: &DataEvent) -> AppResult<Vec<f64>> {
        let mut features = Vec::new();
        
        match &event.data {
            EventData::Network { bytes_sent, bytes_received, .. } => {
                features.push(*bytes_sent as f64);
                features.push(*bytes_received as f64);
                features.push((*bytes_sent + *bytes_received) as f64);
            }
            EventData::System { cpu_usage, memory_usage, disk_usage } => {
                features.push(*cpu_usage);
                features.push(*memory_usage);
                features.push(*disk_usage);
            }
            EventData::Process { .. } => {
                // Extract process-specific features
                features.push(0.0); // Placeholder
            }
            EventData::File { size, .. } => {
                features.push(size.unwrap_or(0) as f64);
            }
        }
        
        Ok(features)
    }
}

#[async_trait]
impl DetectionEngine for AdvancedDetectionEngine {
    async fn analyze(&self, event: &DataEvent) -> AppResult<Vec<DetectionResult>> {
        let mut results = Vec::new();
        
        // Update behavioral profile
        if let Err(e) = self.behavioral_engine.update_profile(event).await {
            tracing::warn!("Failed to update behavioral profile: {}", e);
        }
        
        // Run ML-based detection
        let features = self.extract_features(event).await?;
        let ml_results = self.ml_engine.detect_anomalies(&features).await?;
        results.extend(ml_results);
        
        // Run signature-based detection
        let signature_results = self.signature_engine.evaluate_event(event).await?;
        results.extend(signature_results);
        
        // Run threat intelligence matching
        let threatintel_results = self.run_threat_intel_matching(event).await?;
        results.extend(threatintel_results);
        
        // Run behavioral analysis
        let behavioral_results = self.behavioral_engine.detect_anomalies(event).await?;
        results.extend(behavioral_results);
        
        // Store results in database
        for result in &results {
            self.store_detection_result(result).await?;
        }
        
        Ok(results)
    }

    async fn initialize(&self) -> AppResult<()> {
        // Initialize ML models
        self.ml_engine.initialize().await?;
        
        // Start threat intelligence updates
        let threat_intel_clone = self.threat_intel.clone();
        tokio::spawn(async move {
            threat_intel_clone.start_updates().await;
        });
        
        Ok(())
    }
}

impl AdvancedDetectionEngine {
    async fn run_threat_intel_matching(&self, event: &DataEvent) -> AppResult<Vec<DetectionResult>> {
        let mut results = Vec::new();
        
        // Check for IP addresses in network events
        if let EventData::Network { src_ip, dst_ip, .. } = &event.data {
            // Check source IP
            if let Some(ioc) = self.threat_intel.check_ioc(src_ip).await {
                results.push(DetectionResult {
                    id: uuid::Uuid::new_v4().to_string(),
                    detection_type: "threat_intel".to_string(),
                    confidence: ioc.confidence,
                    severity: "high".to_string(),
                    description: format!("Source IP {} matches threat intelligence: {}", src_ip, ioc.threat_type),
                    metadata: HashMap::from([
                        ("ioc_value".to_string(), ioc.value),
                        ("threat_type".to_string(), ioc.threat_type),
                    ]),
                    timestamp: chrono::Utc::now(),
                });
            }
            
            // Check destination IP
            if let Some(ioc) = self.threat_intel.check_ioc(dst_ip).await {
                results.push(DetectionResult {
                    id: uuid::Uuid::new_v4().to_string(),
                    detection_type: "threat_intel".to_string(),
                    confidence: ioc.confidence,
                    severity: "high".to_string(),
                    description: format!("Destination IP {} matches threat intelligence: {}", dst_ip, ioc.threat_type),
                    metadata: HashMap::from([
                        ("ioc_value".to_string(), ioc.value),
                        ("threat_type".to_string(), ioc.threat_type),
                    ]),
                    timestamp: chrono::Utc::now(),
                });
            }
        }
        
        Ok(results)
    }

    async fn store_detection_result(&self, result: &DetectionResult) -> AppResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO detection_results (id, event_id, detection_type, confidence, severity, description, metadata, timestamp)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            uuid::Uuid::parse_str(&result.id)?,
            uuid::Uuid::parse_str(&result.metadata.get("event_id").unwrap_or(&String::new()))?,
            result.detection_type,
            result.confidence,
            result.severity,
            result.description,
            serde_json::to_value(&result.metadata)?,
            result.timestamp,
        )
        .execute(&self.db_pool)
        .await?;
        
        Ok(())
    }
}