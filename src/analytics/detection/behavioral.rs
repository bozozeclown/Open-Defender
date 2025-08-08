use super::*;
use crate::collectors::DataEvent;
use crate::error::AppResult;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct BehavioralEngine {
    profiles: Arc<RwLock<HashMap<String, BehavioralProfile>>>,
    baseline_window: chrono::Duration,
    anomaly_threshold: f64,
}

#[derive(Debug, Clone)]
pub struct BehavioralProfile {
    pub entity_id: String,
    pub entity_type: String,
    pub baseline_metrics: HashMap<String, f64>,
    pub recent_activity: Vec<DataEvent>,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl BehavioralEngine {
    pub fn new(baseline_window_days: i64, anomaly_threshold: f64) -> Self {
        Self {
            profiles: Arc::new(RwLock::new(HashMap::new())),
            baseline_window: chrono::Duration::days(baseline_window_days),
            anomaly_threshold,
        }
    }

    pub async fn update_profile(&self, event: &DataEvent) -> AppResult<()> {
        let entity_id = self.extract_entity_id(event)?;
        let entity_type = self.extract_entity_type(event)?;
        
        let mut profiles = self.profiles.write().await;
        let profile = profiles.entry(entity_id.clone()).or_insert_with(|| BehavioralProfile {
            entity_id: entity_id.clone(),
            entity_type: entity_type.clone(),
            baseline_metrics: HashMap::new(),
            recent_activity: Vec::new(),
            last_updated: chrono::Utc::now(),
        });

        // Update recent activity
        profile.recent_activity.push(event.clone());
        
        // Keep only recent activity within baseline window
        let cutoff = chrono::Utc::now() - self.baseline_window;
        profile.recent_activity.retain(|e| e.timestamp > cutoff);
        
        // Update baseline metrics
        self.update_baseline_metrics(profile).await?;
        
        profile.last_updated = chrono::Utc::now();
        
        Ok(())
    }

    async fn update_baseline_metrics(&self, profile: &mut BehavioralProfile) -> AppResult<()> {
        match profile.entity_type.as_str() {
            "user" => {
                profile.baseline_metrics.insert(
                    "avg_logins_per_day".to_string(),
                    self.calculate_avg_logins(&profile.recent_activity).await,
                );
                profile.baseline_metrics.insert(
                    "unique_ips_accessed".to_string(),
                    self.calculate_unique_ips(&profile.recent_activity).await as f64,
                );
            }
            "host" => {
                profile.baseline_metrics.insert(
                    "avg_cpu_usage".to_string(),
                    self.calculate_avg_cpu(&profile.recent_activity).await,
                );
                profile.baseline_metrics.insert(
                    "avg_memory_usage".to_string(),
                    self.calculate_avg_memory(&profile.recent_activity).await,
                );
            }
            _ => {}
        }
        Ok(())
    }

    async fn calculate_avg_logins(&self, events: &[DataEvent]) -> f64 {
        let login_events: Vec<_> = events.iter()
            .filter(|e| e.event_type == "login")
            .collect();
        
        if login_events.is_empty() {
            return 0.0;
        }
        
        let days = self.baseline_window.num_days() as f64;
        login_events.len() as f64 / days
    }

    async fn calculate_unique_ips(&self, events: &[DataEvent]) -> usize {
        let mut ips = HashSet::new();
        
        for event in events {
            if let EventData::Network { src_ip, .. } = &event.data {
                ips.insert(src_ip);
            }
        }
        
        ips.len()
    }

    async fn calculate_avg_cpu(&self, events: &[DataEvent]) -> f64 {
        let cpu_values: Vec<f64> = events.iter()
            .filter_map(|e| {
                if let EventData::System { cpu_usage, .. } = &e.data {
                    Some(*cpu_usage)
                } else {
                    None
                }
            })
            .collect();
        
        if cpu_values.is_empty() {
            return 0.0;
        }
        
        cpu_values.iter().sum::<f64>() / cpu_values.len() as f64
    }

    async fn calculate_avg_memory(&self, events: &[DataEvent]) -> f64 {
        let memory_values: Vec<f64> = events.iter()
            .filter_map(|e| {
                if let EventData::System { memory_usage, .. } = &e.data {
                    Some(*memory_usage)
                } else {
                    None
                }
            })
            .collect();
        
        if memory_values.is_empty() {
            return 0.0;
        }
        
        memory_values.iter().sum::<f64>() / memory_values.len() as f64
    }

    pub async fn detect_anomalies(&self, event: &DataEvent) -> AppResult<Vec<DetectionResult>> {
        let entity_id = self.extract_entity_id(event)?;
        let profiles = self.profiles.read().await;
        
        if let Some(profile) = profiles.get(&entity_id) {
            let anomaly_score = self.calculate_anomaly_score(profile, event).await?;
            
            if anomaly_score > self.anomaly_threshold {
                return Ok(vec![DetectionResult {
                    id: uuid::Uuid::new_v4().to_string(),
                    detection_type: "behavioral_anomaly".to_string(),
                    confidence: anomaly_score,
                    severity: if anomaly_score > 0.9 { "high" } else { "medium" }.to_string(),
                    description: format!("Anomalous behavior detected for {}", entity_id),
                    metadata: HashMap::from([
                        ("entity_id".to_string(), entity_id),
                        ("entity_type".to_string(), profile.entity_type.clone()),
                        ("anomaly_score".to_string(), anomaly_score.to_string()),
                    ]),
                    timestamp: chrono::Utc::now(),
                }]);
            }
        }
        
        Ok(vec![])
    }

    async fn calculate_anomaly_score(&self, profile: &BehavioralProfile, event: &DataEvent) -> AppResult<f64> {
        let mut score = 0.0;
        let mut factors = 0;
        
        match profile.entity_type.as_str() {
            "user" => {
                if let EventData::Network { src_ip, .. } = &event.data {
                    // Check if IP is unusual
                    let unique_ips = self.calculate_unique_ips(&profile.recent_activity).await;
                    if unique_ips > profile.baseline_metrics.get("unique_ips_accessed").unwrap_or(&0.0) as usize * 2 {
                        score += 0.4;
                    }
                    factors += 1;
                }
            }
            "host" => {
                if let EventData::System { cpu_usage, memory_usage, .. } = &event.data {
                    // Check CPU usage
                    if let Some(baseline_cpu) = profile.baseline_metrics.get("avg_cpu_usage") {
                        if *cpu_usage > *baseline_cpu * 1.5 {
                            score += 0.3;
                        }
                    }
                    
                    // Check memory usage
                    if let Some(baseline_memory) = profile.baseline_metrics.get("avg_memory_usage") {
                        if *memory_usage > *baseline_memory * 1.5 {
                            score += 0.3;
                        }
                    }
                    factors += 2;
                }
            }
            _ => {}
        }
        
        Ok(if factors > 0 { score / factors as f64 } else { 0.0 })
    }

    fn extract_entity_id(&self, event: &DataEvent) -> AppResult<String> {
        match &event.data {
            EventData::Process { user, .. } => Ok(user.clone()),
            EventData::System { host, .. } => Ok(host.clone()),
            EventData::Network { src_ip, .. } => Ok(src_ip.clone()),
            EventData::File { .. } => Ok("system".to_string()),
        }
    }

    fn extract_entity_type(&self, event: &DataEvent) -> AppResult<String> {
        match &event.data {
            EventData::Process { .. } => Ok("user".to_string()),
            EventData::System { .. } => Ok("host".to_string()),
            EventData::Network { .. } => Ok("network".to_string()),
            EventData::File { .. } => Ok("system".to_string()),
        }
    }
}
