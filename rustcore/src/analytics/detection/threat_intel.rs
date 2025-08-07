use super::*;
use crate::cache::ThreatIntelEntry;
use crate::error::AppResult;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Deserialize)]
pub struct ThreatIntelResponse {
    pub iocs: Vec<IoC>,
    pub timestamp: String,
}

pub struct ThreatIntelEngine {
    client: Client,
    sources: Vec<String>,
    cache: Arc<DetectionCache>,
    update_interval: std::time::Duration,
}

impl ThreatIntelEngine {
    pub fn new(cache: Arc<DetectionCache>) -> Self {
        Self {
            client: Client::new(),
            sources: vec![
                "https://api.threatintel.example.com/iocs".to_string(),
                "https://feeds.example.com/malicious_ips".to_string(),
            ],
            cache,
            update_interval: std::time::Duration::from_secs(3600), // 1 hour
        }
    }

    pub async fn start_updates(&self) {
        let mut interval = tokio::time::interval(self.update_interval);
        
        loop {
            interval.tick().await;
            if let Err(e) = self.update_threat_intel().await {
                tracing::error!("Failed to update threat intelligence: {}", e);
            }
        }
    }

    async fn update_threat_intel(&self) -> AppResult<()> {
        for source in &self.sources {
            match self.fetch_threat_intel(source).await {
                Ok(iocs) => {
                    for ioc in iocs {
                        let entry = ThreatIntelEntry {
                            value: ioc.value.clone(),
                            threat_type: ioc.threat_type.clone(),
                            confidence: ioc.confidence,
                            expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
                        };
                        self.cache.put_threat_intel(ioc.value, entry).await;
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch threat intelligence from {}: {}", source, e);
                }
            }
        }
        Ok(())
    }

    async fn fetch_threat_intel(&self, url: &str) -> AppResult<Vec<IoC>> {
        let response = self.client.get(url).send().await?;
        let threat_data: ThreatIntelResponse = response.json().await?;
        Ok(threat_data.iocs)
    }

    pub async fn check_ioc(&self, value: &str) -> Option<ThreatIntelEntry> {
        self.cache.get_threat_intel(value).await
    }
}