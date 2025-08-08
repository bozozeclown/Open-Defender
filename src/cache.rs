use crate::analytics::detection::DetectionResult;
use lru::LruCache;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct DetectionCache {
    results: Arc<Mutex<LruCache<String, Vec<DetectionResult>>>>,
    threat_intel: Arc<Mutex<LruCache<String, ThreatIntelEntry>>>,
}

#[derive(Debug, Clone)]
pub struct ThreatIntelEntry {
    pub value: String,
    pub threat_type: String,
    pub confidence: f64,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl DetectionCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            results: Arc::new(Mutex::new(LruCache::new(capacity))),
            threat_intel: Arc::new(Mutex::new(LruCache::new(capacity * 10))),
        }
    }

    pub async fn get_detection_results(&self, event_id: &str) -> Option<Vec<DetectionResult>> {
        let mut cache = self.results.lock().await;
        cache.get(&event_id.to_string()).cloned()
    }

    pub async fn put_detection_results(&self, event_id: &str, results: Vec<DetectionResult>) {
        let mut cache = self.results.lock().await;
        cache.put(event_id.to_string(), results);
    }

    pub async fn get_threat_intel(&self, key: &str) -> Option<ThreatIntelEntry> {
        let mut cache = self.threat_intel.lock().await;
        if let Some(entry) = cache.get(&key.to_string()) {
            if entry.expires_at > chrono::Utc::now() {
                return Some(entry.clone());
            }
            cache.pop(&key.to_string());
        }
        None
    }

    pub async fn put_threat_intel(&self, key: String, entry: ThreatIntelEntry) {
        let mut cache = self.threat_intel.lock().await;
        cache.put(key, entry);
    }
}
