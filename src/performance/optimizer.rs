use crate::analytics::detection::AdvancedDetectionEngine;
use crate::cache::DetectionCache;
use crate::collectors::DataEvent;
use crate::config::AppConfig;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{Duration, Instant};

pub struct PerformanceOptimizer {
    max_concurrent_analyses: usize,
    analysis_semaphore: Arc<Semaphore>,
    cache: Arc<DetectionCache>,
}

impl PerformanceOptimizer {
    pub fn new(max_concurrent: usize, cache: Arc<DetectionCache>) -> Self {
        Self {
            max_concurrent_analyses: max_concurrent,
            analysis_semaphore: Arc::new(Semaphore::new(max_concurrent)),
            cache,
        }
    }

    pub async fn analyze_with_optimization(
        &self,
        engine: &AdvancedDetectionEngine,
        event: &DataEvent,
    ) -> Vec<crate::analytics::detection::DetectionResult> {
        let start = Instant::now();
        
        // Check cache first
        if let Some(cached_results) = self.cache.get_detection_results(&event.event_id).await {
            return cached_results;
        }

        // Acquire semaphore for concurrent analysis
        let _permit = self.analysis_semaphore.acquire().await.unwrap();
        
        // Perform analysis
        let results = engine.analyze(event).await.unwrap_or_default();
        
        // Cache results
        self.cache.put_detection_results(&event.event_id, results.clone()).await;
        
        // Log performance metrics
        let duration = start.elapsed();
        if duration > Duration::from_millis(100) {
            tracing::warn!(
                "Slow detection analysis: event_id={}, duration_ms={}",
                event.event_id,
                duration.as_millis()
            );
        }
        
        results
    }

    pub async fn batch_analyze(
        &self,
        engine: &AdvancedDetectionEngine,
        events: &[DataEvent],
    ) -> Vec<crate::analytics::detection::DetectionResult> {
        let mut results = Vec::new();
        
        // Process events in parallel batches
        let batch_size = (self.max_concurrent_analyses / 2).max(1);
        
        for chunk in events.chunks(batch_size) {
            let batch_results: Vec<_> = futures::future::join_all(
                chunk.iter().map(|event| {
                    self.analyze_with_optimization(engine, event)
                })
            ).await;
            
            for mut batch_result in batch_results {
                results.append(&mut batch_result);
            }
        }
        
        results
    }
}