use super::*;
use rayon::prelude::*;
use std::sync::Arc;

pub struct ParallelDetectionEngine {
    engines: Vec<Arc<dyn DetectionEngine>>,
    max_concurrency: usize,
}

impl ParallelDetectionEngine {
    pub fn new(engines: Vec<Arc<dyn DetectionEngine>>, max_concurrency: usize) -> Self {
        Self {
            engines,
            max_concurrency,
        }
    }

    pub async fn analyze_events_parallel(&self, events: &[DataEvent]) -> Vec<DetectionResult> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.max_concurrency)
            .build()
            .unwrap();

        pool.install(|| {
            events
                .par_iter()
                .flat_map(|event| {
                    let engines = self.engines.clone();
                    let event = event.clone();
                    
                    // Run detection engines in parallel for each event
                    let results: Vec<_> = engines
                        .par_iter()
                        .flat_map(|engine| {
                            let rt = tokio::runtime::Runtime::new().unwrap();
                            rt.block_on(async {
                                engine.analyze(&event).await.unwrap_or_default()
                            })
                        })
                        .collect();
                    
                    results
                })
                .collect()
        })
    }
}
