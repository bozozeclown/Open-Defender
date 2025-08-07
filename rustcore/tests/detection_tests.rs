use exploit_detector::analytics::detection::*;
use exploit_detector::collectors::DataEvent;
use exploit_detector::error::AppResult;

#[tokio::test]
async fn test_kmeans_anomaly_detection() -> AppResult<()> {
    let detector = KMeansAnomalyDetector::new(0.8);
    
    // Create test features
    let features = ndarray::Array1::from_vec(vec![1.0, 2.0, 3.0, 4.0, 5.0]);
    
    // This will fail because model isn't trained
    let result = detector.detect_anomalies(&features).await;
    assert!(result.is_err());
    
    // Train the model
    let training_data = ndarray::Array2::from_shape_vec((10, 5), vec![
        1.0, 2.0, 3.0, 4.0, 5.0,
        1.1, 2.1, 3.1, 4.1, 5.1,
        // ... more training data
    ]).unwrap();
    
    detector.train_model(&training_data).await?;
    
    // Test detection
    let results = detector.detect_anomalies(&features).await?;
    assert!(!results.is_empty());
    
    Ok(())
}

#[tokio::test]
async fn test_parallel_detection() -> AppResult<()> {
    let engines: Vec<Arc<dyn DetectionEngine>> = vec![
        Arc::new(MockDetectionEngine::new()),
        Arc::new(MockDetectionEngine::new()),
    ];
    
    let parallel_engine = ParallelDetectionEngine::new(engines, 4);
    
    let events = vec![
        create_test_event(),
        create_test_event(),
        create_test_event(),
    ];
    
    let results = parallel_engine.analyze_events_parallel(&events).await;
    assert_eq!(results.len(), 6); // 2 engines × 3 events
    
    Ok(())
}

fn create_test_event() -> DataEvent {
    DataEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: "test".to_string(),
        source: "test".to_string(),
        data: crate::collectors::EventData::System {
            host: "test_host".to_string(),
            cpu_usage: 50.0,
            memory_usage: 60.0,
            disk_usage: 70.0,
        },
    }
}

struct MockDetectionEngine {
    results: Vec<DetectionResult>,
}

impl MockDetectionEngine {
    fn new() -> Self {
        Self {
            results: vec![DetectionResult {
                id: uuid::Uuid::new_v4().to_string(),
                detection_type: "mock".to_string(),
                confidence: 0.9,
                severity: "medium".to_string(),
                description: "Mock detection".to_string(),
                metadata: HashMap::new(),
                timestamp: chrono::Utc::now(),
            }],
        }
    }
}

#[async_trait]
impl DetectionEngine for MockDetectionEngine {
    async fn analyze(&self, _event: &DataEvent) -> AppResult<Vec<DetectionResult>> {
        Ok(self.results.clone())
    }

    async fn initialize(&self) -> AppResult<()> {
        Ok(())
    }
}