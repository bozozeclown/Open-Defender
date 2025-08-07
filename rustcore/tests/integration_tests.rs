use exploit_detector::analytics::detection::AdvancedDetectionEngine;
use exploit_detector::cache::DetectionCache;
use exploit_detector::collectors::DataEvent;
use exploit_detector::config::AppConfig;
use exploit_detector::database::DatabaseManager;
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn test_full_detection_pipeline() {
    // Load test configuration
    let config = AppConfig::from_env().expect("Failed to load config");
    
    // Initialize database
    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database.url)
        .await
        .expect("Failed to connect to database");
    
    // Initialize cache
    let cache = DetectionCache::new(100);
    
    // Initialize detection engine
    let detection_engine = AdvancedDetectionEngine::new(
        std::sync::Arc::new(config),
        db_pool,
        std::sync::Arc::new(cache),
    );
    detection_engine.initialize().await.expect("Failed to initialize detection engine");
    
    // Create test event
    let event = DataEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        event_type: "network".to_string(),
        source: "test".to_string(),
        data: exploit_detector::collectors::EventData::Network {
            src_ip: "192.168.1.100".to_string(),
            dst_ip: "10.0.0.1".to_string(),
            src_port: 12345,
            dst_port: 80,
            protocol: "TCP".to_string(),
            bytes_sent: 1024,
            bytes_received: 2048,
        },
    };
    
    // Run detection
    let results = detection_engine.analyze(&event).await
        .expect("Failed to analyze event");
    
    // Verify results
    assert!(!results.is_empty());
    
    // Check that results are stored in database
    // (This would require a database query to verify)
}

#[tokio::test]
async fn test_threat_intel_integration() {
    // Test threat intelligence integration
    // This would require mocking the threat intelligence service
}

#[tokio::test]
async fn test_behavioral_analysis() {
    // Test behavioral analysis
    // This would require creating multiple events to establish a baseline
}