// tests/integration_tests.rs
use anyhow::Result;
use config::AppConfig;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

mod analytics;
mod api;
mod collaboration;
mod collectors;
mod config;
mod error;
mod observability;
mod response;
mod utils;

use analytics::AnalyticsManager;
use collectors::{DataEvent, EventData, EventCollector, EventProcessor};
use response::incident_response::IncidentResponseManager;

#[tokio::test]
async fn test_full_event_flow() -> Result<()> {
    // Initialize configuration
    let config = AppConfig::from_env_or_default();
    
    // Initialize database (skip if not available)
    let db = match utils::database::DatabaseManager::new(&config.database).await {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Database not available, skipping database-dependent tests");
            return Ok(());
        }
    };
    
    // Initialize analytics
    let analytics = Arc::new(AnalyticsManager::new(db.clone(), config.analytics)?);
    
    // Create and process a test event
    let event = DataEvent {
        event_id: "test-event-1".to_string(),
        event_type: "network".to_string(),
        timestamp: chrono::Utc::now(),
        data: EventData::Network {
            src_ip: "192.168.1.100".to_string(),
            dst_ip: "192.168.1.200".to_string(),
            protocol: "TCP".to_string(),
            dst_port: 80,
            packet_size: 1024,
        },
    };
    
    // Process the event
    analytics.process_event(event).await?;
    
    // Check that metrics were updated
    let metrics = analytics.get_metrics().await;
    assert_eq!(metrics.events_processed, 1);
    
    Ok(())
}

#[tokio::test]
async fn test_incident_response_flow() -> Result<()> {
    let incident_manager = IncidentResponseManager::new();
    
    // Create an incident
    let incident_id = incident_manager.create_incident(
        "Test Incident".to_string(),
        "This is a test incident".to_string(),
        "medium".to_string(),
    ).await?;
    
    // Get the incident
    let incident = incident_manager.get_incident(&incident_id).await;
    assert!(incident.is_some());
    
    let incident = incident.unwrap();
    assert_eq!(incident.title, "Test Incident");
    assert_eq!(incident.status, "open");
    
    // Assign the incident
    incident_manager.assign_incident(&incident_id, "test_user".to_string()).await?;
    
    // Check assignment
    let incident = incident_manager.get_incident(&incident_id).await;
    assert!(incident.is_some());
    assert_eq!(incident.unwrap().assigned_to, Some("test_user".to_string()));
    
    // Close the incident
    incident_manager.close_incident(&incident_id, "Test resolution".to_string()).await?;
    
    // Check closure
    let incident = incident_manager.get_incident(&incident_id).await;
    assert!(incident.is_some());
    assert_eq!(incident.unwrap().status, "resolved");
    assert!(incident.unwrap().resolved_at.is_some());
    
    Ok(())
}

#[tokio::test]
async fn test_collaboration_workspace() -> Result<()> {
    let config = config::CollaborationConfig {
        websocket_endpoint: "127.0.0.1:8002".to_string(),
        redis_url: "redis://localhost:6379".to_string(),
    };
    
    let collab_manager = collaboration::CollaborationManager::new(config);
    
    // Create a workspace
    let workspace_id = collab_manager.create_workspace(
        "Test Workspace".to_string(),
        "A test workspace for integration testing".to_string(),
        "test_user".to_string(),
    ).await?;
    
    // Join the workspace
    collab_manager.join_workspace(&workspace_id, "test_user2".to_string()).await?;
    
    // Send a chat message
    let message_id = collab_manager.send_chat_message(
        &workspace_id,
        "test_user".to_string(),
        "test_user".to_string(),
        "Hello, world!".to_string(),
        collaboration::MessageType::Text,
    ).await?;
    
    assert!(!message_id.is_empty());
    
    // Share an incident
    collab_manager.share_incident(
        &workspace_id,
        "incident-123".to_string(),
        "test_user".to_string(),
    ).await?;
    
    Ok(())
}

#[tokio::test]
async fn test_event_collection_and_processing() -> Result<()> {
    let config = AppConfig::from_env_or_default();
    
    // Initialize database (skip if not available)
    let db = match utils::database::DatabaseManager::new(&config.database).await {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Database not available, skipping database-dependent tests");
            return Ok(());
        }
    };
    
    // Initialize analytics
    let analytics = Arc::new(AnalyticsManager::new(db.clone(), config.analytics)?);
    
    // Create event collector and processor
    let (collector, event_receiver) = EventCollector::new(analytics.clone());
    let processor = EventProcessor::new(analytics.clone());
    
    // Start processing events in background
    let processor_handle = tokio::spawn(async move {
        processor.process_events(event_receiver).await
    });
    
    // Send some test events
    for i in 0..5 {
        let event = DataEvent {
            event_id: format!("integration-test-event-{}", i),
            event_type: "network".to_string(),
            timestamp: chrono::Utc::now(),
            data: EventData::Network {
                src_ip: "10.0.0.1".to_string(),
                dst_ip: "10.0.0.2".to_string(),
                protocol: "TCP".to_string(),
                dst_port: 80,
                packet_size: 2048,
            },
        };
        
        // Send event through collector
        let (test_collector, mut test_receiver) = EventCollector::new(analytics.clone());
        test_collector.event_buffer.send(event).unwrap();
        
        // Process the event
        if let Some(event) = test_receiver.recv().await {
            analytics.process_event(event).await?;
        }
    }
    
    // Wait for processing to complete
    sleep(Duration::from_millis(100)).await;
    
    // Check that all events were processed
    let metrics = analytics.get_metrics().await;
    assert!(metrics.events_processed >= 5);
    
    // Cancel processor
    processor_handle.abort();
    
    Ok(())
}

#[tokio::test]
async fn test_health_checks() -> Result<()> {
    let config = AppConfig::from_env_or_default();
    
    // Initialize database (skip if not available)
    let db = match utils::database::DatabaseManager::new(&config.database).await {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Database not available, skipping database-dependent tests");
            return Ok(());
        }
    };
    
    // Initialize analytics
    let analytics = Arc::new(AnalyticsManager::new(db.clone(), config.analytics)?);
    
    // Test health status
    let health_status = analytics.get_health_status().await;
    println!("Health status: {:?}", health_status);
    
    // Test health checks
    let health_checks = analytics.get_health_checks().await;
    assert!(!health_checks.is_empty());
    
    for check in &health_checks {
        println!("{}: {} ({})", check.name, check.status, check.message);
        assert!(!check.name.is_empty());
        assert!(!check.status.is_empty());
    }
    
    Ok(())
}

#[tokio::test]
async fn test_error_handling() -> Result<()> {
    use error::AppError;
    
    // Test error creation and conversion
    let error = AppError::NotFound("Test resource not found".to_string());
    assert_eq!(error.to_string(), "Not found: Test resource not found");
    
    // Test error conversion from sqlx::Error
    let sqlx_error = sqlx::Error::RowNotFound;
    let app_error: AppError = sqlx_error.into();
    assert!(matches!(app_error, AppError::Database(_)));
    
    // Test error conversion from serde_json::Error
    let json_error = serde_json::Error::custom("JSON parsing error");
    let app_error: AppError = json_error.into();
    assert!(matches!(app_error, AppError::Validation(_)));
    
    Ok(())
}

#[tokio::test]
async fn test_configuration_loading() -> Result<()> {
    // Test default configuration
    let config = AppConfig::from_env_or_default();
    
    // Verify all configuration sections are present
    assert!(!config.database.url.is_empty());
    assert!(config.database.max_connections > 0);
    assert!(config.analytics.event_buffer_size > 0);
    assert!(config.analytics.port_scan_threshold > 0);
    assert!(!config.api.graphql.endpoint.is_empty());
    assert!(!config.api.jwt_secret.is_empty());
    assert!(!config.collaboration.websocket_endpoint.is_empty());
    assert!(!config.collaboration.redis_url.is_empty());
    
    // Test suspicious processes parsing
    assert!(!config.analytics.suspicious_processes.is_empty());
    assert!(config.analytics.suspicious_processes.contains(&"powershell.exe".to_string()));
    
    Ok(())
}