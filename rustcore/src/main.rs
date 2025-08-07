// src/main.rs
use anyhow::Result;
use config::AppConfig;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};

mod analytics;
mod api;
mod collaboration;
mod config;
mod collectors;
mod error;
mod observability;
mod response;
mod utils;

use analytics::AnalyticsManager;
use api::graphql::GraphQLApi;
use collaboration::CollaborationManager;
use observability::{init_observability, ObservabilityConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("Starting Security Monitoring System");

    // Load configuration
    let config = AppConfig::from_env_or_default();
    info!("Configuration loaded successfully");

    // Initialize observability
    let obs_config = ObservabilityConfig {
        jaeger_endpoint: "localhost:6831".to_string(),
        metrics_endpoint: "localhost:9090".to_string(),
        log_level: "info".to_string(),
    };
    
    if let Err(e) = init_observability(obs_config) {
        error!("Failed to initialize observability: {}", e);
    } else {
        info!("Observability initialized");
    }

    // Initialize database
    let db = Arc::new(utils::database::DatabaseManager::new(&config.database).await?);
    info!("Database connection established");

    // Initialize analytics manager
    let analytics = Arc::new(AnalyticsManager::new(db.clone(), config.analytics)?);
    info!("Analytics manager initialized");

    // Initialize GraphQL API
    let graphql_api = Arc::new(GraphQLApi::new(
        config.api.clone(),
        db.clone(),
        analytics.clone(),
    ).await?);
    info!("GraphQL API initialized");

    // Initialize collaboration manager
    let collaboration_manager = Arc::new(CollaborationManager::new(config.collaboration));
    info!("Collaboration manager initialized");

    // Start metrics server
    if let Some(obs) = observability::OBSERVABILITY.as_ref() {
        if let Err(e) = obs.start_metrics_server("127.0.0.1:9090".parse().unwrap()).await {
            error!("Failed to start metrics server: {}", e);
        } else {
            info!("Metrics server started on http://127.0.0.1:9090/metrics");
        }
    }

    // Start services
    let graphql_handle = tokio::spawn(async move {
        if let Err(e) = graphql_api.run().await {
            error!("GraphQL API error: {}", e);
        }
    });

    let collaboration_handle = tokio::spawn(async move {
        if let Err(e) = collaboration_manager.start_websocket_server().await {
            error!("WebSocket server error: {}", e);
        }
    });

    // Start event collection (placeholder - would integrate with actual collectors)
    let analytics_clone = analytics.clone();
    let collector_handle = tokio::spawn(async move {
        // This is a placeholder for actual event collection
        // In a real implementation, this would connect to various data sources
        info!("Event collector started");
        
        // Simulate some events for demonstration
        for i in 0..10 {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            
            let event = collectors::DataEvent {
                event_id: format!("simulated-event-{}", i),
                event_type: "network".to_string(),
                timestamp: chrono::Utc::now(),
                data: collectors::EventData::Network {
                    src_ip: "192.168.1.100".to_string(),
                    dst_ip: "192.168.1.200".to_string(),
                    protocol: "TCP".to_string(),
                    dst_port: 80,
                    packet_size: 1024,
                },
            };
            
            if let Err(e) = analytics_clone.process_event(event).await {
                error!("Failed to process event: {}", e);
            }
        }
    });

    // Wait for shutdown signal
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received shutdown signal");
        },
        _ = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap().recv() => {
            info!("Received terminate signal");
        },
    }

    info!("Shutting down gracefully...");

    // Cancel all tasks
    graphql_handle.abort();
    collaboration_handle.abort();
    collector_handle.abort();

    // Shutdown observability
    if let Some(obs) = observability::OBSERVABILITY.take() {
        if let Err(e) = obs.shutdown() {
            error!("Error shutting down observability: {}", e);
        }
    }

    info!("Shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_application_initialization() {
        // Test that the application can be initialized without panicking
        let config = AppConfig::from_env_or_default();
        
        // Test database initialization (might fail if no database is running)
        match utils::database::DatabaseManager::new(&config.database).await {
            Ok(_) => println!("Database initialization successful"),
            Err(e) => println!("Database initialization failed (expected if no database): {}", e),
        }
        
        // Test analytics initialization
        let db = Arc::new(utils::database::DatabaseManager::new(&config.database).await.unwrap_or_else(|_| {
            // Create a mock database manager for testing
            unimplemented!()
        }));
        
        match AnalyticsManager::new(db, config.analytics) {
            Ok(_) => println!("Analytics initialization successful"),
            Err(e) => println!("Analytics initialization failed: {}", e),
        }
        
        // Test collaboration initialization
        let collab = CollaborationManager::new(config.collaboration);
        println!("Collaboration initialization successful");
    }
}