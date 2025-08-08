// src/api/health.rs
use axum::{extract::State, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::database::DatabaseManager;

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheck {
    pub status: String,
    pub database: DatabaseHealth,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseHealth {
    pub status: String,
    pub connections: u32,
    pub max_connections: u32,
    pub idle_connections: u32,
}

pub async fn health_check(
    State(db_manager): State<Arc<DatabaseManager>>,
) -> Result<Json<HealthCheck>, StatusCode> {
    let pool = db_manager.get_pool();

    // Check database health
    let db_status = match db_manager.health_check().await {
        Ok(_) => "healthy".to_string(),
        Err(_) => "unhealthy".to_string(),
    };

    // Get pool statistics
    let pool_size = pool.size();
    let pool_idle = pool.num_idle();

    let health = HealthCheck {
        status: if db_status == "healthy" { "healthy" } else { "degraded" }.to_string(),
        database: DatabaseHealth {
            status: db_status,
            connections: pool_size,
            max_connections: pool.options().get_max_connections(),
            idle_connections: pool_idle,
        },
        timestamp: chrono::Utc::now(),
    };

    Ok(Json(health))
}
