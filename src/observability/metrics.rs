// src/observability/metrics.rs
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use prometheus::{Encoder, TextEncoder};
use std::sync::Arc;
use tower_http::auth::RequireAuthorizationLayer;
use crate::AppState;

pub fn metrics_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route_layer(RequireAuthorizationLayer::basic(
            &std::env::var("METRICS_USERNAME").unwrap_or_else(|_| "admin".to_string()),
            &std::env::var("METRICS_PASSWORD").unwrap_or_else(|_| "admin".to_string()),
        ))
}

pub async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = state.registry.gather();
    
    match encoder.encode_to_string(&metric_families) {
        Ok(metrics) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            metrics,
        ).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "text/plain")],
            format!("Failed to encode metrics: {}", e),
        ).into_response(),
    }
}
