// src/resilience/middleware.rs
use axum::{
    extract::State,
    http::Request,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tracing::{info, warn, error};
use crate::observability::metrics::Metrics;

pub async fn resilience_middleware<B>(
    State(metrics): State<Arc<Metrics>>,
    req: Request<B>,
    next: Next<B>,
) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let start = std::time::Instant::now();

    // Log the request
    info!("{} {}", method, uri);

    // Execute the request
    let response = next.run(req).await;

    // Record metrics
    let duration = start.elapsed();
    let status = response.status();

    metrics.http_requests_total
        .with_label_values(&[
            &method.to_string(),
            &uri.path().to_string(),
            &status.as_u16().to_string(),
        ])
        .inc();

    metrics.http_request_duration_seconds
        .with_label_values(&[
            &method.to_string(),
            &uri.path().to_string(),
        ])
        .observe(duration.as_secs_f64());

    // Log response
    if status.is_server_error() {
        error!("{} {} failed with status {}", method, uri, status);
    } else if status.is_client_error() {
        warn!("{} {} failed with status {}", method, uri, status);
    } else {
        info!("{} {} completed with status {}", method, uri, status);
    }

    response
}

pub async fn timeout_middleware<B>(
    req: Request<B>,
    next: Next<B>,
) -> Response {
    let timeout_duration = std::time::Duration::from_secs(30);

    match tokio::time::timeout(timeout_duration, next.run(req)).await {
        Ok(response) => response,
        Err(_) => {
            error!("Request timed out after {:?}", timeout_duration);
            axum::http::StatusCode::REQUEST_TIMEOUT.into_response()
        }
    }
}

pub async fn rate_limit_middleware<B>(
    State(limiter): State<Arc<RateLimiter>>,
    req: Request<B>,
    next: Next<B>,
) -> Response {
    let client_ip = req.headers()
        .get("x-forwarded-for")
        .or(req.headers().get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    if let Err(_) = limiter.check_rate_limit(client_ip).await {
        warn!("Rate limit exceeded for IP: {}", client_ip);
        return axum::http::StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    next.run(req).await
}

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct RateLimiter {
    limits: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
    max_requests: u32,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            limits: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    pub async fn check_rate_limit(&self, key: &str) -> Result<()> {
        let mut limits = self.limits.write().await;
        let now = Instant::now();

        let entry = limits.entry(key.to_string()).or_insert((0, now));
        
        // Reset counter if window has passed
        if now.duration_since(entry.1) > self.window {
            *entry = (0, now);
        }

        // Check if limit exceeded
        if entry.0 >= self.max_requests {
            return Err(crate::error::SecurityMonitoringError::RateLimitExceeded);
        }

        // Increment counter
        entry.0 += 1;

        Ok(())
    }
}