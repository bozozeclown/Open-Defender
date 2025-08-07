// src/main.rs
mod config;
mod error;
mod resilience;
mod health;
mod observability;
mod network;
mod service_discovery;
mod database;

use config::AppConfig;
use error::{SecurityMonitoringError, Result};
use resilience::{circuit_breaker::CircuitBreaker, retry::RetryPolicy};
use health::{HealthChecker, DatabaseHealthCheck, RedisHealthCheck};
use observability::metrics::Metrics;
use network::PortManager;
use service_discovery::ServiceDiscovery;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, warn, error};

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = AppConfig::load()?;
    config.validate()?;

    // Initialize observability
    let metrics = Arc::new(Metrics::new()?);
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::from_str(&config.observability.log_level)?)
        .init();

    info!("Starting {} v{} in {} mode", 
        config.app.name, 
        config.app.version, 
        config.app.environment);

    // Initialize port manager
    let port_manager = Arc::new(PortManager::new("config/ports.yaml", &config.app.environment).await?);
    port_manager.validate_port_mappings()?;

    // Initialize service discovery
    let mut service_discovery = ServiceDiscovery::new("config/services.yaml").await?;
    service_discovery.start_health_monitoring().await;

    // Initialize database with circuit breaker
    let db_url = service_discovery.get_service_url("postgres")?;
    let mut db_config = config.database.clone();
    db_config.url = format!("postgres://postgres:postgres@{}/security_monitoring", db_url);

    let db_circuit_breaker = Arc::new(CircuitBreaker::new(
        resilience::circuit_breaker::CircuitBreakerConfig {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(60),
            max_retries: 3,
            backoff_multiplier: 2.0,
        }
    ));

    let db_manager = Arc::new(
        DatabaseManager::new_with_circuit_breaker(&db_config, db_circuit_breaker.clone()).await?
    );

    // Initialize Redis with circuit breaker
    let redis_url = service_discovery.get_service_url("redis")?;
    let redis_client = redis::Client::open(redis_url.clone())?;
    let redis_circuit_breaker = Arc::new(CircuitBreaker::new(
        resilience::circuit_breaker::CircuitBreakerConfig {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(30),
            max_retries: 3,
            backoff_multiplier: 2.0,
        }
    ));

    // Initialize health checker
    let mut health_checker = HealthChecker::new();
    health_checker.register_check(Arc::new(
        DatabaseHealthCheck::new(db_manager.get_pool().clone(), health::HealthCheckConfig {
            name: "database".to_string(),
            timeout: Duration::from_secs(5),
            interval: Duration::from_secs(10),
            critical: true,
        })
    ));

    health_checker.register_check(Arc::new(
        RedisHealthCheck::new(redis_client.clone(), health::HealthCheckConfig {
            name: "redis".to_string(),
            timeout: Duration::from_secs(3),
            interval: Duration::from_secs(15),
            critical: true,
        })
    ));

    health_checker.start_monitoring().await;

    // Register circuit breaker metrics with health checker
    health_checker.register_circuit_breaker_metrics(
        "database".to_string(),
        db_circuit_breaker.get_metrics().await
    );

    // Initialize rate limiter
    let rate_limiter = Arc::new(resilience::middleware::RateLimiter::new(
        100,  // max requests
        Duration::from_secs(60),  // per minute
    ));

    // Build application state
    let app_state = Arc::new(AppState {
        config,
        db_manager,
        redis_client,
        metrics,
        port_manager,
        service_discovery: Arc::new(service_discovery),
        health_checker: Arc::new(health_checker),
        rate_limiter,
    });

    // Start metrics collection
    start_metrics_collection(app_state.clone()).await;

    // Start graceful shutdown handler
    let shutdown_signal = shutdown_signal().await;

    // Run the application
    info!("Application started successfully");
    
    tokio::select! {
        _ = run_application(app_state.clone()) => {
            info!("Application stopped");
        }
        _ = shutdown_signal => {
            info!("Received shutdown signal");
        }
    }

    // Graceful shutdown
    info!("Shutting down gracefully...");
    Ok(())
}

async fn start_metrics_collection(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        
        loop {
            interval.tick().await;
            
            // Update system metrics
            state.metrics.update_system_metrics().await;
            
            // Update database metrics
            if let Ok(pool) = state.db_manager.get_pool() {
                state.metrics.db_connections_active.set(pool.size() as i64);
                state.metrics.db_connections_idle.set(pool.num_idle() as i64);
            }
            
            // Update health metrics
            let health = state.health_checker.get_health_status().await;
            state.metrics.active_connections.set(health.checks.len() as i64);
        }
    });
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn run_application(state: Arc<AppState>) -> Result<()> {
    // Build Axum application with resilience middleware
    let app = axum::Router::new()
        .route("/health", axum::routing::get(health_handler))
        .route("/metrics", axum::routing::get(metrics_handler))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            resilience::middleware::resilience_middleware
        ))
        .route_layer(axum::middleware::from_fn_with_state(
            state.rate_limiter.clone(),
            resilience::middleware::rate_limit_middleware
        ))
        .route_layer(axum::middleware::from_fn(
            resilience::middleware::timeout_middleware
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn health_handler(State(state): State<Arc<AppState>>) -> axum::Json<health::SystemHealth> {
    axum::Json(state.health_checker.get_health_status().await)
}

async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl axum::response::IntoResponse {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = state.metrics.registry.gather();
    
    match encoder.encode_to_string(&metric_families) {
        Ok(metrics) => (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            metrics,
        ).into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            [(axum::http::header::CONTENT_TYPE, "text/plain")],
            format!("Failed to encode metrics: {}", e),
        ).into_response(),
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub db_manager: Arc<DatabaseManager>,
    pub redis_client: redis::Client,
    pub metrics: Arc<Metrics>,
    pub port_manager: Arc<PortManager>,
    pub service_discovery: Arc<ServiceDiscovery>,
    pub health_checker: Arc<HealthChecker>,
    pub rate_limiter: Arc<resilience::middleware::RateLimiter>,
}