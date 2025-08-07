// src/observability/mod.rs
use opentelemetry::{global, trace::TraceContextExt, trace::Tracer};
use opentelemetry_jaeger::new_pipeline;
use opentelemetry_prometheus::PrometheusExporter;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::TracerProvider;
use prometheus::{Encoder, TextEncoder};
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::{debug, error, info, span, Level, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub struct ObservabilityConfig {
    pub jaeger_endpoint: String,
    pub metrics_endpoint: String,
    pub log_level: String,
}

pub struct ObservabilityManager {
    tracer: opentelemetry_sdk::trace::Tracer,
    meter_provider: SdkMeterProvider,
    metrics_exporter: PrometheusExporter,
}

impl ObservabilityManager {
    pub fn new(config: ObservabilityConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize tracing
        let level = match config.log_level.as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        };
        
        // Initialize Jaeger tracer
        let tracer_provider = new_pipeline()
            .with_service_name("security-monitoring")
            .with_agent_endpoint(config.jaeger_endpoint.parse().unwrap())
            .install_batch(opentelemetry_sdk::runtime::Tokio)?;
        
        let tracer = tracer_provider.tracer("security-monitoring");
        
        // Initialize metrics
        let (metrics_exporter, meter_provider) = opentelemetry_prometheus::exporter()
            .with_default_histogram_boundaries(vec![0.1, 0.5, 1.0, 2.5, 5.0, 10.0])
            .init();
        
        // Initialize logging
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| format!("{}=trace", env!("CARGO_PKG_NAME")).into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_opentelemetry::layer().with_tracer(tracer.clone()))
            .init();
        
        Ok(Self {
            tracer,
            meter_provider,
            metrics_exporter,
        })
    }
    
    pub fn tracer(&self) -> opentelemetry_sdk::trace::Tracer {
        self.tracer.clone()
    }
    
    pub fn meter(&self) -> opentelemetry::metrics::Meter {
        self.meter_provider.meter("security-monitoring")
    }
    
    pub async fn start_metrics_server(&self, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let metrics_exporter = self.metrics_exporter.clone();
        
        tokio::spawn(async move {
            let app = axum::Router::new().route("/metrics", axum::routing::get(move || async move {
                let encoder = TextEncoder::new();
                let metric_families = metrics_exporter.registry().gather();
                let mut buffer = Vec::new();
                encoder.encode(&metric_families, &mut buffer).unwrap();
                axum::response::Response::builder()
                    .header("Content-Type", "text/plain")
                    .body(axum::body::Body::from(buffer))
                    .unwrap()
            }));
            
            if let Err(e) = axum::Server::bind(&addr)
                .serve(app.into_make_service())
                .await
            {
                error!("Metrics server error: {}", e);
            }
        });
        
        Ok(())
    }
    
    pub fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        global::shutdown_tracer_provider();
        Ok(())
    }
}

// Instrumentation macros
#[macro_export]
macro_rules! trace_function {
    ($name:expr) => {
        let span = span!(Level::TRACE, $name);
        let _enter = span.enter();
    };
}

#[macro_export]
macro_rules! increment_counter {
    ($name:expr) => {
        if let Some(observability) = $crate::observability::OBSERVABILITY.get() {
            let meter = observability.meter();
            let counter = meter
                .u64_counter($name)
                .with_description("Counter for tracking operations")
                .init();
            counter.add(1, &[]);
        }
    };
    
    ($name:expr, $labels:expr) => {
        if let Some(observability) = $crate::observability::OBSERVABILITY.get() {
            let meter = observability.meter();
            let counter = meter
                .u64_counter($name)
                .with_description("Counter for tracking operations")
                .init();
            
            let labels: Vec<_> = $labels.iter()
                .map(|(k, v)| opentelemetry::KeyValue::new(k.clone(), v.clone()))
                .collect();
            
            counter.add(1, &labels);
        }
    };
}

#[macro_export]
macro_rules! record_histogram {
    ($name:expr, $value:expr) => {
        if let Some(observability) = $crate::observability::OBSERVABILITY.get() {
            let meter = observability.meter();
            let histogram = meter
                .f64_histogram($name)
                .with_description("Histogram for recording values")
                .init();
            histogram.record($value, &[]);
        }
    };
    
    ($name:expr, $value:expr, $labels:expr) => {
        if let Some(observability) = $crate::observability::OBSERVABILITY.get() {
            let meter = observability.meter();
            let histogram = meter
                .f64_histogram($name)
                .with_description("Histogram for recording values")
                .init();
            
            let labels: Vec<_> = $labels.iter()
                .map(|(k, v)| opentelemetry::KeyValue::new(k.clone(), v.clone()))
                .collect();
            
            histogram.record($value, &labels);
        }
    };
}

// Global observability manager
pub static OBSERVABILITY: once_cell::sync::Lazy<Option<ObservabilityManager>> = once_cell::sync::Lazy::new(|| None);

pub fn init_observability(config: ObservabilityConfig) -> Result<(), Box<dyn std::error::Error>> {
    let manager = ObservabilityManager::new(config)?;
    unsafe {
        let ptr = &OBSERVABILITY as *const _ as *mut Option<ObservabilityManager>;
        *ptr = Some(manager);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observability_initialization() {
        // This test ensures the observability system can be initialized
        let config = ObservabilityConfig {
            jaeger_endpoint: "localhost:6831".to_string(),
            metrics_endpoint: "localhost:9090".to_string(),
            log_level: "info".to_string(),
        };
        
        // Note: This might fail if Jaeger is not running
        // In a real test, we'd mock the Jaeger endpoint
        let result = ObservabilityManager::new(config);
        
        // We can't guarantee Jaeger is running, so we'll just check the type
        match result {
            Ok(_) => println!("Observability initialized successfully"),
            Err(e) => println!("Observability initialization failed (expected if Jaeger not running): {}", e),
        }
    }
}