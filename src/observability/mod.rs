// src/observability/mod.rs
use prometheus::{
    Counter, Gauge, Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    Opts, Registry,
};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,
    
    // Application Metrics
    pub http_requests_total: IntCounterVec,
    pub http_request_duration_seconds: HistogramVec,
    pub active_connections: IntGauge,
    
    // Database Metrics
    pub db_connections_active: IntGauge,
    pub db_connections_idle: IntGauge,
    pub db_query_duration_seconds: Histogram,
    pub db_errors_total: IntCounter,
    
    // Analytics Metrics
    pub events_processed_total: IntCounter,
    pub events_processed_duration_seconds: Histogram,
    pub detection_latency_seconds: Histogram,
    pub threats_detected_total: IntCounterVec,
    
    // Security Metrics
    pub authentication_failures_total: IntCounter,
    pub authorization_failures_total: IntCounter,
    pub suspicious_activities_total: IntCounterVec,
    
    // System Metrics
    pub memory_usage_bytes: IntGauge,
    pub cpu_usage_percent: Gauge,
    pub goroutines: IntGauge,
}

impl Metrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();
        
        // Application Metrics
        let http_requests_total = IntCounterVec::new(
            Opts::new("http_requests_total", "Total HTTP requests"),
            &["method", "endpoint", "status"],
        )?;
        
        let http_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new("http_request_duration_seconds", "HTTP request duration"),
            &["method", "endpoint"],
        )?;
        
        let active_connections = IntGauge::new("active_connections", "Active connections")?;
        
        // Database Metrics
        let db_connections_active = IntGauge::new("db_connections_active", "Active database connections")?;
        let db_connections_idle = IntGauge::new("db_connections_idle", "Idle database connections")?;
        let db_query_duration_seconds = Histogram::new(
            "db_query_duration_seconds", "Database query duration"
        )?;
        let db_errors_total = IntCounter::new("db_errors_total", "Total database errors")?;
        
        // Analytics Metrics
        let events_processed_total = IntCounter::new("events_processed_total", "Total events processed")?;
        let events_processed_duration_seconds = Histogram::new(
            "events_processed_duration_seconds", "Event processing duration"
        )?;
        let detection_latency_seconds = Histogram::new(
            "detection_latency_seconds", "Threat detection latency"
        )?;
        let threats_detected_total = IntCounterVec::new(
            Opts::new("threats_detected_total", "Total threats detected"),
            &["threat_type", "severity"],
        )?;
        
        // Security Metrics
        let authentication_failures_total = IntCounter::new(
            "authentication_failures_total", "Total authentication failures"
        )?;
        let authorization_failures_total = IntCounter::new(
            "authorization_failures_total", "Total authorization failures"
        )?;
        let suspicious_activities_total = IntCounterVec::new(
            Opts::new("suspicious_activities_total", "Total suspicious activities"),
            &["activity_type", "source"],
        )?;
        
        // System Metrics
        let memory_usage_bytes = IntGauge::new("memory_usage_bytes", "Memory usage in bytes")?;
        let cpu_usage_percent = Gauge::new("cpu_usage_percent", "CPU usage percentage")?;
        let goroutines = IntGauge::new("goroutines", "Number of goroutines")?;
        
        // Register all metrics
        registry.register(Box::new(http_requests_total.clone()))?;
        registry.register(Box::new(http_request_duration_seconds.clone()))?;
        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(db_connections_active.clone()))?;
        registry.register(Box::new(db_connections_idle.clone()))?;
        registry.register(Box::new(db_query_duration_seconds.clone()))?;
        registry.register(Box::new(db_errors_total.clone()))?;
        registry.register(Box::new(events_processed_total.clone()))?;
        registry.register(Box::new(events_processed_duration_seconds.clone()))?;
        registry.register(Box::new(detection_latency_seconds.clone()))?;
        registry.register(Box::new(threats_detected_total.clone()))?;
        registry.register(Box::new(authentication_failures_total.clone()))?;
        registry.register(Box::new(authorization_failures_total.clone()))?;
        registry.register(Box::new(suspicious_activities_total.clone()))?;
        registry.register(Box::new(memory_usage_bytes.clone()))?;
        registry.register(Box::new(cpu_usage_percent.clone()))?;
        registry.register(Box::new(goroutines.clone()))?;
        
        Ok(Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
            active_connections,
            db_connections_active,
            db_connections_idle,
            db_query_duration_seconds,
            db_errors_total,
            events_processed_total,
            events_processed_duration_seconds,
            detection_latency_seconds,
            threats_detected_total,
            authentication_failures_total,
            authorization_failures_total,
            suspicious_activities_total,
            memory_usage_bytes,
            cpu_usage_percent,
            goroutines,
        })
    }
    
    pub async fn update_system_metrics(&self) {
        // Update memory usage
        if let Ok(memory) = sysinfo::System::new_all().memory() {
            self.memory_usage_bytes.set(memory.total() - memory.available());
        }
        
        // Update CPU usage
        if let Ok(cpu) = sysinfo::System::new_all().global_cpu_usage() {
            self.cpu_usage_percent.set(cpu as f64);
        }
        
        // Update goroutine count
        self.goroutines.set(tokio::runtime::Handle::current().metrics().active_tasks() as i64);
    }
}
