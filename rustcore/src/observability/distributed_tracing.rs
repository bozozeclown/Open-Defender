// src/observability/distributed_tracing.rs
use opentelemetry::{global, trace::TraceContextExt, trace::Tracer, Context};
use opentelemetry_jaeger::new_pipeline;
use opentelemetry_sdk::trace::TracerProvider;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, span, Level, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub struct DistributedTracingManager {
    tracer: opentelemetry_sdk::trace::Tracer,
    service_name: String,
    traces_sampler: Arc<RwLock<TraceSampler>>,
}

#[derive(Debug, Clone)]
pub struct TraceSampler {
    sample_rate: f64,
    sampled_traces: HashMap<String, TraceInfo>,
}

#[derive(Debug, Clone)]
pub struct TraceInfo {
    pub trace_id: String,
    pub span_id: String,
    pub sampled: bool,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub duration_ms: u64,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub baggage: HashMap<String, String>,
}

impl DistributedTracingManager {
    pub fn new(service_name: &str, jaeger_endpoint: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize Jaeger tracer
        let tracer_provider = new_pipeline()
            .with_service_name(service_name)
            .with_agent_endpoint(jaeger_endpoint.parse()?)
            .install_batch(opentelemetry_sdk::runtime::Tokio)?;
        
        let tracer = tracer_provider.tracer(service_name);
        
        // Initialize trace sampler
        let traces_sampler = Arc::new(RwLock::new(TraceSampler {
            sample_rate: 0.1, // Sample 10% of traces by default
            sampled_traces: HashMap::new(),
        }));
        
        Ok(Self {
            tracer,
            service_name: service_name.to_string(),
            traces_sampler,
        })
    }

    pub fn tracer(&self) -> opentelemetry_sdk::trace::Tracer {
        self.tracer.clone()
    }

    pub async fn start_span(&self, name: &str) -> TracingSpan {
        let span = self.tracer.start(name);
        let cx = Context::current_with_span(span);
        
        TracingSpan {
            span,
            cx,
            name: name.to_string(),
            start_time: chrono::Utc::now(),
            tags: HashMap::new(),
        }
    }

    pub async fn start_span_with_parent(&self, name: &str, parent_context: &TraceContext) -> TracingSpan {
        let parent_cx = self.deserialize_context(parent_context)?;
        let span = self.tracer.start_with_context(name, &parent_cx);
        let cx = Context::current_with_span(span);
        
        TracingSpan {
            span,
            cx,
            name: name.to_string(),
            start_time: chrono::Utc::now(),
            tags: HashMap::new(),
        }
    }

    pub async fn extract_context(&self, headers: &HashMap<String, String>) -> Result<TraceContext, Box<dyn std::error::Error>> {
        // Extract trace context from HTTP headers
        let trace_id = headers.get("traceparent")
            .and_then(|h| h.split('-').nth(0))
            .unwrap_or("default")
            .to_string();
        
        let span_id = headers.get("traceparent")
            .and_then(|h| h.split('-').nth(1))
            .unwrap_or("default")
            .to_string();
        
        let parent_span_id = headers.get("traceparent")
            .and_then(|h| h.split('-').nth(2))
            .map(|s| s.to_string());
        
        // Extract baggage
        let mut baggage = HashMap::new();
        if let Some(baggage_header) = headers.get("baggage") {
            for item in baggage_header.split(',') {
                if let Some((key, value)) = item.split_once('=') {
                    baggage.insert(key.to_string(), value.to_string());
                }
            }
        }
        
        Ok(TraceContext {
            trace_id,
            span_id,
            parent_span_id,
            baggage,
        })
    }

    pub async fn inject_context(&self, context: &TraceContext) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        let mut headers = HashMap::new();
        
        // Inject traceparent header
        let traceparent = format!("{}-{}-{}", context.trace_id, context.span_id, "01");
        headers.insert("traceparent".to_string(), traceparent);
        
        // Inject baggage
        if !context.baggage.is_empty() {
            let baggage_items: Vec<String> = context.baggage
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            headers.insert("baggage".to_string(), baggage_items.join(","));
        }
        
        Ok(headers)
    }

    fn deserialize_context(&self, context: &TraceContext) -> Result<Context, Box<dyn std::error::Error>> {
        // In a real implementation, this would deserialize the trace context
        // For now, we'll create a new context
        Ok(Context::current())
    }

    pub async fn set_sampling_rate(&self, rate: f64) -> AppResult<()> {
        let mut sampler = self.traces_sampler.write().await;
        sampler.sample_rate = rate.clamp(0.0, 1.0);
        Ok(())
    }

    pub async fn get_sampled_traces(&self) -> Vec<TraceInfo> {
        let sampler = self.traces_sampler.read().await;
        sampler.sampled_traces.values().cloned().collect()
    }

    pub async fn record_span(&self, span: &TracingSpan, outcome: SpanOutcome) {
        let duration_ms = (chrono::Utc::now() - span.start_time).num_milliseconds() as u64;
        
        // Record span outcome
        match outcome {
            SpanOutcome::Success => {
                span.set_tag("status", "success");
            },
            SpanOutcome::Error(error) => {
                span.set_tag("status", "error");
                span.set_tag("error", error);
            },
        }
        
        // Check if we should sample this trace
        let should_sample = {
            let sampler = self.traces_sampler.read().await;
            rand::random::<f64>() < sampler.sample_rate
        };
        
        if should_sample {
            let trace_info = TraceInfo {
                trace_id: span.span.context().span().span_context().trace_id().to_string(),
                span_id: span.span.context().span().span_context().span_id().to_string(),
                sampled: true,
                timestamp: span.start_time,
                duration_ms,
                tags: span.tags.clone(),
            };
            
            let mut sampler = self.traces_sampler.write().await;
            sampler.sampled_traces.insert(
                format!("{}:{}", trace_info.trace_id, trace_info.span_id),
                trace_info,
            );
        }
        
        // End the span
        span.span.end();
    }
}

#[derive(Debug, Clone)]
pub struct TracingSpan {
    span: opentelemetry::trace::Span,
    cx: Context,
    name: String,
    start_time: chrono::DateTime<chrono::Utc>,
    tags: HashMap<String, String>,
}

impl TracingSpan {
    pub fn set_tag(&mut self, key: &str, value: &str) {
        self.tags.insert(key.to_string(), value.to_string());
        self.span.set_attribute(key.to_string(), value.to_string());
    }

    pub fn set_attribute(&mut self, key: &str, value: serde_json::Value) {
        match value {
            serde_json::Value::String(s) => {
                self.span.set_attribute(key.to_string(), s);
            },
            serde_json::Value::Number(n) => {
                if let Some(f) = n.as_f64() {
                    self.span.set_attribute(key.to_string(), f);
                }
            },
            serde_json::Value::Bool(b) => {
                self.span.set_attribute(key.to_string(), b);
            },
            _ => {},
        }
    }

    pub fn add_event(&mut self, name: &str, attributes: HashMap<String, serde_json::Value>) {
        let mut otel_attrs = Vec::new();
        for (key, value) in attributes {
            match value {
                serde_json::Value::String(s) => {
                    otel_attrs.push(opentelemetry::KeyValue::new(key, s));
                },
                serde_json::Value::Number(n) => {
                    if let Some(f) = n.as_f64() {
                        otel_attrs.push(opentelemetry::KeyValue::new(key, f));
                    }
                },
                serde_json::Value::Bool(b) => {
                    otel_attrs.push(opentelemetry::KeyValue::new(key, b));
                },
                _ => {},
            }
        }
        
        self.span.add_event(name, otel_attrs, opentelemetry::trace::Event::new(
            name,
            chrono::Utc::now(),
            0,
        ));
    }

    pub fn context(&self) -> TraceContext {
        // Extract context from span
        let span_context = self.span.context();
        let trace_id = span_context.trace_id().to_string();
        let span_id = span_context.span_id().to_string();
        
        // Extract parent span ID if available
        let parent_span_id = if let Some(parent) = span_context.span().parent_span_id() {
            Some(parent.to_string())
        } else {
            None
        };
        
        // Extract baggage
        let mut baggage = HashMap::new();
        for (key, value) in span_context.baggage() {
            baggage.insert(key.to_string(), value.as_str().to_string());
        }
        
        TraceContext {
            trace_id,
            span_id,
            parent_span_id,
            baggage,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SpanOutcome {
    Success,
    Error(String),
}

// Macro for easier tracing
#[macro_export]
macro_rules! trace_span {
    ($name:expr) => {
        {
            let span = $crate::observability::distributed_tracing::DISTRIBUTED_TRACING
                .as_ref()
                .map(|tracing| async {
                    tracing.start_span($name).await
                });
            
            async move {
                let span = match span {
                    Some(s) => s.await,
                    None => return $crate::observability::distributed_tracing::TracingSpan::placeholder(),
                };
                
                span
            }
        }
    };
    
    ($name:expr, $parent:expr) => {
        {
            let span = $crate::observability::distributed_tracing::DISTRIBUTED_TRACING
                .as_ref()
                .map(|tracing| async {
                    tracing.start_span_with_parent($name, $parent).await
                });
            
            async move {
                let span = match span {
                    Some(s) => s.await,
                    None => return $crate::observability::distributed_tracing::TracingSpan::placeholder(),
                };
                
                span
            }
        }
    };
}

#[macro_export]
macro_rules! record_span_outcome {
    ($span:expr, $outcome:expr) => {
        if let Some(tracing) = $crate::observability::distributed_tracing::DISTRIBUTED_TRACING.as_ref() {
            tracing.record_span(&$span, $outcome).await;
        }
    };
}

impl TracingSpan {
    pub fn placeholder() -> Self {
        Self {
            span: opentelemetry::trace::NoopSpan::new(),
            cx: Context::current(),
            name: "placeholder".to_string(),
            start_time: chrono::Utc::now(),
            tags: HashMap::new(),
        }
    }
}

// Global distributed tracing manager
pub static DISTRIBUTED_TRACING: once_cell::sync::Lazy<Option<DistributedTracingManager>> = once_cell::sync::Lazy::new(|| None);

pub fn init_distributed_tracing(
    service_name: &str,
    jaeger_endpoint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let manager = DistributedTracingManager::new(service_name, jaeger_endpoint)?;
    unsafe {
        let ptr = &DISTRIBUTED_TRACING as *const _ as *mut Option<DistributedTracingManager>;
        *ptr = Some(manager);
    }
    Ok(())
}