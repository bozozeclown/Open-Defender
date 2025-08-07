// src/web/mod.rs
pub mod dashboard;
pub mod api;

use std::sync::Arc;
use axum::{extract::Extension, routing::get, Router};
use tower_http::cors::CorsLayer;
use crate::config::Config;
use crate::analytics::AnalyticsManager;
use crate::response::ResponseManager;
use crate::collectors::CollectorManager;
use crate::models::ModelManager;
use anyhow::{Context, Result};

pub struct WebServer {
    config: Arc<Config>,
    analytics: Arc<AnalyticsManager>,
    response_manager: Arc<ResponseManager>,
    collector_manager: Arc<CollectorManager>,
    model_manager: Arc<ModelManager>,
}

impl WebServer {
    pub fn new(
        config: Arc<Config>,
        analytics: Arc<AnalyticsManager>,
        response_manager: Arc<ResponseManager>,
        collector_manager: Arc<CollectorManager>,
        model_manager: Arc<ModelManager>,
    ) -> Self {
        Self {
            config,
            analytics,
            response_manager,
            collector_manager,
            model_manager,
        }
    }
    
    pub async fn run(&self) -> Result<()> {
        let app = Router::new()
            .route("/", get(dashboard::index))
            .route("/api/dashboard", get(api::dashboard_summary))
            .route("/api/events", get(api::get_events))
            .route("/api/anomalies", get(api::get_anomalies))
            .route("/api/incidents", get(api::get_incidents))
            .route("/api/vulnerabilities", get(api::get_vulnerabilities))
            .route("/api/threats", get(api::get_threats))
            .route("/api/system/health", get(api::get_system_health))
            .layer(CorsLayer::permissive())
            .layer(Extension(self.config.clone()))
            .layer(Extension(self.analytics.clone()))
            .layer(Extension(self.response_manager.clone()))
            .layer(Extension(self.collector_manager.clone()))
            .layer(Extension(self.model_manager.clone()));

        let addr = format!("{}:{}", self.config.dashboard.host, self.config.dashboard.port);
        let listener = tokio::net::TcpListener::bind(&addr).await
            .context("Failed to bind to address")?;
        
        println!("Web server running at http://{}", addr);
        
        axum::serve(listener, app).await
            .context("Failed to start web server")?;
        
        Ok(())
    }
}

// Dashboard handlers
pub mod dashboard {
    use axum::response::Html;
    
    pub async fn index() -> Html<&'static str> {
        Html(r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Exploit Detector Dashboard</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <div class="container-fluid">
                    <a class="navbar-brand" href="#">Exploit Detector</a>
                </div>
            </nav>
            
            <div class="container mt-4">
                <div class="row">
                    <div class="col-md-3">
                        <div class="card bg-primary text-white">
                            <div class="card-body">
                                <h5 class="card-title">Events Processed</h5>
                                <h2 id="events-count">0</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-warning text-white">
                            <div class="card-body">
                                <h5 class="card-title">Anomalies Detected</h5>
                                <h2 id="anomalies-count">0</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-danger text-white">
                            <div class="card-body">
                                <h5 class="card-title">Incidents</h5>
                                <h2 id="incidents-count">0</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-success text-white">
                            <div class="card-body">
                                <h5 class="card-title">System Health</h5>
                                <h2 id="system-health">Good</h2>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row mt-4">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h5>Event Timeline</h5>
                            </div>
                            <div class="card-body">
                                <canvas id="event-chart"></canvas>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h5>Anomaly Distribution</h5>
                            </div>
                            <div class="card-body">
                                <canvas id="anomaly-chart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row mt-4">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-header">
                                <h5>Recent Events</h5>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-striped">
                                        <thead>
                                            <tr>
                                                <th>Timestamp</th>
                                                <th>Type</th>
                                                <th>Details</th>
                                                <th>Score</th>
                                            </tr>
                                        </thead>
                                        <tbody id="events-table">
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                // Initialize dashboard
                document.addEventListener('DOMContentLoaded', function() {
                    fetchDashboardData();
                    setInterval(fetchDashboardData, 5000); // Refresh every 5 seconds
                });
                
                async function fetchDashboardData() {
                    try {
                        const response = await fetch('/api/dashboard');
                        const data = await response.json();
                        
                        // Update counters
                        document.getElementById('events-count').textContent = data.metrics.events_processed;
                        document.getElementById('anomalies-count').textContent = data.metrics.anomalies_detected;
                        document.getElementById('incidents-count').textContent = data.metrics.incidents_created;
                        document.getElementById('system-health').textContent = data.system_health.status;
                        
                        // Update charts
                        updateEventChart(data.event_timeline);
                        updateAnomalyChart(data.anomaly_distribution);
                        
                        // Update events table
                        updateEventsTable(data.recent_events);
                    } catch (error) {
                        console.error('Error fetching dashboard data:', error);
                    }
                }
                
                function updateEventChart(timeline) {
                    // Implementation for updating event timeline chart
                }
                
                function updateAnomalyChart(distribution) {
                    // Implementation for updating anomaly distribution chart
                }
                
                function updateEventsTable(events) {
                    const tableBody = document.getElementById('events-table');
                    tableBody.innerHTML = '';
                    
                    events.forEach(event => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${new Date(event.timestamp).toLocaleString()}</td>
                            <td>${event.event_type}</td>
                            <td>${JSON.stringify(event.data)}</td>
                            <td>${event.anomaly_score || 'N/A'}</td>
                        `;
                        tableBody.appendChild(row);
                    });
                }
            </script>
        </body>
        </html>
        "#)
    }
}

// API handlers
pub mod api {
    use axum::{extract::Extension, Json};
    use serde::{Deserialize, Serialize};
    use crate::analytics::AnalyticsManager;
    use crate::response::ResponseManager;
    use crate::collectors::CollectorManager;
    use crate::models::ModelManager;
    use crate::config::Config;
    use anyhow::Result;
    
    #[derive(Serialize)]
    pub struct DashboardResponse {
        pub metrics: crate::analytics::AnalyticsMetrics,
        pub event_timeline: Vec<EventTimelineData>,
        pub anomaly_distribution: Vec<AnomalyDistributionData>,
        pub recent_events: Vec<crate::collectors::DataEvent>,
        pub system_health: SystemHealth,
    }
    
    #[derive(Serialize)]
    pub struct EventTimelineData {
        pub timestamp: String,
        pub count: u32,
    }
    
    #[derive(Serialize)]
    pub struct AnomalyDistributionData {
        pub cluster_id: usize,
        pub count: u32,
    }
    
    #[derive(Serialize)]
    pub struct SystemHealth {
        pub status: String,
        pub cpu_usage: f64,
        pub memory_usage: f64,
        pub disk_usage: f64,
    }
    
    pub async fn dashboard_summary(
        Extension(analytics): Extension<Arc<AnalyticsManager>>,
        Extension(collector_manager): Extension<Arc<CollectorManager>>,
    ) -> Result<Json<DashboardResponse>> {
        let metrics = analytics.get_metrics().await;
        
        // Get recent events
        let recent_events = collector_manager.collect_events().await.unwrap_or_default();
        
        // Generate event timeline (simplified)
        let event_timeline = vec![
            EventTimelineData {
                timestamp: chrono::Utc::now().to_rfc3339(),
                count: recent_events.len() as u32,
            }
        ];
        
        // Generate anomaly distribution (simplified)
        let anomaly_distribution = vec![
            AnomalyDistributionData { cluster_id: 0, count: 10 },
            AnomalyDistributionData { cluster_id: 1, count: 5 },
            AnomalyDistributionData { cluster_id: 2, count: 3 },
        ];
        
        // Get system health
        let system_health = get_system_health().await;
        
        Ok(Json(DashboardResponse {
            metrics,
            event_timeline,
            anomaly_distribution,
            recent_events,
            system_health,
        }))
    }
    
    pub async fn get_events(
        Extension(collector_manager): Extension<Arc<CollectorManager>>,
    ) -> Result<Json<Vec<crate::collectors::DataEvent>>> {
        let events = collector_manager.collect_events().await.unwrap_or_default();
        Ok(Json(events))
    }
    
    pub async fn get_anomalies(
        Extension(model_manager): Extension<Arc<ModelManager>>,
        Extension(collector_manager): Extension<Arc<CollectorManager>>,
    ) -> Result<Json<Vec<crate::models::AnomalyResult>>> {
        let events = collector_manager.collect_events().await.unwrap_or_default();
        let anomalies = model_manager.process_events(&events).await.unwrap_or_default();
        Ok(Json(anomalies))
    }
    
    pub async fn get_incidents(
        Extension(response_manager): Extension<Arc<ResponseManager>>,
    ) -> Result<Json<Vec<crate::response::Incident>>> {
        let incidents = response_manager.incident_orchestrator.get_open_incidents().await;
        Ok(Json(incidents))
    }
    
    pub async fn get_vulnerabilities() -> Result<Json<Vec<Vulnerability>>> {
        // This would integrate with the vulnerability scanner
        Ok(Json(vec![]))
    }
    
    pub async fn get_threats() -> Result<Json<Vec<Threat>>> {
        // This would integrate with threat intelligence
        Ok(Json(vec![]))
    }
    
    pub async fn get_system_health() -> Result<Json<SystemHealth>> {
        let health = get_system_health().await;
        Ok(Json(health))
    }
    
    async fn get_system_health() -> SystemHealth {
        use sysinfo::{System, SystemExt, ProcessExt, CpuExt};
        
        let mut sys = System::new_all();
        sys.refresh_all();
        
        let cpu_usage = sys.global_cpu_info().cpu_usage();
        let total_memory = sys.total_memory();
        let used_memory = sys.used_memory();
        let memory_usage = (used_memory as f64 / total_memory as f64) * 100.0;
        
        // Get disk usage (simplified)
        let disk_usage = 0.0; // Would need to implement disk usage calculation
        
        let status = if cpu_usage > 90.0 || memory_usage > 90.0 {
            "Critical".to_string()
        } else if cpu_usage > 70.0 || memory_usage > 70.0 {
            "Warning".to_string()
        } else {
            "Good".to_string()
        };
        
        SystemHealth {
            status,
            cpu_usage,
            memory_usage,
            disk_usage,
        }
    }
    
    #[derive(Serialize)]
    pub struct Vulnerability {
        pub id: String,
        pub title: String,
        pub severity: String,
        pub affected_software: String,
        pub published_date: String,
    }
    
    #[derive(Serialize)]
    pub struct Threat {
        pub id: String,
        pub threat_type: String,
        pub source_ip: String,
        pub target_ip: String,
        pub confidence: f32,
        pub timestamp: String,
    }
}