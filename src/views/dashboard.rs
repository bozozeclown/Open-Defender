// src/views/dashboard.rs
use anyhow::{Context, Result};
use axum::{
    extract::{Path, Query, State},
    response::Html,
    routing::{get, get_service},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use tracing::{debug, error, info};

use crate::config::DashboardConfig;
use crate::utils::database::DatabaseManager;

pub struct DashboardView {
    config: DashboardConfig,
    db: Arc<DatabaseManager>,
    app_state: Arc<RwLock<AppState>>,
}

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<DatabaseManager>,
}

impl DashboardView {
    pub async fn new(config: &DashboardConfig, db: Arc<DatabaseManager>) -> Result<Self> {
        let app_state = Arc::new(RwLock::new(AppState { db: db.clone() }));

        Ok(Self {
            config: config.clone(),
            db,
            app_state,
        })
    }

    pub async fn run(&self) -> Result<()> {
        let app = Router::new()
            .route("/", get(dashboard))
            .route("/api/dashboard/summary", get(dashboard_summary))
            .route("/api/events", get(events))
            .route("/api/anomalies", get(anomalies))
            .route("/api/incidents", get(incidents))
            .nest_service("/static", get_service(ServeDir::new("static")))
            .with_state(self.app_state.clone());

        let listener = tokio::net::TcpListener::bind("0.0.0.0:5000")
            .await
            .context("Failed to bind to address")?;

        info!("Dashboard running on http://localhost:5000");
        axum::serve(listener, app)
            .await
            .context("Failed to start server")?;

        Ok(())
    }
}

async fn dashboard() -> Html<&'static str> {
    Html(
        r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Exploit Detector Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
            <div class="container-fluid">
                <a class="navbar-brand" href="#">Exploit Detector</a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarNav">
                    <ul class="navbar-nav">
                        <li class="nav-item">
                            <a class="nav-link active" href="/">Dashboard</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/events">Events</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/anomalies">Anomalies</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/incidents">Incidents</a>
                        </li>
                    </ul>
                </div>
            </div>
        </nav>

        <div class="container mt-4">
            <h1>Security Dashboard</h1>
            <div class="row">
                <div class="col-md-3">
                    <div class="card text-white bg-primary mb-3">
                        <div class="card-header">Total Events</div>
                        <div class="card-body">
                            <h5 class="card-title" id="total-events">0</h5>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-white bg-warning mb-3">
                        <div class="card-header">Anomalies</div>
                        <div class="card-body">
                            <h5 class="card-title" id="total-anomalies">0</h5>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-white bg-info mb-3">
                        <div class="card-header">Active Incidents</div>
                        <div class="card-body">
                            <h5 class="card-title" id="active-incidents">0</h5>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-white bg-success mb-3">
                        <div class="card-header">System Status</div>
                        <div class="card-body">
                            <h5 class="card-title">Operational</h5>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row mt-4">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">Event Types</div>
                        <div class="card-body">
                            <canvas id="event-types-chart"></canvas>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">Anomaly Scores</div>
                        <div class="card-body">
                            <canvas id="anomaly-scores-chart"></canvas>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row mt-4">
                <div class="col-md-12">
                    <div class="card">
                        <div class="card-header">Recent Events</div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-striped">
                                    <thead>
                                        <tr>
                                            <th>Timestamp</th>
                                            <th>Type</th>
                                            <th>Details</th>
                                        </tr>
                                    </thead>
                                    <tbody id="recent-events">
                                        <!-- Events will be populated here -->
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            // Fetch dashboard data
            fetch('/api/dashboard/summary')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-events').textContent = data.total_events;
                    document.getElementById('total-anomalies').textContent = data.total_anomalies;
                    document.getElementById('active-incidents').textContent = data.active_incidents;
                    
                    // Update charts
                    updateEventTypesChart(data.event_types);
                    updateAnomalyScoresChart(data.anomaly_scores);
                });
            
            // Fetch recent events
            fetch('/api/events?limit=10')
                .then(response => response.json())
                .then(data => {
                    const eventsTable = document.getElementById('recent-events');
                    eventsTable.innerHTML = '';
                    
                    data.events.forEach(event => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${new Date(event.timestamp).toLocaleString()}</td>
                            <td>${event.event_type}</td>
                            <td>${JSON.stringify(event.data).substring(0, 100)}...</td>
                        `;
                        eventsTable.appendChild(row);
                    });
                });
            
            function updateEventTypesChart(eventTypes) {
                const ctx = document.getElementById('event-types-chart').getContext('2d');
                new Chart(ctx, {
                    type: 'pie',
                    data: {
                        labels: Object.keys(eventTypes),
                        datasets: [{
                            data: Object.values(eventTypes),
                            backgroundColor: [
                                'rgba(255, 99, 132, 0.7)',
                                'rgba(54, 162, 235, 0.7)',
                                'rgba(255, 206, 86, 0.7)',
                                'rgba(75, 192, 192, 0.7)',
                                'rgba(153, 102, 255, 0.7)'
                            ]
                        }]
                    },
                    options: {
                        responsive: true
                    }
                });
            }
            
            function updateAnomalyScoresChart(anomalyScores) {
                const ctx = document.getElementById('anomaly-scores-chart').getContext('2d');
                new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: anomalyScores.map(score => score.timestamp),
                        datasets: [{
                            label: 'Anomaly Score',
                            data: anomalyScores.map(score => score.score),
                            borderColor: 'rgba(255, 99, 132, 1)',
                            backgroundColor: 'rgba(255, 99, 132, 0.2)',
                            tension: 0.1
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            }
        </script>
    </body>
    </html>
    "#,
    )
}

async fn dashboard_summary(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Result<axum::Json<DashboardSummary>, axum::response::ErrorResponse> {
    let state = state.read().await;
    let db = &state.db;

    // Get dashboard summary data
    let recent_events = db.get_recent_events(100).await.map_err(|e| {
        error!("Failed to get recent events: {}", e);
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let recent_anomalies = db.get_recent_anomalies(100).await.map_err(|e| {
        error!("Failed to get recent anomalies: {}", e);
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Calculate summary statistics
    let total_events = recent_events.len() as i64;
    let total_anomalies = recent_anomalies.len() as i64;
    let active_incidents = 0; // Placeholder

    // Count event types
    let mut event_types = HashMap::new();
    for event in &recent_events {
        *event_types.entry(event.event_type.clone()).or_insert(0) += 1;
    }

    // Prepare anomaly scores for chart
    let anomaly_scores = recent_anomalies
        .into_iter()
        .map(|(event, score)| AnomalyScore {
            timestamp: event.timestamp.to_rfc3339(),
            score,
        })
        .collect();

    Ok(axum::Json(DashboardSummary {
        total_events,
        total_anomalies,
        active_incidents,
        event_types,
        anomaly_scores,
    }))
}

#[derive(Serialize, Deserialize)]
struct DashboardSummary {
    total_events: i64,
    total_anomalies: i64,
    active_incidents: i64,
    event_types: HashMap<String, i64>,
    anomaly_scores: Vec<AnomalyScore>,
}

#[derive(Serialize, Deserialize)]
struct AnomalyScore {
    timestamp: String,
    score: f64,
}

async fn events(
    State(state): State<Arc<RwLock<AppState>>>,
    Query(params): Query<EventParams>,
) -> Result<axum::Json<EventsResponse>, axum::response::ErrorResponse> {
    let state = state.read().await;
    let db = &state.db;

    let limit = params.limit.unwrap_or(50);
    let events = db.get_recent_events(limit).await.map_err(|e| {
        error!("Failed to get events: {}", e);
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(axum::Json(EventsResponse { events }))
}

#[derive(Deserialize)]
struct EventParams {
    limit: Option<i64>,
}

#[derive(Serialize)]
struct EventsResponse {
    events: Vec<crate::collectors::DataEvent>,
}

async fn anomalies(
    State(state): State<Arc<RwLock<AppState>>>,
    Query(params): Query<AnomalyParams>,
) -> Result<axum::Json<AnomaliesResponse>, axum::response::ErrorResponse> {
    let state = state.read().await;
    let db = &state.db;

    let limit = params.limit.unwrap_or(50);
    let anomalies = db.get_recent_anomalies(limit).await.map_err(|e| {
        error!("Failed to get anomalies: {}", e);
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(axum::Json(AnomaliesResponse { anomalies }))
}

#[derive(Deserialize)]
struct AnomalyParams {
    limit: Option<i64>,
}

#[derive(Serialize)]
struct AnomaliesResponse {
    anomalies: Vec<(crate::collectors::DataEvent, f64)>,
}

async fn incidents(
    State(_state): State<Arc<RwLock<AppState>>>,
) -> Result<axum::Json<IncidentsResponse>, axum::response::ErrorResponse> {
    // Placeholder implementation
    Ok(axum::Json(IncidentsResponse { incidents: vec![] }))
}

#[derive(Serialize)]
struct IncidentsResponse {
    incidents: Vec<Incident>,
}

#[derive(Serialize)]
struct Incident {
    id: String,
    title: String,
    description: String,
    severity: String,
    status: String,
    created_at: String,
    updated_at: String,
}