// src/api/graphql.rs
use anyhow::{Context, Result};
use async_graphql::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::analytics::AnalyticsManager;
use crate::collectors::DataEvent;
use crate::config::ApiConfig;
use crate::error::AppError;
use crate::response::incident_response::Incident;
use crate::utils::database::DatabaseManager;
use crate::utils::telemetry::{HealthCheck, HealthStatus};

pub struct GraphQLApi {
    config: ApiConfig,
    schema: Schema<Query, Mutation, EmptySubscription>,
    db: Arc<DatabaseManager>,
    analytics: Arc<AnalyticsManager>,
}

// Pagination type for events
#[derive(Debug)]
pub struct PaginatedEvents {
    items: Vec<DataEvent>,
    total_count: u32,
    has_next_page: bool,
}

#[Object]
impl PaginatedEvents {
    async fn items(&self) -> Vec<DataEvent> {
        self.items.clone()
    }
    
    async fn total_count(&self) -> u32 {
        self.total_count
    }
    
    async fn has_next_page(&self) -> bool {
        self.has_next_page
    }
}

// Standardized error type
#[derive(Debug, SimpleObject)]
pub struct ApiError {
    code: String,
    message: String,
    details: Option<serde_json::Value>,
}

#[derive(Default)]
pub struct Query;

#[Object]
impl Query {
    async fn events(
        &self,
        ctx: &Context<'_>,
        limit: Option<i32>,
        offset: Option<i32>,
        event_type: Option<String>,
    ) -> Result<PaginatedEvents> {
        let db = ctx.data_unchecked::<Arc<DatabaseManager>>();
        let limit = limit.unwrap_or(50).min(1000); // Cap at 1000
        let offset = offset.unwrap_or(0);
        
        let events = db.get_recent_events(limit).await.map_err(|e| {
            error!("Failed to get events: {}", e);
            Error::new("Failed to fetch events")
        })?;
        
        // For pagination, we need total count - this is simplified
        let total_count = events.len() as u32 + offset;
        let has_next_page = events.len() >= limit as usize;
        
        Ok(PaginatedEvents {
            items: events,
            total_count,
            has_next_page,
        })
    }

    async fn event(&self, ctx: &Context<'_>, id: ID) -> Result<Option<DataEvent>> {
        let db = ctx.data_unchecked::<Arc<DatabaseManager>>();
        // Implementation would get specific event by ID
        Ok(None)
    }

    async fn incidents(
        &self,
        ctx: &Context<'_>,
        status: Option<String>,
        severity: Option<String>,
    ) -> Result<Vec<Incident>> {
        let incident_manager = ctx.data_unchecked::<Arc<crate::response::incident_response::IncidentResponseManager>>();
        
        let incidents = incident_manager.get_open_incidents().await;
        
        Ok(incidents.into_iter()
            .filter(|i| {
                (status.is_none() || i.status == status.as_ref().unwrap()) &&
                (severity.is_none() || i.severity == severity.as_ref().unwrap())
            })
            .collect())
    }

    async fn incident(&self, ctx: &Context<'_>, id: ID) -> Result<Option<Incident>> {
        let incident_manager = ctx.data_unchecked::<Arc<crate::response::incident_response::IncidentResponseManager>>();
        
        let incident_id = id.to_string();
        Ok(incident_manager.get_incident(&incident_id).await)
    }

    async fn analytics_metrics(&self, ctx: &Context<'_>) -> Result<crate::analytics::AnalyticsMetrics> {
        let analytics = ctx.data_unchecked::<Arc<AnalyticsManager>>();
        Ok(analytics.get_metrics().await)
    }

    async fn analytics_alerts(
        &self,
        ctx: &Context<'_>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<Vec<crate::analytics::AnalyticsAlert>> {
        let analytics = ctx.data_unchecked::<Arc<AnalyticsManager>>();
        let limit = limit.unwrap_or(50).min(1000);
        let offset = offset.unwrap_or(0);
        
        let alerts = analytics.get_alerts().await;
        Ok(alerts.into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn analytics_patterns(&self, ctx: &Context<'_>) -> Result<Vec<crate::analytics::AttackPattern>> {
        let analytics = ctx.data_unchecked::<Arc<AnalyticsManager>>();
        Ok(analytics.get_patterns().await)
    }

    async fn system_health(&self, ctx: &Context<'_>) -> Result<SystemHealth> {
        let analytics = ctx.data_unchecked::<Arc<AnalyticsManager>>();
        let health_status = analytics.get_health_status().await;
        let health_checks = analytics.get_health_checks().await;
        
        Ok(SystemHealth {
            status: match health_status {
                HealthStatus::Healthy => "healthy".to_string(),
                HealthStatus::Degraded => "degraded".to_string(),
                HealthStatus::Unhealthy => "unhealthy".to_string(),
            },
            checks: health_checks,
        })
    }
}

#[derive(Default)]
pub struct Mutation;

#[Object]
impl Mutation {
    async fn create_incident(
        &self,
        ctx: &Context<'_>,
        title: String,
        description: String,
        severity: String,
    ) -> Result<Incident> {
        let incident_manager = ctx.data_unchecked::<Arc<crate::response::incident_response::IncidentResponseManager>>();
        
        match incident_manager.create_incident(title, description, severity).await {
            Ok(incident_id) => {
                match incident_manager.get_incident(&incident_id).await {
                    Some(incident) => Ok(incident),
                    None => {
                        error!("Failed to retrieve created incident");
                        Err(Error::new("Failed to retrieve created incident"))
                    }
                }
            },
            Err(e) => {
                error!("Failed to create incident: {}", e);
                Err(Error::new(format!("Failed to create incident: {}", e)))
            }
        }
    }

    async fn update_incident(
        &self,
        ctx: &Context<'_>,
        id: ID,
        title: Option<String>,
        description: Option<String>,
        severity: Option<String>,
        status: Option<String>,
    ) -> Result<Incident> {
        let incident_manager = ctx.data_unchecked::<Arc<crate::response::incident_response::IncidentResponseManager>>();
        let incident_id = id.to_string();
        
        if let Some(title) = title {
            // Implementation would update incident title
        }
        
        if let Some(description) = description {
            // Implementation would update incident description
        }
        
        if let Some(severity) = severity {
            // Implementation would update incident severity
        }
        
        if let Some(status) = status {
            // Implementation would update incident status
        }
        
        let incident = incident_manager.get_incident(&incident_id).await
            .ok_or_else(|| {
                error!("Failed to retrieve updated incident");
                Error::new("Failed to retrieve updated incident")
            })?;
        
        Ok(incident)
    }

    async fn assign_incident(
        &self,
        ctx: &Context<'_>,
        id: ID,
        user: String,
    ) -> Result<Incident> {
        let incident_manager = ctx.data_unchecked::<Arc<crate::response::incident_response::IncidentResponseManager>>();
        let incident_id = id.to_string();
        
        match incident_manager.assign_incident(&incident_id, user).await {
            Ok(()) => {
                let incident = incident_manager.get_incident(&incident_id).await
                    .ok_or_else(|| {
                        error!("Failed to retrieve assigned incident");
                        Error::new("Failed to retrieve assigned incident")
                    })?;
                Ok(incident)
            },
            Err(e) => {
                error!("Failed to assign incident: {}", e);
                Err(Error::new(format!("Failed to assign incident: {}", e)))
            }
        }
    }

    async fn close_incident(
        &self,
        ctx: &Context<'_>,
        id: ID,
        resolution: String,
    ) -> Result<Incident> {
        let incident_manager = ctx.data_unchecked::<Arc<crate::response::incident_response::IncidentResponseManager>>();
        let incident_id = id.to_string();
        
        match incident_manager.close_incident(&incident_id, resolution).await {
            Ok(()) => {
                let incident = incident_manager.get_incident(&incident_id).await
                    .ok_or_else(|| {
                        error!("Failed to retrieve closed incident");
                        Error::new("Failed to retrieve closed incident")
                    })?;
                Ok(incident)
            },
            Err(e) => {
                error!("Failed to close incident: {}", e);
                Err(Error::new(format!("Failed to close incident: {}", e)))
            }
        }
    }

    async fn acknowledge_alert(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<crate::analytics::AnalyticsAlert> {
        let analytics = ctx.data_unchecked::<Arc<AnalyticsManager>>();
        let alert_id = id.to_string();
        
        match analytics.acknowledge_alert(&alert_id).await {
            Ok(()) => {
                let alerts = analytics.get_alerts().await;
                alerts.into_iter()
                    .find(|a| a.id == alert_id)
                    .ok_or_else(|| {
                        error!("Alert not found after acknowledgment");
                        Error::new("Alert not found")
                    })
            },
            Err(AppError::NotFound(msg)) => {
                warn!("Alert not found: {}", msg);
                Err(Error::new("Alert not found"))
            },
            Err(e) => {
                error!("Failed to acknowledge alert: {}", e);
                Err(Error::new(format!("Failed to acknowledge alert: {}", e)))
            }
        }
    }

    async fn resolve_alert(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<crate::analytics::AnalyticsAlert> {
        let analytics = ctx.data_unchecked::<Arc<AnalyticsManager>>();
        let alert_id = id.to_string();
        
        match analytics.resolve_alert(&alert_id).await {
            Ok(()) => {
                let alerts = analytics.get_alerts().await;
                alerts.into_iter()
                    .find(|a| a.id == alert_id)
                    .ok_or_else(|| {
                        error!("Alert not found after resolution");
                        Error::new("Alert not found")
                    })
            },
            Err(AppError::NotFound(msg)) => {
                warn!("Alert not found: {}", msg);
                Err(Error::new("Alert not found"))
            },
            Err(e) => {
                error!("Failed to resolve alert: {}", e);
                Err(Error::new(format!("Failed to resolve alert: {}", e)))
            }
        }
    }
}

#[derive(SimpleObject)]
pub struct SystemHealth {
    pub status: String,
    pub checks: Vec<HealthCheck>,
}

#[derive(SimpleObject)]
pub struct DataEventGQL {
    pub id: ID,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub data: serde_json::Value,
}

impl From<DataEvent> for DataEventGQL {
    fn from(event: DataEvent) -> Self {
        Self {
            id: ID::from(&event.event_id),
            event_type: event.event_type,
            timestamp: event.timestamp,
            data: serde_json::to_value(event.data).unwrap_or_default(),
        }
    }
}

#[derive(SimpleObject)]
pub struct IncidentGQL {
    pub id: ID,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Incident> for IncidentGQL {
    fn from(incident: Incident) -> Self {
        Self {
            id: ID::from(&incident.id),
            title: incident.title,
            description: incident.description,
            severity: incident.severity,
            status: incident.status,
            created_at: incident.created_at,
            updated_at: incident.updated_at,
        }
    }
}

impl GraphQLApi {
    pub async fn new(
        config: ApiConfig,
        db: Arc<DatabaseManager>,
        analytics: Arc<AnalyticsManager>,
    ) -> Result<Self> {
        let schema = Schema::build(Query, Mutation, EmptySubscription)
            .data(db.clone())
            .data(analytics.clone())
            .finish();

        Ok(Self {
            config,
            schema,
            db,
            analytics,
        })
    }

    pub async fn run(&self) -> Result<()> {
        info!("Starting GraphQL API server on {}", self.config.graphql.endpoint);

        let app = axum::Router::new()
            .route("/", axum::routing::get(graphql_playground))
            .route("/graphql", axum::routing::post(graphql_handler))
            .layer(axum::extract::Extension(self.schema.clone()));

        let listener = tokio::net::TcpListener::bind(&self.config.graphql.endpoint)
            .await
            .context("Failed to bind to address")?;

        axum::serve(listener, app)
            .await
            .context("Failed to start GraphQL server")?;

        Ok(())
    }
}

async fn graphql_handler(
    schema: Extension<Schema<Query, Mutation, EmptySubscription>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    let mut request = async_graphql_axum::GraphQLRequest::from(req);
    let response = schema.execute(request.into()).await;
    axum::response::Json(response).into_response()
}

async fn graphql_playground() -> axum::response::Html<String> {
    axum::response::Html(async_graphql::http::GraphQLPlaygroundConfig::new("/graphql").into())
}