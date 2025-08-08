use async_graphql::*;
use crate::analytics::detection::DetectionResult;
use crate::health::HealthStatus;

#[derive(SimpleObject)]
pub struct DetectionResultGql {
    pub id: ID,
    pub detection_type: String,
    pub confidence: f64,
    pub severity: String,
    pub description: String,
    pub metadata: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(InputObject)]
pub struct AnalysisFilter {
    pub event_types: Option<Vec<String>>,
    pub time_range: Option<DateRange>,
    pub min_confidence: Option<f64>,
}

#[derive(InputObject)]
pub struct DateRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

#[derive(SimpleObject)]
pub struct HealthStatusGql {
    pub overall: String,
    pub checks: Vec<HealthCheckGql>,
}

#[derive(SimpleObject)]
pub struct HealthCheckGql {
    pub name: String,
    pub status: String,
    pub message: String,
    pub duration_ms: u64,
}

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    async fn detection_results(
        &self,
        ctx: &Context<'_>,
        filter: Option<AnalysisFilter>,
    ) -> Result<Vec<DetectionResultGql>> {
        // Implement with proper filtering and pagination
        Ok(vec![])
    }

    async fn health_status(&self, ctx: &Context<'_>) -> Result<HealthStatusGql> {
        let health_checker = ctx.data::<HealthChecker>()?;
        let status = health_checker.check_health().await;
        
        Ok(HealthStatusGql {
            overall: format!("{:?}", status.overall),
            checks: status.checks.into_iter().map(|c| HealthCheckGql {
                name: c.name,
                status: format!("{:?}", c.status),
                message: c.message,
                duration_ms: c.duration_ms,
            }).collect(),
        })
    }
}

pub struct MutationRoot;

#[Object]
impl MutationRoot {
    async fn analyze_event(
        &self,
        ctx: &Context<'_>,
        event: String,
    ) -> Result<Vec<DetectionResultGql>> {
        // Parse event and run analysis
        Ok(vec![])
    }
}
