// src/repositories/mod.rs
use crate::analytics::{AnalyticsAlert, AttackPattern};
use crate::collectors::DataEvent;
use crate::error::{AppError, AppResult};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;

pub mod event_repository;
pub mod alert_repository;
pub mod pattern_repository;

#[async_trait]
pub trait Repository<T> {
    async fn create(&self, item: &T) -> AppResult<()>;
    async fn get_by_id(&self, id: &str) -> AppResult<Option<T>>;
    async fn update(&self, item: &T) -> AppResult<()>;
    async fn delete(&self, id: &str) -> AppResult<()>;
}

// Event Repository Implementation
pub struct EventRepository {
    pool: PgPool,
}

impl EventRepository {
    pub async fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_recent_events(&self, limit: i32) -> AppResult<Vec<DataEvent>> {
        let events = sqlx::query_as!(
            DataEvent,
            r#"
            SELECT id as event_id, event_type, timestamp, data
            FROM events
            ORDER BY timestamp DESC
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to fetch events: {}", e)))?;

        Ok(events)
    }

    pub async fn get_paginated_events(
        &self,
        limit: i32,
        offset: i32,
        event_type: Option<String>,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) -> AppResult<(Vec<DataEvent>, u32)> {
        let mut query = String::from(
            "SELECT id as event_id, event_type, timestamp, data FROM events WHERE 1=1"
        );
        let mut params: Vec<&dyn sqlx::postgres::PgArguments> = Vec::new();
        let mut param_count = 0;

        if let Some(ref et) = event_type {
            param_count += 1;
            query.push_str(&format!(" AND event_type = ${}", param_count));
        }

        if let Some(ref st) = start_time {
            param_count += 1;
            query.push_str(&format!(" AND timestamp >= ${}", param_count));
        }

        if let Some(ref et) = end_time {
            param_count += 1;
            query.push_str(&format!(" AND timestamp <= ${}", param_count));
        }

        query.push_str(" ORDER BY timestamp DESC");

        // Get total count
        let count_query = query.replace("SELECT id as event_id, event_type, timestamp, data", "SELECT COUNT(*)");
        let total_count: (i64,) = sqlx::query_as(&count_query)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to count events: {}", e)))?;

        // Add pagination
        param_count += 1;
        query.push_str(&format!(" LIMIT ${}", param_count));
        param_count += 1;
        query.push_str(&format!(" OFFSET ${}", param_count));

        let events = sqlx::query_as(&query)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to fetch paginated events: {}", e)))?;

        Ok((events, total_count.0 as u32))
    }

    pub async fn get_events_by_type(&self, event_type: &str, limit: i32) -> AppResult<Vec<DataEvent>> {
        let events = sqlx::query_as!(
            DataEvent,
            r#"
            SELECT id as event_id, event_type, timestamp, data
            FROM events
            WHERE event_type = $1
            ORDER BY timestamp DESC
            LIMIT $2
            "#,
            event_type,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to fetch events by type: {}", e)))?;

        Ok(events)
    }

    pub async fn get_events_in_timerange(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> AppResult<Vec<DataEvent>> {
        let events = sqlx::query_as!(
            DataEvent,
            r#"
            SELECT id as event_id, event_type, timestamp, data
            FROM events
            WHERE timestamp BETWEEN $1 AND $2
            ORDER BY timestamp DESC
            "#,
            start,
            end
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to fetch events in timerange: {}", e)))?;

        Ok(events)
    }
}

#[async_trait]
impl Repository<DataEvent> for EventRepository {
    async fn create(&self, event: &DataEvent) -> AppResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO events (id, event_type, timestamp, data)
            VALUES ($1, $2, $3, $4)
            "#,
            event.event_id,
            event.event_type,
            event.timestamp,
            serde_json::to_value(event.data).map_err(|e| AppError::Validation(e.to_string()))?
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to create event: {}", e)))?;
        
        Ok(())
    }

    async fn get_by_id(&self, id: &str) -> AppResult<Option<DataEvent>> {
        let event = sqlx::query_as!(
            DataEvent,
            r#"
            SELECT id as event_id, event_type, timestamp, data
            FROM events
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to get event by ID: {}", e)))?;

        Ok(event)
    }

    async fn update(&self, _item: &DataEvent) -> AppResult<()> {
        // Events are immutable, so update is not supported
        Err(AppError::Validation("Events cannot be updated".to_string()))
    }

    async fn delete(&self, id: &str) -> AppResult<()> {
        sqlx::query!("DELETE FROM events WHERE id = $1", id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to delete event: {}", e)))?;
        
        Ok(())
    }
}

// Alert Repository Implementation
pub struct AlertRepository {
    pool: PgPool,
}

impl AlertRepository {
    pub async fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_recent_alerts(&self, limit: i32) -> AppResult<Vec<AnalyticsAlert>> {
        let alerts = sqlx::query_as!(
            AnalyticsAlert,
            r#"
            SELECT id, alert_type, severity, title, description, timestamp, acknowledged, resolved, metadata
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to fetch alerts: {}", e)))?;

        Ok(alerts)
    }

    pub async fn get_alerts_by_severity(&self, severity: &str) -> AppResult<Vec<AnalyticsAlert>> {
        let alerts = sqlx::query_as!(
            AnalyticsAlert,
            r#"
            SELECT id, alert_type, severity, title, description, timestamp, acknowledged, resolved, metadata
            FROM alerts
            WHERE severity = $1
            ORDER BY timestamp DESC
            "#,
            severity
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to fetch alerts by severity: {}", e)))?;

        Ok(alerts)
    }

    pub async fn get_unacknowledged_alerts(&self) -> AppResult<Vec<AnalyticsAlert>> {
        let alerts = sqlx::query_as!(
            AnalyticsAlert,
            r#"
            SELECT id, alert_type, severity, title, description, timestamp, acknowledged, resolved, metadata
            FROM alerts
            WHERE acknowledged = false
            ORDER BY timestamp DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to fetch unacknowledged alerts: {}", e)))?;

        Ok(alerts)
    }

    pub async fn acknowledge_alert(&self, alert_id: &str) -> AppResult<()> {
        sqlx::query!(
            "UPDATE alerts SET acknowledged = true WHERE id = $1",
            alert_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to acknowledge alert: {}", e)))?;
        
        Ok(())
    }

    pub async fn resolve_alert(&self, alert_id: &str) -> AppResult<()> {
        sqlx::query!(
            "UPDATE alerts SET resolved = true WHERE id = $1",
            alert_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to resolve alert: {}", e)))?;
        
        Ok(())
    }
}

#[async_trait]
impl Repository<AnalyticsAlert> for AlertRepository {
    async fn create(&self, alert: &AnalyticsAlert) -> AppResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO alerts (id, alert_type, severity, title, description, timestamp, acknowledged, resolved, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            alert.id,
            alert.alert_type,
            alert.severity,
            alert.title,
            alert.description,
            alert.timestamp,
            alert.acknowledged,
            alert.resolved,
            serde_json::to_value(alert.metadata.clone()).map_err(|e| AppError::Validation(e.to_string()))?
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to create alert: {}", e)))?;
        
        Ok(())
    }

    async fn get_by_id(&self, id: &str) -> AppResult<Option<AnalyticsAlert>> {
        let alert = sqlx::query_as!(
            AnalyticsAlert,
            r#"
            SELECT id, alert_type, severity, title, description, timestamp, acknowledged, resolved, metadata
            FROM alerts
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to get alert by ID: {}", e)))?;

        Ok(alert)
    }

    async fn update(&self, alert: &AnalyticsAlert) -> AppResult<()> {
        sqlx::query!(
            r#"
            UPDATE alerts 
            SET alert_type = $2, severity = $3, title = $4, description = $5, 
                timestamp = $6, acknowledged = $7, resolved = $8, metadata = $9
            WHERE id = $1
            "#,
            alert.id,
            alert.alert_type,
            alert.severity,
            alert.title,
            alert.description,
            alert.timestamp,
            alert.acknowledged,
            alert.resolved,
            serde_json::to_value(alert.metadata.clone()).map_err(|e| AppError::Validation(e.to_string()))?
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to update alert: {}", e)))?;
        
        Ok(())
    }

    async fn delete(&self, id: &str) -> AppResult<()> {
        sqlx::query!("DELETE FROM alerts WHERE id = $1", id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to delete alert: {}", e)))?;
        
        Ok(())
    }
}

// Pattern Repository Implementation
pub struct PatternRepository {
    pool: PgPool,
}

impl PatternRepository {
    pub async fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_active_patterns(&self) -> AppResult<Vec<AttackPattern>> {
        let patterns = sqlx::query_as!(
            AttackPattern,
            r#"
            SELECT id, name, description, pattern_type, indicators, confidence, last_seen, frequency
            FROM attack_patterns
            WHERE last_seen > NOW() - INTERVAL '24 hours'
            ORDER BY frequency DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to fetch active patterns: {}", e)))?;

        Ok(patterns)
    }

    pub async fn get_patterns_by_type(&self, pattern_type: &str) -> AppResult<Vec<AttackPattern>> {
        let patterns = sqlx::query_as!(
            AttackPattern,
            r#"
            SELECT id, name, description, pattern_type, indicators, confidence, last_seen, frequency
            FROM attack_patterns
            WHERE pattern_type = $1
            ORDER BY last_seen DESC
            "#,
            pattern_type
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to fetch patterns by type: {}", e)))?;

        Ok(patterns)
    }

    pub async fn update_pattern_frequency(&self, pattern_id: &str, frequency: u32) -> AppResult<()> {
        sqlx::query!(
            "UPDATE attack_patterns SET frequency = $2, last_seen = NOW() WHERE id = $1",
            pattern_id,
            frequency
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to update pattern frequency: {}", e)))?;
        
        Ok(())
    }
}

#[async_trait]
impl Repository<AttackPattern> for PatternRepository {
    async fn create(&self, pattern: &AttackPattern) -> AppResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO attack_patterns (id, name, description, pattern_type, indicators, confidence, last_seen, frequency)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                pattern_type = EXCLUDED.pattern_type,
                indicators = EXCLUDED.indicators,
                confidence = EXCLUDED.confidence,
                last_seen = EXCLUDED.last_seen,
                frequency = EXCLUDED.frequency
            "#,
            pattern.id,
            pattern.name,
            pattern.description,
            pattern.pattern_type,
            serde_json::to_value(pattern.indicators.clone()).map_err(|e| AppError::Validation(e.to_string()))?,
            pattern.confidence,
            pattern.last_seen,
            pattern.frequency
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to create pattern: {}", e)))?;
        
        Ok(())
    }

    async fn get_by_id(&self, id: &str) -> AppResult<Option<AttackPattern>> {
        let pattern = sqlx::query_as!(
            AttackPattern,
            r#"
            SELECT id, name, description, pattern_type, indicators, confidence, last_seen, frequency
            FROM attack_patterns
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to get pattern by ID: {}", e)))?;

        Ok(pattern)
    }

    async fn update(&self, pattern: &AttackPattern) -> AppResult<()> {
        sqlx::query!(
            r#"
            UPDATE attack_patterns 
            SET name = $2, description = $3, pattern_type = $4, indicators = $5, 
                confidence = $6, last_seen = $7, frequency = $8
            WHERE id = $1
            "#,
            pattern.id,
            pattern.name,
            pattern.description,
            pattern.pattern_type,
            serde_json::to_value(pattern.indicators.clone()).map_err(|e| AppError::Validation(e.to_string()))?,
            pattern.confidence,
            pattern.last_seen,
            pattern.frequency
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to update pattern: {}", e)))?;
        
        Ok(())
    }

    async fn delete(&self, id: &str) -> AppResult<()> {
        sqlx::query!("DELETE FROM attack_patterns WHERE id = $1", id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to delete pattern: {}", e)))?;
        
        Ok(())
    }
}