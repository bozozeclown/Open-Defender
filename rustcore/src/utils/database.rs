// src/utils/database.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ring::{aead, rand};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Pool, Sqlite, Row};
use std::path::Path;
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::collectors::DataEvent;
use crate::config::DatabaseConfig;

pub struct DatabaseManager {
    pool: Pool<Sqlite>,
    encryption_key: Option<aead::LessSafeKey>,
}

impl DatabaseManager {
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        // Create database pool
        let pool = SqlitePoolOptions::new()
            .max_connections(config.max_connections)
            .connect(&config.path)
            .await
            .context("Failed to create database pool")?;

        // Run migrations
        Self::run_migrations(&pool).await?;

        // Initialize encryption key if provided
        let encryption_key = if let Some(key_str) = &config.encryption_key {
            let key_bytes = base64::decode(key_str)
                .context("Failed to decode encryption key")?;
            let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)
                .context("Failed to create encryption key")?;
            Some(aead::LessSafeKey::new(unbound_key))
        } else {
            None
        };

        Ok(Self { pool, encryption_key })
    }

    async fn run_migrations(pool: &Pool<Sqlite>) -> Result<()> {
        // Create tables if they don't exist
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                data TEXT NOT NULL
            )
            "#,
        )
        .execute(pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS anomalies (
                id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                score REAL NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (event_id) REFERENCES events (id)
            )
            "#,
        )
        .execute(pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(pool)
        .await?;

        info!("Database migrations completed");
        Ok(())
    }

    pub async fn store_event(&self, event: &DataEvent) -> Result<()> {
        let event_json = serde_json::to_string(event)
            .context("Failed to serialize event")?;

        sqlx::query(
            r#"
            INSERT INTO events (id, event_type, timestamp, data)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(event.event_id.to_string())
        .bind(&event.event_type)
        .bind(event.timestamp.to_rfc3339())
        .bind(event_json)
        .execute(&self.pool)
        .await
        .context("Failed to store event")?;

        debug!("Stored event: {}", event.event_id);
        Ok(())
    }

    pub async fn store_anomaly(&self, event: &DataEvent, score: f64) -> Result<()> {
        let anomaly_id = Uuid::new_v4();
        let timestamp = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO anomalies (id, event_id, score, timestamp)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(anomaly_id.to_string())
        .bind(event.event_id.to_string())
        .bind(score)
        .bind(timestamp.to_rfc3339())
        .execute(&self.pool)
        .await
        .context("Failed to store anomaly")?;

        debug!("Stored anomaly: {} with score: {}", anomaly_id, score);
        Ok(())
    }

    pub async fn get_recent_events(&self, limit: i64) -> Result<Vec<DataEvent>> {
        let rows = sqlx::query(
            r#"
            SELECT data FROM events
            ORDER BY timestamp DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut events = Vec::new();
        for row in rows {
            let data: String = row.get("data");
            let event: DataEvent = serde_json::from_str(&data)
                .context("Failed to deserialize event")?;
            events.push(event);
        }

        Ok(events)
    }

    pub async fn get_recent_anomalies(&self, limit: i64) -> Result<Vec<(DataEvent, f64)>> {
        let rows = sqlx::query(
            r#"
            SELECT e.data, a.score
            FROM anomalies a
            JOIN events e ON a.event_id = e.id
            ORDER BY a.timestamp DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut anomalies = Vec::new();
        for row in rows {
            let data: String = row.get("data");
            let event: DataEvent = serde_json::from_str(&data)
                .context("Failed to deserialize event")?;
            let score: f64 = row.get("score");
            anomalies.push((event, score));
        }

        Ok(anomalies)
    }

    pub async fn generate_report_data(&self) -> Result<ReportData> {
        // Get counts of different event types
        let event_counts = sqlx::query(
            r#"
            SELECT event_type, COUNT(*) as count
            FROM events
            GROUP BY event_type
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut event_type_counts = std::collections::HashMap::new();
        for row in event_counts {
            let event_type: String = row.get("event_type");
            let count: i64 = row.get("count");
            event_type_counts.insert(event_type, count);
        }

        // Get anomaly statistics
        let anomaly_stats = sqlx::query(
            r#"
            SELECT 
                COUNT(*) as total_anomalies,
                AVG(score) as avg_score,
                MIN(score) as min_score,
                MAX(score) as max_score
            FROM anomalies
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        let total_anomalies: i64 = anomaly_stats.get("total_anomalies");
        let avg_score: Option<f64> = anomaly_stats.get("avg_score");
        let min_score: Option<f64> = anomaly_stats.get("min_score");
        let max_score: Option<f64> = anomaly_stats.get("max_score");

        Ok(ReportData {
            event_type_counts,
            total_anomalies,
            avg_score,
            min_score,
            max_score,
            generated_at: Utc::now(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportData {
    pub event_type_counts: std::collections::HashMap<String, i64>,
    pub total_anomalies: i64,
    pub avg_score: Option<f64>,
    pub min_score: Option<f64>,
    pub max_score: Option<f64>,
    pub generated_at: DateTime<Utc>,
}