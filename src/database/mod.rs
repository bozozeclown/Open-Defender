// src/database/mod.rs
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::time::Duration;
use anyhow::{Result, Context};
use crate::config::DatabaseConfig;

pub struct DatabaseManager {
    pool: PgPool,
}

impl DatabaseManager {
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        let connect_options = PgConnectOptions::from_str(&config.url)?
            .application_name("security-monitoring")
            .log_statements(tracing::log::LevelFilter::Debug);

        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.max_connections / 2)
            .acquire_timeout(Duration::from_secs(config.pool_timeout))
            .idle_timeout(Duration::from_secs(300))
            .max_lifetime(Duration::from_secs(3600))
            .connect_with(connect_options)
            .await
            .context("Failed to create database connection pool")?;

        Ok(Self { pool })
    }

    pub fn get_pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .fetch_one(self.get_pool())
            .await
            .context("Database health check failed")?;
        Ok(())
    }
}
