// src/database/mod.rs
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::time::Duration;
use anyhow::{Result, Context};
use crate::config::DatabaseConfig;
use backoff::{ExponentialBackoff, future::retry};
use tracing::{info, warn, error};

pub struct DatabaseManager {
    pool: PgPool,
    config: DatabaseConfig,
}

impl DatabaseManager {
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        info!("Initializing database connection pool");
        
        let connect_options = PgConnectOptions::from_str(&config.url)?
            .application_name("security-monitoring")
            .log_statements(tracing::log::LevelFilter::Debug);

        // Configure connection pool with retry logic
        let pool = retry(ExponentialBackoff::default(), || async {
            let pool = PgPoolOptions::new()
                .max_connections(config.max_connections)
                .min_connections(config.min_connections.unwrap_or(1))
                .acquire_timeout(Duration::from_secs(config.pool_timeout))
                .idle_timeout(Duration::from_secs(300))
                .max_lifetime(Duration::from_secs(3600))
                .test_before_acquire(true)
                .connect_with(connect_options.clone())
                .await
                .context("Failed to create database connection pool")?;

            // Test the connection
            sqlx::query("SELECT 1")
                .fetch_one(&pool)
                .await
                .context("Database connection test failed")?;

            Ok(pool)
        }).await?;

        info!("Database connection pool established successfully");
        Ok(Self { 
            pool,
            config: config.clone(),
        })
    }

    pub fn get_pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn health_check(&self) -> Result<()> {
        retry(ExponentialBackoff::default(), || async {
            match sqlx::query("SELECT 1")
                .fetch_one(self.get_pool())
                .await
            {
                Ok(_) => {
                    info!("Database health check passed");
                    Ok(())
                }
                Err(e) => {
                    error!("Database health check failed: {}", e);
                    Err(e.into())
                }
            }
        }).await
    }

    // Execute with retry logic
    pub async fn execute_with_retry<F, R>(&self, op: F) -> Result<R>
    where
        F: Fn() -> futures::future::BoxFuture<'_, Result<R>>,
    {
        retry(ExponentialBackoff::default(), op).await
    }

    // Get read replica connection for read operations
    pub async fn get_read_connection(&self) -> Result<PgPool> {
        if let Some(replicas) = &self.config.read_replicas {
            if !replicas.is_empty() {
                // Simple round-robin selection
                let replica_url = replicas.first().unwrap();
                let connect_options = PgConnectOptions::from_str(replica_url)?
                    .application_name("security-monitoring-read");
                
                let pool = PgPoolOptions::new()
                    .max_connections(self.config.max_connections / 2)
                    .connect_with(connect_options)
                    .await?;
                
                return Ok(pool);
            }
        }
        Ok(self.pool.clone())
    }
}