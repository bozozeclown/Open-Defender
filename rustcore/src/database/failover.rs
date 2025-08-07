// src/database/failover.rs
use sqlx::postgres::{PgConnectOptions, PgPool};
use sqlx::PgPool;
use std::time::Duration;
use anyhow::{Result, Context};
use crate::config::DatabaseConfig;
use tokio::time::sleep;
use tracing::{info, warn, error};

pub struct DatabaseFailoverManager {
    primary_pool: PgPool,
    replica_pools: Vec<PgPool>,
    current_primary: String,
    replicas: Vec<String>,
    failover_timeout: Duration,
}

impl DatabaseFailoverManager {
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        let primary_options = PgConnectOptions::from_str(&config.url)?
            .application_name("security-monitoring-primary");

        let primary_pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .connect_with(primary_options)
            .await?;

        let mut replica_pools = Vec::new();
        let mut replicas = Vec::new();

        if let Some(replica_urls) = &config.read_replicas {
            for replica_url in replica_urls.split(',') {
                let replica_url = replica_url.trim();
                if !replica_url.is_empty() {
                    let replica_options = PgConnectOptions::from_str(&format!("postgres://postgres:postgres@{}", replica_url))?
                        .application_name("security-monitoring-replica");

                    let replica_pool = PgPoolOptions::new()
                        .max_connections(config.max_connections / 2)
                        .connect_with(replica_options)
                        .await?;

                    replica_pools.push(replica_pool);
                    replicas.push(replica_url.to_string());
                }
            }
        }

        Ok(Self {
            primary_pool,
            replica_pools,
            current_primary: config.url.clone(),
            replicas,
            failover_timeout: Duration::from_secs(config.failover_timeout.unwrap_or(5)),
        })
    }

    pub fn get_primary_pool(&self) -> &PgPool {
        &self.primary_pool
    }

    pub fn get_read_pool(&self) -> &PgPool {
        if self.replica_pools.is_empty() {
            &self.primary_pool
        } else {
            // Simple round-robin selection
            let index = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as usize) % self.replica_pools.len();
            &self.replica_pools[index]
        }
    }

    pub async fn check_primary_health(&self) -> bool {
        match sqlx::query("SELECT 1")
            .fetch_one(self.get_primary_pool())
            .await
        {
            Ok(_) => true,
            Err(e) => {
                warn!("Primary database health check failed: {}", e);
                false
            }
        }
    }

    pub async fn failover_to_replica(&mut self) -> Result<()> {
        info!("Attempting database failover...");

        for (i, replica_pool) in self.replica_pools.iter().enumerate() {
            info!("Trying replica {}: {}", i, self.replicas[i]);

            match sqlx::query("SELECT 1")
                .fetch_one(replica_pool)
                .await
            {
                Ok(_) => {
                    info!("Successfully failed over to replica {}", self.replicas[i]);
                    return Ok(());
                }
                Err(e) => {
                    warn!("Replica {} health check failed: {}", self.replicas[i], e);
                }
            }

            sleep(Duration::from_millis(1000)).await;
        }

        error!("All replicas failed, unable to failover");
        Err(anyhow::anyhow!("Database failover failed"))
    }
}