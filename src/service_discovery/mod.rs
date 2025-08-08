// src/service_discovery/mod.rs
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::{info, warn, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub port: u16,
    pub health_check: Option<HealthCheckConfig>,
    pub connection_pool: Option<ConnectionPoolConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub path: Option<String>,
    pub command: Option<String>,
    pub interval: u64,
    pub timeout: u64,
    pub retries: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub name: String,
    pub services: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServicesConfig {
    pub services: HashMap<String, ServiceConfig>,
    pub networks: HashMap<String, NetworkConfig>,
}

pub struct ServiceDiscovery {
    services: HashMap<String, ServiceConfig>,
    networks: HashMap<String, NetworkConfig>,
    service_health: HashMap<String, bool>,
}

impl ServiceDiscovery {
    pub async fn new(config_path: &str) -> Result<Self> {
        let config_content = tokio::fs::read_to_string(config_path)
            .await
            .context("Failed to read services configuration")?;
        
        let services_config: ServicesConfig = serde_yaml::from_str(&config_content)
            .context("Failed to parse services configuration")?;
        
        let mut service_health = HashMap::new();
        for name in services_config.services.keys() {
            service_health.insert(name.clone(), true);
        }
        
        Ok(Self {
            services: services_config.services,
            networks: services_config.networks,
            service_health,
        })
    }

    pub fn get_service_address(&self, service_name: &str) -> Result<SocketAddr> {
        let service = self.services.get(service_name)
            .ok_or_else(|| anyhow::anyhow!("Service '{}' not found", service_name))?;
        
        let host = match service_name {
            "postgres" => "postgres",
            "redis" => "redis",
            "security-monitoring" => "localhost",
            _ => service_name,
        };

        format!("{}:{}", host, service.port)
            .parse()
            .context("Failed to parse service address")
    }

    pub fn get_service_url(&self, service_name: &str) -> Result<String> {
        let service = self.services.get(service_name)
            .ok_or_else(|| anyhow::anyhow!("Service '{}' not found", service_name))?;
        
        let host = match service_name {
            "postgres" => "postgres",
            "redis" => "redis",
            "security-monitoring" => "localhost",
            _ => service_name,
        };

        Ok(format!("{}:{}", host, service.port))
    }

    pub fn is_service_healthy(&self, service_name: &str) -> bool {
        self.service_health.get(service_name).copied().unwrap_or(false)
    }

    pub async fn check_service_health(&mut self, service_name: &str) -> Result<bool> {
        let service = self.services.get(service_name)
            .ok_or_else(|| anyhow::anyhow!("Service '{}' not found", service_name))?;
        
        let health_check = service.health_check.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No health check configured for service '{}'", service_name))?;
        
        let is_healthy = match &health_check.path {
            Some(path) => {
                let url = format!("http://{}{}{}", self.get_service_url(service_name)?, path, "");
                let client = reqwest::Client::new();
                
                match client
                    .get(&url)
                    .timeout(Duration::from_secs(health_check.timeout))
                    .send()
                    .await
                {
                    Ok(response) => response.status().is_success(),
                    Err(e) => {
                        warn!("Health check failed for service '{}': {}", service_name, e);
                        false
                    }
                }
            },
            Some(command) => {
                // For services like Redis that use command-based health checks
                match service_name {
                    "redis" => {
                        let client = redis::Client::open(self.get_service_url(service_name)?)?;
                        let mut con = client.get_async_connection().await?;
                        redis::cmd("PING").query_async::<_, String>(&mut con).await.is_ok()
                    },
                    _ => false
                }
            },
            _ => false,
        };

        self.service_health.insert(service_name.to_string(), is_healthy);
        
        if is_healthy {
            info!("Service '{}' is healthy", service_name);
        } else {
            warn!("Service '{}' is unhealthy", service_name);
        }

        Ok(is_healthy)
    }

    pub async fn start_health_monitoring(&mut self) {
        let services_to_monitor: Vec<String> = self.services.keys().cloned().collect();
        
        tokio::spawn(async move {
            loop {
                for service_name in &services_to_monitor {
                    if let Err(e) = self.check_service_health(service_name).await {
                        error!("Failed to check health for service '{}': {}", service_name, e);
                    }
                }
                
                sleep(Duration::from_secs(30)).await;
            }
        });
    }

    pub fn get_network_services(&self, network_name: &str) -> Vec<&str> {
        if let Some(network) = self.networks.get(network_name) {
            network.services.iter().map(|s| s.as_str()).collect()
        } else {
            Vec::new()
        }
    }
}
