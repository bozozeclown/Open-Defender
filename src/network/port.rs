// src/network/ports.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::{Result, Context};
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
pub struct PortConfig {
    pub ports: PortDefinitions,
    pub environments: HashMap<String, EnvironmentConfig>,
    pub security: SecurityConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PortDefinitions {
    pub application: ApplicationPorts,
    pub database: DatabasePorts,
    pub cache: CachePorts,
    pub monitoring: MonitoringPorts,
    pub development: DevelopmentPorts,
    pub external: ExternalPorts,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApplicationPorts {
    pub graphql: u16,
    pub websocket: u16,
    pub metrics: u16,
    pub health: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabasePorts {
    pub postgres: u16,
    pub postgres_exporter: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CachePorts {
    pub redis: u16,
    pub redis_exporter: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonitoringPorts {
    pub prometheus_ui: u16,
    pub prometheus_metrics: u16,
    pub grafana: u16,
    pub jaeger_ui: u16,
    pub jaeger_collector_http: u16,
    pub jaeger_collector_udp: u16,
    pub node_exporter: u16,
    pub cadvisor: u16,
    pub alertmanager: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DevelopmentPorts {
    pub debug: u16,
    pub hot_reload: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalPorts {
    pub https: u16,
    pub http: u16,
    pub ssh: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    pub host_ports: HostPortMappings,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostPortMappings {
    pub application: ApplicationPorts,
    pub database: DatabasePorts,
    pub cache: CachePorts,
    pub monitoring: MonitoringPorts,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub internal_only: Vec<String>,
    pub auth_required: Vec<String>,
    pub https_only: Vec<String>,
}

pub struct PortManager {
    config: PortConfig,
    environment: String,
}

impl PortManager {
    pub async fn new(config_path: &str, environment: &str) -> Result<Self> {
        let config_content = fs::read_to_string(config_path)
            .await
            .context("Failed to read port configuration")?;
        
        let config: PortConfig = serde_yaml::from_str(&config_content)
            .context("Failed to parse port configuration")?;
        
        Ok(Self {
            config,
            environment: environment.to_string(),
        })
    }

    pub fn get_service_port(&self, service: &str, port_name: &str) -> Result<u16> {
        let parts: Vec<&str> = service.split('.').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid service name format. Use 'category.service'"));
        }

        let category = parts[0];
        let service_name = parts[1];

        match category {
            "application" => self.get_application_port(port_name),
            "database" => self.get_database_port(port_name),
            "cache" => self.get_cache_port(port_name),
            "monitoring" => self.get_monitoring_port(port_name),
            "development" => self.get_development_port(port_name),
            "external" => self.get_external_port(port_name),
            _ => Err(anyhow::anyhow!("Unknown service category: {}", category)),
        }
    }

    pub fn get_host_port(&self, service: &str, port_name: &str) -> Result<u16> {
        let parts: Vec<&str> = service.split('.').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid service name format. Use 'category.service'"));
        }

        let category = parts[0];
        let service_name = parts[1];

        let env_config = self.config.environments.get(&self.environment)
            .ok_or_else(|| anyhow::anyhow!("Environment '{}' not found", self.environment))?;

        match category {
            "application" => Ok(env_config.host_ports.application.get_port(port_name)?),
            "database" => Ok(env_config.host_ports.database.get_port(port_name)?),
            "cache" => Ok(env_config.host_ports.cache.get_port(port_name)?),
            "monitoring" => Ok(env_config.host_ports.monitoring.get_port(port_name)?),
            _ => Err(anyhow::anyhow!("Host port not available for category: {}", category)),
        }
    }

    pub fn is_internal_only(&self, service: &str, port_name: &str) -> bool {
        let port_key = format!("{}.{}", service, port_name);
        self.config.security.internal_only.contains(&port_key)
    }

    pub fn requires_auth(&self, service: &str, port_name: &str) -> bool {
        let port_key = format!("{}.{}", service, port_name);
        self.config.security.auth_required.contains(&port_key)
    }

    pub fn requires_https(&self, service: &str, port_name: &str) -> bool {
        let port_key = format!("{}.{}", service, port_name);
        self.config.security.https_only.contains(&port_key)
    }

    pub fn validate_port_mappings(&self) -> Result<()> {
        let mut used_ports = std::collections::HashSet::new();
        
        // Check service ports for conflicts
        self.check_service_ports(&mut used_ports, "application", &self.config.ports.application)?;
        self.check_service_ports(&mut used_ports, "database", &self.config.ports.database)?;
        self.check_service_ports(&mut used_ports, "cache", &self.config.ports.cache)?;
        self.check_service_ports(&mut used_ports, "monitoring", &self.config.ports.monitoring)?;
        self.check_service_ports(&mut used_ports, "development", &self.config.ports.development)?;
        self.check_service_ports(&mut used_ports, "external", &self.config.ports.external)?;

        // Check host ports for conflicts
        if let Some(env_config) = self.config.environments.get(&self.environment) {
            let mut host_used_ports = std::collections::HashSet::new();
            
            self.check_host_ports(&mut host_used_ports, "application", &env_config.host_ports.application)?;
            self.check_host_ports(&mut host_used_ports, "database", &env_config.host_ports.database)?;
            self.check_host_ports(&mut host_used_ports, "cache", &env_config.host_ports.cache)?;
            self.check_host_ports(&mut host_used_ports, "monitoring", &env_config.host_ports.monitoring)?;
        }

        Ok(())
    }

    fn check_service_ports<T>(&self, used_ports: &mut std::collections::HashSet<u16>, category: &str, ports: &T) -> Result<()>
    where
        T: serde::Serialize,
    {
        let ports_map = serde_json::to_value(ports)
            .context("Failed to serialize ports")?;
        
        if let Some(obj) = ports_map.as_object() {
            for (port_name, port_value) in obj {
                if let Some(port_num) = port_value.as_u64() {
                    let port = port_num as u16;
                    if used_ports.contains(&port) {
                        return Err(anyhow::anyhow!("Port conflict: {} is used by multiple services", port));
                    }
                    used_ports.insert(port);
                }
            }
        }
        
        Ok(())
    }

    fn check_host_ports<T>(&self, used_ports: &mut std::collections::HashSet<u16>, category: &str, ports: &T) -> Result<()>
    where
        T: serde::Serialize,
    {
        self.check_service_ports(used_ports, category, ports)
    }

    fn get_application_port(&self, port_name: &str) -> Result<u16> {
        match port_name {
            "graphql" => Ok(self.config.ports.application.graphql),
            "websocket" => Ok(self.config.ports.application.websocket),
            "metrics" => Ok(self.config.ports.application.metrics),
            "health" => Ok(self.config.ports.application.health),
            _ => Err(anyhow::anyhow!("Unknown application port: {}", port_name)),
        }
    }

    fn get_database_port(&self, port_name: &str) -> Result<u16> {
        match port_name {
            "postgres" => Ok(self.config.ports.database.postgres),
            "postgres_exporter" => Ok(self.config.ports.database.postgres_exporter),
            _ => Err(anyhow::anyhow!("Unknown database port: {}", port_name)),
        }
    }

    fn get_cache_port(&self, port_name: &str) -> Result<u16> {
        match port_name {
            "redis" => Ok(self.config.ports.cache.redis),
            "redis_exporter" => Ok(self.config.ports.cache.redis_exporter),
            _ => Err(anyhow::anyhow!("Unknown cache port: {}", port_name)),
        }
    }

    fn get_monitoring_port(&self, port_name: &str) -> Result<u16> {
        match port_name {
            "prometheus_ui" => Ok(self.config.ports.monitoring.prometheus_ui),
            "prometheus_metrics" => Ok(self.config.ports.monitoring.prometheus_metrics),
            "grafana" => Ok(self.config.ports.monitoring.grafana),
            "jaeger_ui" => Ok(self.config.ports.monitoring.jaeger_ui),
            "jaeger_collector_http" => Ok(self.config.ports.monitoring.jaeger_collector_http),
            "jaeger_collector_udp" => Ok(self.config.ports.monitoring.jaeger_collector_udp),
            "node_exporter" => Ok(self.config.ports.monitoring.node_exporter),
            "cadvisor" => Ok(self.config.ports.monitoring.cadvisor),
            "alertmanager" => Ok(self.config.ports.monitoring.alertmanager),
            _ => Err(anyhow::anyhow!("Unknown monitoring port: {}", port_name)),
        }
    }

    fn get_development_port(&self, port_name: &str) -> Result<u16> {
        match port_name {
            "debug" => Ok(self.config.ports.development.debug),
            "hot_reload" => Ok(self.config.ports.development.hot_reload),
            _ => Err(anyhow::anyhow!("Unknown development port: {}", port_name)),
        }
    }

    fn get_external_port(&self, port_name: &str) -> Result<u16> {
        match port_name {
            "https" => Ok(self.config.ports.external.https),
            "http" => Ok(self.config.ports.external.http),
            "ssh" => Ok(self.config.ports.external.ssh),
            _ => Err(anyhow::anyhow!("Unknown external port: {}", port_name)),
        }
    }
}

trait PortGetter {
    fn get_port(&self, port_name: &str) -> Result<u16>;
}

impl PortGetter for ApplicationPorts {
    fn get_port(&self, port_name: &str) -> Result<u16> {
        match port_name {
            "graphql" => Ok(self.graphql),
            "websocket" => Ok(self.websocket),
            "metrics" => Ok(self.metrics),
            "health" => Ok(self.health),
            _ => Err(anyhow::anyhow!("Unknown application port: {}", port_name)),
        }
    }
}

impl PortGetter for DatabasePorts {
    fn get_port(&self, port_name: &str) -> Result<u16> {
        match port_name {
            "postgres" => Ok(self.postgres),
            "postgres_exporter" => Ok(self.postgres_exporter),
            _ => Err(anyhow::anyhow!("Unknown database port: {}", port_name)),
        }
    }
}

impl PortGetter for CachePorts {
    fn get_port(&self, port_name: &str) -> Result<u16> {
        match port_name {
            "redis" => Ok(self.redis),
            "redis_exporter" => Ok(self.redis_exporter),
            _ => Err(anyhow::anyhow!("Unknown cache port: {}", port_name)),
        }
    }
}

impl PortGetter for MonitoringPorts {
    fn get_port(&self, port_name: &str) -> Result<u16> {
        match port_name {
            "prometheus_ui" => Ok(self.prometheus_ui),
            "prometheus_metrics" => Ok(self.prometheus_metrics),
            "grafana" => Ok(self.grafana),
            "jaeger_ui" => Ok(self.jaeger_ui),
            "jaeger_collector_http" => Ok(self.jaeger_collector_http),
            "jaeger_collector_udp" => Ok(self.jaeger_collector_udp),
            "node_exporter" => Ok(self.node_exporter),
            "cadvisor" => Ok(self.cadvisor),
            "alertmanager" => Ok(self.alertmanager),
            _ => Err(anyhow::anyhow!("Unknown monitoring port: {}", port_name)),
        }
    }
}