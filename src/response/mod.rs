// src/response/mod.rs
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::config::Config;
use crate::collectors::DataEvent;
use crate::models::AnomalyResult;
use anyhow::{Context, Result};
use sysinfo::{ProcessExt, System, SystemExt};
use std::process::Command;
use std::net::IpAddr;
use std::fs;
use std::path::Path;

pub struct ResponseManager {
    config: Arc<Config>,
    response_handler: ResponseHandler,
    incident_orchestrator: IncidentOrchestrator,
    active_responses: Arc<RwLock<Vec<ResponseAction>>>,
}

impl ResponseManager {
    pub fn new(config: Arc<Config>) -> Self {
        let response_handler = ResponseHandler::new(config.clone());
        let incident_orchestrator = IncidentOrchestrator::new(config.clone());
        
        Self {
            config,
            response_handler,
            incident_orchestrator,
            active_responses: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    pub async fn handle_anomaly(&self, anomaly: &AnomalyResult, event: &DataEvent) -> Result<()> {
        if !self.config.response.automation_enabled {
            return Ok(());
        }
        
        // Create incident if anomaly score is high enough
        if anomaly.anomaly_score > self.config.ml.anomaly_threshold {
            let incident_id = self.incident_orchestrator.create_incident(
                "Anomaly Detected".to_string(),
                format!("High anomaly score detected: {}", anomaly.anomaly_score),
                "high".to_string(),
            ).await?;
            
            // Execute response actions
            let response_actions = self.response_handler.create_response_actions(anomaly, event).await?;
            
            for action in response_actions {
                self.execute_response_action(action).await?;
            }
        }
        
        Ok(())
    }
    
    async fn execute_response_action(&self, action: ResponseAction) -> Result<()> {
        // Add to active responses
        {
            let mut responses = self.active_responses.write().await;
            responses.push(action.clone());
        }
        
        // Execute the action with timeout
        let timeout = tokio::time::Duration::from_secs(self.config.response.response_timeout as u64);
        let result = tokio::time::timeout(timeout, self.perform_action(action.clone())).await;
        
        match result {
            Ok(action_result) => {
                // Update status
                {
                    let mut responses = self.active_responses.write().await;
                    if let Some(response) = responses.iter_mut().find(|r| r.id == action.id) {
                        response.status = "completed".to_string();
                        response.completed_at = Some(chrono::Utc::now());
                    }
                }
                
                action_result?;
            },
            Err(_) => {
                // Timeout occurred
                {
                    let mut responses = self.active_responses.write().await;
                    if let Some(response) = responses.iter_mut().find(|r| r.id == action.id) {
                        response.status = "timeout".to_string();
                        response.completed_at = Some(chrono::Utc::now());
                    }
                }
                
                return Err(anyhow::anyhow!("Response action timed out: {}", action.action_type));
            }
        }
        
        Ok(())
    }
    
    async fn perform_action(&self, action: ResponseAction) -> Result<()> {
        match action.action_type.as_str() {
            "terminate_process" => {
                if let Some(pid) = action.metadata.get("pid") {
                    if let Some(pid_str) = pid.as_str() {
                        let pid: u32 = pid_str.parse()?;
                        self.terminate_process(pid).await?;
                    }
                }
            },
            "block_ip" => {
                if let Some(ip) = action.metadata.get("ip") {
                    if let Some(ip_str) = ip.as_str() {
                        self.block_ip(ip_str).await?;
                    }
                }
            },
            "quarantine_file" => {
                if let Some(file_path) = action.metadata.get("file_path") {
                    if let Some(path_str) = file_path.as_str() {
                        self.quarantine_file(path_str).await?;
                    }
                }
            },
            "isolate_network" => {
                if let Some(ip) = action.metadata.get("ip") {
                    if let Some(ip_str) = ip.as_str() {
                        self.isolate_network(ip_str).await?;
                    }
                }
            },
            "disable_user" => {
                if let Some(username) = action.metadata.get("username") {
                    if let Some(user_str) = username.as_str() {
                        self.disable_user(user_str).await?;
                    }
                }
            },
            _ => {
                return Err(anyhow::anyhow!("Unknown action type: {}", action.action_type));
            }
        }
        
        Ok(())
    }
    
    async fn terminate_process(&self, pid: u32) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            // Windows implementation using taskkill
            let output = Command::new("taskkill")
                .args(&["/F", "/PID", &pid.to_string()])
                .output()
                .context("Failed to execute taskkill")?;
            
            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to terminate process: {}", String::from_utf8_lossy(&output.stderr)));
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            // Linux implementation using kill
            let output = Command::new("kill")
                .args(&["-9", &pid.to_string()])
                .output()
                .context("Failed to execute kill")?;
            
            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to terminate process: {}", String::from_utf8_lossy(&output.stderr)));
            }
        }
        
        log::info!("Terminated process with PID: {}", pid);
        Ok(())
    }
    
    async fn block_ip(&self, ip: &str) -> Result<()> {
        let ip_addr: IpAddr = ip.parse()
            .context("Invalid IP address")?;
        
        #[cfg(target_os = "windows")]
        {
            // Windows implementation using Windows Firewall
            let rule_name = format!("BlockIP_{}", ip.replace('.', "_"));
            let output = Command::new("netsh")
                .args(&[
                    "advfirewall", "firewall", "add", "rule",
                    "name=", &rule_name,
                    "dir=in", "action=block",
                    "remoteip=", ip
                ])
                .output()
                .context("Failed to execute netsh")?;
            
            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to block IP: {}", String::from_utf8_lossy(&output.stderr)));
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            // Linux implementation using iptables
            let output = Command::new("iptables")
                .args(&["-A", "INPUT", "-s", ip, "-j", "DROP"])
                .output()
                .context("Failed to execute iptables")?;
            
            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to block IP: {}", String::from_utf8_lossy(&output.stderr)));
            }
        }
        
        log::info!("Blocked IP address: {}", ip);
        Ok(())
    }
    
    async fn quarantine_file(&self, file_path: &str) -> Result<()> {
        let path = Path::new(file_path);
        
        if !path.exists() {
            return Err(anyhow::anyhow!("File does not exist: {}", file_path));
        }
        
        // Create quarantine directory if it doesn't exist
        let quarantine_dir = Path::new("/tmp/quarantine");
        fs::create_dir_all(quarantine_dir)
            .context("Failed to create quarantine directory")?;
        
        // Generate quarantine path
        let file_name = path.file_name()
            .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?;
        let quarantine_path = quarantine_dir.join(format!("{}_{}", chrono::Utc::now().timestamp(), file_name.to_string_lossy()));
        
        // Move file to quarantine
        fs::rename(path, &quarantine_path)
            .context("Failed to move file to quarantine")?;
        
        log::info!("Quarantined file: {} to {}", file_path, quarantine_path.display());
        Ok(())
    }
    
    async fn isolate_network(&self, ip: &str) -> Result<()> {
        // This is a more aggressive network isolation
        // It would block all traffic to/from the IP
        
        #[cfg(target_os = "windows")]
        {
            // Windows implementation
            let rule_name = format!("IsolateNetwork_{}", ip.replace('.', "_"));
            
            // Block inbound traffic
            let output = Command::new("netsh")
                .args(&[
                    "advfirewall", "firewall", "add", "rule",
                    "name=", &format!("{}_in", rule_name),
                    "dir=in", "action=block",
                    "remoteip=", ip
                ])
                .output()
                .context("Failed to execute netsh for inbound")?;
            
            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to block inbound traffic: {}", String::from_utf8_lossy(&output.stderr)));
            }
            
            // Block outbound traffic
            let output = Command::new("netsh")
                .args(&[
                    "advfirewall", "firewall", "add", "rule",
                    "name=", &format!("{}_out", rule_name),
                    "dir=out", "action=block",
                    "remoteip=", ip
                ])
                .output()
                .context("Failed to execute netsh for outbound")?;
            
            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to block outbound traffic: {}", String::from_utf8_lossy(&output.stderr)));
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            // Linux implementation
            let output = Command::new("iptables")
                .args(&["-A", "INPUT", "-s", ip, "-j", "DROP"])
                .output()
                .context("Failed to execute iptables for INPUT")?;
            
            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to block INPUT traffic: {}", String::from_utf8_lossy(&output.stderr)));
            }
            
            let output = Command::new("iptables")
                .args(&["-A", "OUTPUT", "-d", ip, "-j", "DROP"])
                .output()
                .context("Failed to execute iptables for OUTPUT")?;
            
            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to block OUTPUT traffic: {}", String::from_utf8_lossy(&output.stderr)));
            }
        }
        
        log::info!("Isolated network for IP: {}", ip);
        Ok(())
    }
    
    async fn disable_user(&self, username: &str) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            // Windows implementation using net user
            let output = Command::new("net")
                .args(&["user", username, "/active:no"])
                .output()
                .context("Failed to execute net user")?;
            
            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to disable user: {}", String::from_utf8_lossy(&output.stderr)));
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            // Linux implementation using usermod
            let output = Command::new("usermod")
                .args(&["--lock", username])
                .output()
                .context("Failed to execute usermod")?;
            
            if !output.status.success() {
                return Err(anyhow::anyhow!("Failed to disable user: {}", String::from_utf8_lossy(&output.stderr)));
            }
        }
        
        log::info!("Disabled user account: {}", username);
        Ok(())
    }
}

pub struct ResponseHandler {
    config: Arc<Config>,
}

impl ResponseHandler {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
    
    pub async fn create_response_actions(&self, anomaly: &AnomalyResult, event: &DataEvent) -> Result<Vec<ResponseAction>> {
        let mut actions = Vec::new();
        
        // Create response actions based on event type and anomaly score
        match &event.data {
            crate::collectors::EventData::Process { pid, name, .. } => {
                if anomaly.anomaly_score > 0.8 {
                    actions.push(ResponseAction {
                        id: uuid::Uuid::new_v4().to_string(),
                        action_type: "terminate_process".to_string(),
                        description: format!("Terminate suspicious process: {} (PID: {})", name, pid),
                        metadata: serde_json::json!({ "pid": pid }),
                        status: "pending".to_string(),
                        created_at: chrono::Utc::now(),
                        completed_at: None,
                    });
                }
            },
            crate::collectors::EventData::Network { src_ip, dst_ip, .. } => {
                if anomaly.anomaly_score > 0.7 {
                    actions.push(ResponseAction {
                        id: uuid::Uuid::new_v4().to_string(),
                        action_type: "block_ip".to_string(),
                        description: format!("Block suspicious IP: {}", src_ip),
                        metadata: serde_json::json!({ "ip": src_ip }),
                        status: "pending".to_string(),
                        created_at: chrono::Utc::now(),
                        completed_at: None,
                    });
                    
                    // For very high scores, isolate the network completely
                    if anomaly.anomaly_score > 0.9 {
                        actions.push(ResponseAction {
                            id: uuid::Uuid::new_v4().to_string(),
                            action_type: "isolate_network".to_string(),
                            description: format!("Isolate network for IP: {}", src_ip),
                            metadata: serde_json::json!({ "ip": src_ip }),
                            status: "pending".to_string(),
                            created_at: chrono::Utc::now(),
                            completed_at: None,
                        });
                    }
                }
            },
            crate::collectors::EventData::File { path, operation, process_id, user } => {
                if anomaly.anomaly_score > 0.8 && (operation == "create" || operation == "modify") {
                    actions.push(ResponseAction {
                        id: uuid::Uuid::new_v4().to_string(),
                        action_type: "quarantine_file".to_string(),
                        description: format!("Quarantine suspicious file: {}", path),
                        metadata: serde_json::json!({ "file_path": path }),
                        status: "pending".to_string(),
                        created_at: chrono::Utc::now(),
                        completed_at: None,
                    });
                    
                    // Also disable the user if the score is very high
                    if anomaly.anomaly_score > 0.9 {
                        actions.push(ResponseAction {
                            id: uuid::Uuid::new_v4().to_string(),
                            action_type: "disable_user".to_string(),
                            description: format!("Disable user account: {}", user),
                            metadata: serde_json::json!({ "username": user }),
                            status: "pending".to_string(),
                            created_at: chrono::Utc::now(),
                            completed_at: None,
                        });
                    }
                }
            },
            _ => {}
        }
        
        Ok(actions)
    }
}

pub struct IncidentOrchestrator {
    config: Arc<Config>,
    incidents: Arc<RwLock<Vec<Incident>>>,
}

impl IncidentOrchestrator {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            incidents: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    pub async fn create_incident(&self, title: String, description: String, severity: String) -> Result<String> {
        let incident = Incident {
            id: uuid::Uuid::new_v4().to_string(),
            title,
            description,
            severity,
            status: "open".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            assigned_to: None,
            resolution: None,
        };
        
        {
            let mut incidents = self.incidents.write().await;
            incidents.push(incident.clone());
        }
        
        log::info!("Created incident: {} - {}", incident.id, incident.title);
        Ok(incident.id)
    }
    
    pub async fn get_open_incidents(&self) -> Vec<Incident> {
        let incidents = self.incidents.read().await;
        incidents.iter()
            .filter(|i| i.status == "open")
            .cloned()
            .collect()
    }
    
    pub async fn get_incident(&self, incident_id: &str) -> Option<Incident> {
        let incidents = self.incidents.read().await;
        incidents.iter()
            .find(|i| i.id == incident_id)
            .cloned()
    }
    
    pub async fn assign_incident(&self, incident_id: &str, user: String) -> Result<()> {
        let mut incidents = self.incidents.write().await;
        
        if let Some(incident) = incidents.iter_mut().find(|i| i.id == incident_id) {
            incident.assigned_to = Some(user);
            incident.updated_at = chrono::Utc::now();
            log::info!("Assigned incident {} to user {}", incident_id, user);
            return Ok(());
        }
        
        Err(anyhow::anyhow!("Incident not found: {}", incident_id))
    }
    
    pub async fn close_incident(&self, incident_id: &str, resolution: String) -> Result<()> {
        let mut incidents = self.incidents.write().await;
        
        if let Some(incident) = incidents.iter_mut().find(|i| i.id == incident_id) {
            incident.status = "closed".to_string();
            incident.resolution = Some(resolution);
            incident.updated_at = chrono::Utc::now();
            log::info!("Closed incident {} with resolution: {}", incident_id, incident.resolution.as_ref().unwrap());
            return Ok(());
        }
        
        Err(anyhow::anyhow!("Incident not found: {}", incident_id))
    }
}

#[derive(Debug, Clone)]
pub struct ResponseAction {
    pub id: String,
    pub action_type: String,
    pub description: String,
    pub metadata: serde_json::Value,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone)]
pub struct Incident {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub assigned_to: Option<String>,
    pub resolution: Option<String>,
}
