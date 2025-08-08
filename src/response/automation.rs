// src/response/automation.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::collectors::DataEvent;
use crate::config::ResponseConfig;
use crate::response::incident_response::Incident;

pub struct ResponseAutomation {
    config: ResponseConfig,
    playbooks: Arc<RwLock<HashMap<String, Playbook>>>,
    execution_engine: ExecutionEngine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub triggers: Vec<Trigger>,
    pub steps: Vec<PlaybookStep>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trigger {
    pub event_type: String,
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub field: String,
    pub operator: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub id: String,
    pub name: String,
    pub description: String,
    pub action_type: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub on_success: Option<String>,
    pub on_failure: Option<String>,
    pub timeout_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub playbook_id: String,
    pub execution_id: String,
    pub incident_id: Option<String>,
    pub event: Option<DataEvent>,
    pub variables: HashMap<String, serde_json::Value>,
    pub current_step: Option<String>,
    pub status: ExecutionStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub logs: Vec<ExecutionLog>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Timeout,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLog {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
    pub step_id: Option<String>,
}

impl ResponseAutomation {
    pub fn new(config: ResponseConfig) -> Result<Self> {
        let playbooks = Arc::new(RwLock::new(HashMap::new()));
        let execution_engine = ExecutionEngine::new(config.clone())?;
        
        Ok(Self {
            config,
            playbooks,
            execution_engine,
        })
    }

    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing response automation");

        // Load default playbooks
        self.load_default_playbooks().await?;

        info!("Response automation initialized");
        Ok(())
    }

    async fn load_default_playbooks(&self) -> Result<()> {
        let mut playbooks = self.playbooks.write().await;

        // Add malware response playbook
        playbooks.insert(
            "malware_response".to_string(),
            Playbook {
                id: "malware_response".to_string(),
                name: "Malware Response Playbook".to_string(),
                description: "Automated response to detected malware".to_string(),
                triggers: vec![Trigger {
                    event_type: "anomaly".to_string(),
                    conditions: vec![
                        Condition {
                            field: "event_type".to_string(),
                            operator: "equals".to_string(),
                            value: serde_json::json!("file"),
                        },
                        Condition {
                            field: "score".to_string(),
                            operator: "greater_than".to_string(),
                            value: serde_json::json!(0.8),
                        },
                    ],
                }],
                steps: vec![
                    PlaybookStep {
                        id: "quarantine_file".to_string(),
                        name: "Quarantine File".to_string(),
                        description: "Move suspicious file to quarantine".to_string(),
                        action_type: "quarantine_file".to_string(),
                        parameters: {
                            let mut params = HashMap::new();
                            params.insert("destination".to_string(), serde_json::json!("C:\\Quarantine"));
                            params
                        },
                        on_success: Some("terminate_process".to_string()),
                        on_failure: Some("alert_admin".to_string()),
                        timeout_seconds: 30,
                    },
                    PlaybookStep {
                        id: "terminate_process".to_string(),
                        name: "Terminate Process".to_string(),
                        description: "Terminate the process that created the file".to_string(),
                        action_type: "terminate_process".to_string(),
                        parameters: HashMap::new(),
                        on_success: Some("scan_memory".to_string()),
                        on_failure: Some("alert_admin".to_string()),
                        timeout_seconds: 10,
                    },
                    PlaybookStep {
                        id: "scan_memory".to_string(),
                        name: "Scan Memory".to_string(),
                        description: "Scan process memory for malicious code".to_string(),
                        action_type: "scan_memory".to_string(),
                        parameters: HashMap::new(),
                        on_success: Some("update_ioc".to_string()),
                        on_failure: Some("alert_admin".to_string()),
                        timeout_seconds: 60,
                    },
                    PlaybookStep {
                        id: "update_ioc".to_string(),
                        name: "Update IOC".to_string(),
                        description: "Update threat intelligence with new indicators".to_string(),
                        action_type: "update_ioc".to_string(),
                        parameters: HashMap::new(),
                        on_success: Some("generate_report".to_string()),
                        on_failure: Some("alert_admin".to_string()),
                        timeout_seconds: 30,
                    },
                    PlaybookStep {
                        id: "generate_report".to_string(),
                        name: "Generate Report".to_string(),
                        description: "Generate incident report".to_string(),
                        action_type: "generate_report".to_string(),
                        parameters: HashMap::new(),
                        on_success: None,
                        on_failure: Some("alert_admin".to_string()),
                        timeout_seconds: 30,
                    },
                    PlaybookStep {
                        id: "alert_admin".to_string(),
                        name: "Alert Administrator".to_string(),
                        description: "Send alert to security administrator".to_string(),
                        action_type: "send_alert".to_string(),
                        parameters: {
                            let mut params = HashMap::new();
                            params.insert("recipient".to_string(), serde_json::json!("security@company.com"));
                            params.insert("priority".to_string(), serde_json::json!("high"));
                            params
                        },
                        on_success: None,
                        on_failure: None,
                        timeout_seconds: 10,
                    },
                ],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                enabled: true,
            },
        );

        // Add network intrusion playbook
        playbooks.insert(
            "network_intrusion".to_string(),
            Playbook {
                id: "network_intrusion".to_string(),
                name: "Network Intrusion Response".to_string(),
                description: "Automated response to network intrusion attempts".to_string(),
                triggers: vec![Trigger {
                    event_type: "anomaly".to_string(),
                    conditions: vec![
                        Condition {
                            field: "event_type".to_string(),
                            operator: "equals".to_string(),
                            value: serde_json::json!("network"),
                        },
                        Condition {
                            field: "score".to_string(),
                            operator: "greater_than".to_string(),
                            value: serde_json::json!(0.9),
                        },
                    ],
                }],
                steps: vec![
                    PlaybookStep {
                        id: "block_ip".to_string(),
                        name: "Block IP Address".to_string(),
                        description: "Block the source IP address at firewall".to_string(),
                        action_type: "block_ip".to_string(),
                        parameters: HashMap::new(),
                        on_success: Some("isolate_system".to_string()),
                        on_failure: Some("alert_admin".to_string()),
                        timeout_seconds: 30,
                    },
                    PlaybookStep {
                        id: "isolate_system".to_string(),
                        name: "Isolate System".to_string(),
                        description: "Isolate the affected system from network".to_string(),
                        action_type: "isolate_system".to_string(),
                        parameters: HashMap::new(),
                        on_success: Some("collect_forensics".to_string()),
                        on_failure: Some("alert_admin".to_string()),
                        timeout_seconds: 60,
                    },
                    PlaybookStep {
                        id: "collect_forensics".to_string(),
                        name: "Collect Forensics".to_string(),
                        description: "Collect forensic data from the system".to_string(),
                        action_type: "collect_forensics".to_string(),
                        parameters: HashMap::new(),
                        on_success: Some("update_ioc".to_string()),
                        on_failure: Some("alert_admin".to_string()),
                        timeout_seconds: 120,
                    },
                    PlaybookStep {
                        id: "update_ioc".to_string(),
                        name: "Update IOC".to_string(),
                        description: "Update threat intelligence with new indicators".to_string(),
                        action_type: "update_ioc".to_string(),
                        parameters: HashMap::new(),
                        on_success: Some("generate_report".to_string()),
                        on_failure: Some("alert_admin".to_string()),
                        timeout_seconds: 30,
                    },
                    PlaybookStep {
                        id: "generate_report".to_string(),
                        name: "Generate Report".to_string(),
                        description: "Generate incident report".to_string(),
                        action_type: "generate_report".to_string(),
                        parameters: HashMap::new(),
                        on_success: None,
                        on_failure: Some("alert_admin".to_string()),
                        timeout_seconds: 30,
                    },
                    PlaybookStep {
                        id: "alert_admin".to_string(),
                        name: "Alert Administrator".to_string(),
                        description: "Send alert to security administrator".to_string(),
                        action_type: "send_alert".to_string(),
                        parameters: {
                            let mut params = HashMap::new();
                            params.insert("recipient".to_string(), serde_json::json!("security@company.com"));
                            params.insert("priority".to_string(), serde_json::json!("critical"));
                            params
                        },
                        on_success: None,
                        on_failure: None,
                        timeout_seconds: 10,
                    },
                ],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                enabled: true,
            },
        );

        Ok(())
    }

    pub async fn process_event(&self, event: DataEvent, score: f64) -> Result<()> {
        if !self.config.automation_enabled {
            return Ok(());
        }

        // Find matching playbooks
        let playbooks = self.playbooks.read().await;
        
        for (_, playbook) in playbooks.iter() {
            if !playbook.enabled {
                continue;
            }

            // Check if playbook triggers match the event
            for trigger in &playbook.triggers {
                if self.evaluate_trigger(trigger, &event, score).await? {
                    info!("Executing playbook: {}", playbook.name);
                    
                    // Create execution context
                    let context = ExecutionContext {
                        playbook_id: playbook.id.clone(),
                        execution_id: uuid::Uuid::new_v4().to_string(),
                        incident_id: None,
                        event: Some(event.clone()),
                        variables: HashMap::new(),
                        current_step: None,
                        status: ExecutionStatus::Pending,
                        started_at: Utc::now(),
                        completed_at: None,
                        logs: vec![],
                    };

                    // Execute playbook
                    if let Err(e) = self.execution_engine.execute_playbook(&playbook, context).await {
                        error!("Failed to execute playbook {}: {}", playbook.name, e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn evaluate_trigger(&self, trigger: &Trigger, event: &DataEvent, score: f64) -> Result<bool> {
        // Check event type
        if trigger.event_type != "anomaly" && trigger.event_type != event.event_type {
            return Ok(false);
        }

        // Evaluate all conditions
        for condition in &trigger.conditions {
            if !self.evaluate_condition(condition, event, score).await? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn evaluate_condition(&self, condition: &Condition, event: &DataEvent, score: f64) -> Result<bool> {
        let field_value = match condition.field.as_str() {
            "event_type" => serde_json::Value::String(event.event_type.clone()),
            "score" => serde_json::Value::Number(serde_json::Number::from_f64(score).unwrap()),
            _ => return Ok(false),
        };

        match condition.operator.as_str() {
            "equals" => field_value == condition.value,
            "not_equals" => field_value != condition.value,
            "greater_than" => {
                if let (Some(num1), Some(num2)) = (
                    field_value.as_f64(),
                    condition.value.as_f64(),
                ) {
                    num1 > num2
                } else {
                    false
                }
            }
            "less_than" => {
                if let (Some(num1), Some(num2)) = (
                    field_value.as_f64(),
                    condition.value.as_f64(),
                ) {
                    num1 < num2
                } else {
                    false
                }
            }
            "contains" => {
                if let (Some(str1), Some(str2)) = (
                    field_value.as_str(),
                    condition.value.as_str(),
                ) {
                    str1.contains(str2)
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    pub async fn execute_playbook_for_incident(&self, playbook_id: &str, incident: &Incident) -> Result<()> {
        let playbooks = self.playbooks.read().await;
        
        if let Some(playbook) = playbooks.get(playbook_id) {
            if !playbook.enabled {
                return Ok(());
            }

            info!("Executing playbook {} for incident {}", playbook.name, incident.id);
            
            // Create execution context
            let context = ExecutionContext {
                playbook_id: playbook.id.clone(),
                execution_id: uuid::Uuid::new_v4().to_string(),
                incident_id: Some(incident.id.clone()),
                event: None,
                variables: HashMap::new(),
                current_step: None,
                status: ExecutionStatus::Pending,
                started_at: Utc::now(),
                completed_at: None,
                logs: vec![],
            };

            // Execute playbook
            self.execution_engine.execute_playbook(playbook, context).await?;
        }

        Ok(())
    }
}

pub struct ExecutionEngine {
    config: ResponseConfig,
    action_handlers: HashMap<String, Box<dyn ActionHandler>>,
}

impl ExecutionEngine {
    pub fn new(config: ResponseConfig) -> Result<Self> {
        let mut action_handlers = HashMap::new();
        
        // Register action handlers
        action_handlers.insert("quarantine_file".to_string(), Box::new(QuarantineFileHandler::new()?));
        action_handlers.insert("terminate_process".to_string(), Box::new(TerminateProcessHandler::new()?));
        action_handlers.insert("scan_memory".to_string(), Box::new(ScanMemoryHandler::new()?));
        action_handlers.insert("update_ioc".to_string(), Box::new(UpdateIocHandler::new()?));
        action_handlers.insert("generate_report".to_string(), Box::new(GenerateReportHandler::new()?));
        action_handlers.insert("send_alert".to_string(), Box::new(SendAlertHandler::new(config.email.clone(), config.webhook.clone())?));
        action_handlers.insert("block_ip".to_string(), Box::new(BlockIpHandler::new()?));
        action_handlers.insert("isolate_system".to_string(), Box::new(IsolateSystemHandler::new()?));
        action_handlers.insert("collect_forensics".to_string(), Box::new(CollectForensicsHandler::new()?));

        Ok(Self {
            config,
            action_handlers,
        })
    }

    pub async fn execute_playbook(&self, playbook: &Playbook, mut context: ExecutionContext) -> Result<()> {
        context.status = ExecutionStatus::Running;
        
        // Execute steps in order
        let mut current_step_id = playbook.steps.first().map(|s| s.id.clone());
        
        while let Some(step_id) = current_step_id {
            context.current_step = Some(step_id.clone());
            
            // Find the step
            let step = playbook.steps.iter()
                .find(|s| s.id == step_id)
                .ok_or_else(|| anyhow::anyhow!("Step not found: {}", step_id))?;
            
            // Execute the step
            let result = self.execute_step(step, &mut context).await;
            
            // Determine next step
            current_step_id = match result {
                Ok(_) => step.on_success.clone(),
                Err(_) => step.on_failure.clone(),
            };
            
            // If no next step, we're done
            if current_step_id.is_none() {
                break;
            }
        }
        
        // Update execution status
        context.status = ExecutionStatus::Completed;
        context.completed_at = Some(Utc::now());
        
        Ok(())
    }

    async fn execute_step(&self, step: &PlaybookStep, context: &mut ExecutionContext) -> Result<()> {
        // Log step execution
        context.logs.push(ExecutionLog {
            timestamp: Utc::now(),
            level: "info".to_string(),
            message: format!("Executing step: {}", step.name),
            step_id: Some(step.id.clone()),
        });

        // Find the action handler
        let handler = self.action_handlers.get(&step.action_type)
            .ok_or_else(|| anyhow::anyhow!("No handler for action type: {}", step.action_type))?;
        
        // Execute with timeout
        let result = tokio::time::timeout(
            tokio::time::Duration::from_secs(step.timeout_seconds as u64),
            handler.execute(&step.parameters, context),
        ).await;

        match result {
            Ok(Ok(())) => {
                context.logs.push(ExecutionLog {
                    timestamp: Utc::now(),
                    level: "info".to_string(),
                    message: format!("Step completed successfully: {}", step.name),
                    step_id: Some(step.id.clone()),
                });
                Ok(())
            }
            Ok(Err(e)) => {
                context.logs.push(ExecutionLog {
                    timestamp: Utc::now(),
                    level: "error".to_string(),
                    message: format!("Step failed: {} - {}", step.name, e),
                    step_id: Some(step.id.clone()),
                });
                Err(e)
            }
            Err(_) => {
                context.logs.push(ExecutionLog {
                    timestamp: Utc::now(),
                    level: "error".to_string(),
                    message: format!("Step timed out: {}", step.name),
                    step_id: Some(step.id.clone()),
                });
                Err(anyhow::anyhow!("Step timed out"))
            }
        }
    }
}

#[async_trait::async_trait]
pub trait ActionHandler: Send + Sync {
    async fn execute(&self, parameters: &HashMap<String, serde_json::Value>, context: &ExecutionContext) -> Result<()>;
}

pub struct QuarantineFileHandler {
    quarantine_dir: String,
}

impl QuarantineFileHandler {
    pub fn new() -> Result<Self> {
        Ok(Self {
            quarantine_dir: "C:\\Quarantine".to_string(),
        })
    }
}

#[async_trait::async_trait]
impl ActionHandler for QuarantineFileHandler {
    async fn execute(&self, parameters: &HashMap<String, serde_json::Value>, context: &ExecutionContext) -> Result<()> {
        // Get file path from context
        let file_path = if let Some(event) = &context.event {
            if let crate::collectors::EventData::File { path, .. } = &event.data {
                path.clone()
            } else {
                return Err(anyhow::anyhow!("No file path in context"));
            }
        } else {
            return Err(anyhow::anyhow!("No event in context"));
        };

        // Create quarantine directory if it doesn't exist
        tokio::fs::create_dir_all(&self.quarantine_dir).await?;

        // Move file to quarantine
        let file_name = std::path::Path::new(&file_path)
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid file path"))?;

        let quarantine_path = format!("{}\\{}", self.quarantine_dir, file_name);
        tokio::fs::rename(&file_path, &quarantine_path).await?;

        info!("Quarantined file: {} to {}", file_path, quarantine_path);
        Ok(())
    }
}

pub struct TerminateProcessHandler;

impl TerminateProcessHandler {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}

#[async_trait::async_trait]
impl ActionHandler for TerminateProcessHandler {
    async fn execute(&self, _parameters: &HashMap<String, serde_json::Value>, context: &ExecutionContext) -> Result<()> {
        // Get process ID from context
        let pid = if let Some(event) = &context.event {
            if let crate::collectors::EventData::File { process_id, .. } = &event.data {
                *process_id
            } else {
                return Err(anyhow::anyhow!("No process ID in context"));
            }
        } else {
            return Err(anyhow::anyhow!("No event in context"));
        };

        // Terminate process
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::System::Threading::*;
            
            let handle = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) }?;
            if !handle.is_invalid() {
                unsafe { TerminateProcess(handle, 1) }?;
                info!("Terminated process: {}", pid);
            }
        }

        Ok(())
    }
}

// Other action handlers would be implemented similarly...

pub struct ScanMemoryHandler;

impl ScanMemoryHandler {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}

#[async_trait::async_trait]
impl ActionHandler for ScanMemoryHandler {
    async fn execute(&self, _parameters: &HashMap<String, serde_json::Value>, context: &ExecutionContext) -> Result<()> {
        // Get process ID from context
        let pid = if let Some(event) = &context.event {
            if let crate::collectors::EventData::File { process_id, .. } = &event.data {
                *process_id
            } else {
                return Err(anyhow::anyhow!("No process ID in context"));
            }
        } else {
            return Err(anyhow::anyhow!("No event in context"));
        };

        // Scan process memory for malicious patterns
        info!("Scanning memory for process: {}", pid);
        
        // Implementation would use memory scanning techniques
        // This is a placeholder
        
        Ok(())
    }
}

pub struct UpdateIocHandler;

impl UpdateIocHandler {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}

#[async_trait::async_trait]
impl ActionHandler for UpdateIocHandler {
    async fn execute(&self, _parameters: &HashMap<String, serde_json::Value>, context: &ExecutionContext) -> Result<()> {
        // Extract IOCs from the event
        if let Some(event) = &context.event {
            match &event.data {
                crate::collectors::EventData::File { path, hash, .. } => {
                    info!("Updating IOCs from file event: {}, hash: {:?}", path, hash);
                    // Implementation would update threat intelligence database
                }
                crate::collectors::EventData::Network { src_ip, dst_ip, .. } => {
                    info!("Updating IOCs from network event: {} -> {}", src_ip, dst_ip);
                    // Implementation would update threat intelligence database
                }
                _ => {}
            }
        }

        Ok(())
    }
}

pub struct GenerateReportHandler;

impl GenerateReportHandler {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}

#[async_trait::async_trait]
impl ActionHandler for GenerateReportHandler {
    async fn execute(&self, _parameters: &HashMap<String, serde_json::Value>, context: &ExecutionContext) -> Result<()> {
        let report_id = uuid::Uuid::new_v4();
        let report_path = format!("reports\\incident_report_{}.json", report_id);
        
        // Create report
        let report = serde_json::json!({
            "report_id": report_id,
            "execution_id": context.execution_id,
            "incident_id": context.incident_id,
            "playbook_id": context.playbook_id,
            "generated_at": Utc::now(),
            "steps": context.logs,
        });
        
        // Write report to file
        tokio::fs::write(&report_path, serde_json::to_string_pretty(&report)?).await?;
        
        info!("Generated report: {}", report_path);
        Ok(())
    }
}

pub struct SendAlertHandler {
    email_config: crate::config::EmailConfig,
    webhook_config: crate::config::WebhookConfig,
}

impl SendAlertHandler {
    pub fn new(email_config: crate::config::EmailConfig, webhook_config: crate::config::WebhookConfig) -> Result<Self> {
        Ok(Self {
            email_config,
            webhook_config,
        })
    }
}

#[async_trait::async_trait]
impl ActionHandler for SendAlertHandler {
    async fn execute(&self, parameters: &HashMap<String, serde_json::Value>, context: &ExecutionContext) -> Result<()> {
        let recipient = parameters.get("recipient")
            .and_then(|v| v.as_str())
            .unwrap_or("security@company.com");
        
        let priority = parameters.get("priority")
            .and_then(|v| v.as_str())
            .unwrap_or("medium");
        
        let subject = format!("Security Alert - {}", priority.to_uppercase());
        let body = format!(
            "Security incident detected.\n\nExecution ID: {}\nPlaybook: {}\nPriority: {}\n\nSteps executed:\n{}",
            context.execution_id,
            context.playbook_id,
            priority,
            context.logs.iter()
                .map(|log| format!("- {}: {}", log.timestamp, log.message))
                .collect::<Vec<_>>()
                .join("\n")
        );
        
        // Send email alert
        if self.email_config.enabled {
            // Implementation would send email
            info!("Sending email alert to {}: {}", recipient, subject);
        }
        
        // Send webhook alert
        if self.webhook_config.enabled {
            // Implementation would send webhook
            info!("Sending webhook alert to {}", self.webhook_config.url);
        }
        
        Ok(())
    }
}

// Other action handlers would be implemented similarly...
