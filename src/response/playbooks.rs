// src/response/playbooks.rs
use crate::error::AppResult;
use crate::response::incident_response::{Incident, IncidentResponseManager, ResponseAction};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct PlaybookManager {
    playbooks: Arc<RwLock<HashMap<String, Playbook>>>,
    execution_history: Arc<RwLock<HashMap<String, PlaybookExecution>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub incident_types: Vec<String>,
    pub severity_levels: Vec<String>,
    pub steps: Vec<PlaybookStep>,
    pub variables: HashMap<String, PlaybookVariable>,
    pub timeout_seconds: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub id: String,
    pub name: String,
    pub description: String,
    pub step_type: StepType,
    pub action: PlaybookAction,
    pub conditions: Vec<StepCondition>,
    pub on_success: Option<Vec<String>>, // IDs of next steps
    pub on_failure: Option<Vec<String>>, // IDs of next steps
    pub timeout_seconds: u64,
    pub retry_count: u32,
    pub retry_delay_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepType {
    Manual,
    Automated,
    Conditional,
    Parallel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlaybookAction {
    IsolateHost { host_ip: String },
    BlockIp { ip_address: String },
    KillProcess { host_ip: String, process_id: u64 },
    QuarantineFile { host_ip: String, file_path: String },
    NotifyTeam { message: String, team: String },
    CreateTicket { title: String, description: String, priority: String },
    RunScript { script_path: String, arguments: Vec<String> },
    ApiCall { url: String, method: String, headers: HashMap<String, String>, body: String },
    WaitForApproval { approvers: Vec<String>, timeout_seconds: u64 },
    CollectEvidence { evidence_type: String, source: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepCondition {
    FieldEquals { field: String, value: String },
    FieldContains { field: String, value: String },
    ThresholdExceeded { field: String, threshold: f64 },
    TimeElapsed { seconds: u64 },
    ManualApproval { approvers: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookVariable {
    pub name: String,
    pub description: String,
    pub variable_type: VariableType,
    pub default_value: Option<serde_json::Value>,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VariableType {
    String,
    Number,
    Boolean,
    Array,
    Object,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookExecution {
    pub id: String,
    pub playbook_id: String,
    pub incident_id: String,
    pub status: ExecutionStatus,
    pub current_step_id: Option<String>,
    pub completed_steps: Vec<String>,
    pub variables: HashMap<String, serde_json::Value>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub error_message: Option<String>,
    pub execution_log: Vec<ExecutionLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub step_id: String,
    pub level: LogLevel,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
    Debug,
}

impl PlaybookManager {
    pub fn new() -> Self {
        Self {
            playbooks: Arc::new(RwLock::new(HashMap::new())),
            execution_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn initialize(&self) -> AppResult<()> {
        // Load default playbooks
        self.load_default_playbooks().await?;
        
        Ok(())
    }

    async fn load_default_playbooks(&self) -> AppResult<()> {
        let mut playbooks = self.playbooks.write().await;
        
        // Malware Response Playbook
        playbooks.insert("malware_response".to_string(), Playbook {
            id: "malware_response".to_string(),
            name: "Malware Response Playbook".to_string(),
            description: "Automated response playbook for malware incidents".to_string(),
            version: "1.0".to_string(),
            incident_types: vec!["malware".to_string()],
            severity_levels: vec!["high".to_string(), "critical".to_string()],
            steps: vec![
                PlaybookStep {
                    id: "isolate_host".to_string(),
                    name: "Isolate Infected Host".to_string(),
                    description: "Isolate the infected host from the network".to_string(),
                    step_type: StepType::Automated,
                    action: PlaybookAction::IsolateHost { host_ip: "${host_ip}".to_string() },
                    conditions: vec![],
                    on_success: Some(vec!["collect_evidence".to_string()]),
                    on_failure: Some(vec!["notify_failure".to_string()]),
                    timeout_seconds: 300,
                    retry_count: 3,
                    retry_delay_seconds: 30,
                },
                PlaybookStep {
                    id: "collect_evidence".to_string(),
                    name: "Collect Evidence".to_string(),
                    description: "Collect forensic evidence from the infected host".to_string(),
                    step_type: StepType::Automated,
                    action: PlaybookAction::CollectEvidence {
                        evidence_type: "memory_dump".to_string(),
                        source: "${host_ip}".to_string(),
                    },
                    conditions: vec![],
                    on_success: Some(vec!["quarantine_files".to_string()]),
                    on_failure: Some(vec!["notify_failure".to_string()]),
                    timeout_seconds: 600,
                    retry_count: 2,
                    retry_delay_seconds: 60,
                },
                PlaybookStep {
                    id: "quarantine_files".to_string(),
                    name: "Quarantine Suspicious Files".to_string(),
                    description: "Quarantine suspicious files on the infected host".to_string(),
                    step_type: StepType::Automated,
                    action: PlaybookAction::QuarantineFile {
                        host_ip: "${host_ip}".to_string(),
                        file_path: "${file_path}".to_string(),
                    },
                    conditions: vec![],
                    on_success: Some(vec!["notify_team".to_string()]),
                    on_failure: Some(vec!["notify_failure".to_string()]),
                    timeout_seconds: 300,
                    retry_count: 3,
                    retry_delay_seconds: 30,
                },
                PlaybookStep {
                    id: "notify_team".to_string(),
                    name: "Notify Security Team".to_string(),
                    description: "Notify the security team about the malware incident".to_string(),
                    step_type: StepType::Automated,
                    action: PlaybookAction::NotifyTeam {
                        message: "Malware incident detected on ${host_ip}. Host isolated and evidence collected.".to_string(),
                        team: "security".to_string(),
                    },
                    conditions: vec![],
                    on_success: Some(vec!["create_ticket".to_string()]),
                    on_failure: Some(vec!["notify_failure".to_string()]),
                    timeout_seconds: 60,
                    retry_count: 1,
                    retry_delay_seconds: 0,
                },
                PlaybookStep {
                    id: "create_ticket".to_string(),
                    name: "Create Incident Ticket".to_string(),
                    description: "Create a ticket in the incident tracking system".to_string(),
                    step_type: StepType::Automated,
                    action: PlaybookAction::CreateTicket {
                        title: "Malware Incident - ${host_ip}".to_string(),
                        description: "Malware detected on host ${host_ip}. Actions taken: isolation, evidence collection, quarantine.".to_string(),
                        priority: "high".to_string(),
                    },
                    conditions: vec![],
                    on_success: None,
                    on_failure: Some(vec!["notify_failure".to_string()]),
                    timeout_seconds: 120,
                    retry_count: 2,
                    retry_delay_seconds: 30,
                },
                PlaybookStep {
                    id: "notify_failure".to_string(),
                    name: "Notify Failure".to_string(),
                    description: "Notify team about playbook execution failure".to_string(),
                    step_type: StepType::Automated,
                    action: PlaybookAction::NotifyTeam {
                        message: "Playbook execution failed for incident ${incident_id}. Manual intervention required.".to_string(),
                        team: "security".to_string(),
                    },
                    conditions: vec![],
                    on_success: None,
                    on_failure: None,
                    timeout_seconds: 60,
                    retry_count: 1,
                    retry_delay_seconds: 0,
                },
            ],
            variables: HashMap::from([
                ("host_ip".to_string(), PlaybookVariable {
                    name: "host_ip".to_string(),
                    description: "IP address of the infected host".to_string(),
                    variable_type: VariableType::String,
                    default_value: None,
                    required: true,
                }),
                ("file_path".to_string(), PlaybookVariable {
                    name: "file_path".to_string(),
                    description: "Path to the suspicious file".to_string(),
                    variable_type: VariableType::String,
                    default_value: None,
                    required: true,
                }),
                ("incident_id".to_string(), PlaybookVariable {
                    name: "incident_id".to_string(),
                    description: "ID of the incident".to_string(),
                    variable_type: VariableType::String,
                    default_value: None,
                    required: true,
                }),
            ]),
            timeout_seconds: 3600,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
        
        // Phishing Response Playbook
        playbooks.insert("phishing_response".to_string(), Playbook {
            id: "phishing_response".to_string(),
            name: "Phishing Response Playbook".to_string(),
            description: "Automated response playbook for phishing incidents".to_string(),
            version: "1.0".to_string(),
            incident_types: vec!["phishing".to_string()],
            severity_levels: vec!["medium".to_string(), "high".to_string()],
            steps: vec![
                PlaybookStep {
                    id: "block_url".to_string(),
                    name: "Block Phishing URL".to_string(),
                    description: "Block the phishing URL at the network level".to_string(),
                    step_type: StepType::Automated,
                    action: PlaybookAction::BlockIp { ip_address: "${url}".to_string() },
                    conditions: vec![],
                    on_success: Some(vec!["notify_users".to_string()]),
                    on_failure: Some(vec!["notify_failure".to_string()]),
                    timeout_seconds: 120,
                    retry_count: 3,
                    retry_delay_seconds: 30,
                },
                PlaybookStep {
                    id: "notify_users".to_string(),
                    name: "Notify Affected Users".to_string(),
                    description: "Notify users who may have accessed the phishing URL".to_string(),
                    step_type: StepType::Automated,
                    action: PlaybookAction::NotifyTeam {
                        message: "Phishing URL detected: ${url}. Users who clicked the link should change their passwords immediately.".to_string(),
                        team: "helpdesk".to_string(),
                    },
                    conditions: vec![],
                    on_success: Some(vec!["collect_evidence".to_string()]),
                    on_failure: Some(vec!["notify_failure".to_string()]),
                    timeout_seconds: 60,
                    retry_count: 1,
                    retry_delay_seconds: 0,
                },
                PlaybookStep {
                    id: "collect_evidence".to_string(),
                    name: "Collect Evidence".to_string(),
                    description: "Collect evidence related to the phishing incident".to_string(),
                    step_type: StepType::Automated,
                    action: PlaybookAction::CollectEvidence {
                        evidence_type: "email_headers".to_string(),
                        source: "${email_id}".to_string(),
                    },
                    conditions: vec![],
                    on_success: Some(vec!["create_ticket".to_string()]),
                    on_failure: Some(vec!["notify_failure".to_string()]),
                    timeout_seconds: 300,
                    retry_count: 2,
                    retry_delay_seconds: 60,
                },
                PlaybookStep {
                    id: "create_ticket".to_string(),
                    name: "Create Incident Ticket".to_string(),
                    description: "Create a ticket for the phishing incident".to_string(),
                    step_type: StepType::Automated,
                    action: PlaybookAction::CreateTicket {
                        title: "Phishing Incident - ${url}".to_string(),
                        description: "Phishing URL detected: ${url}. Actions taken: URL blocked, users notified.".to_string(),
                        priority: "medium".to_string(),
                    },
                    conditions: vec![],
                    on_success: None,
                    on_failure: Some(vec!["notify_failure".to_string()]),
                    timeout_seconds: 120,
                    retry_count: 2,
                    retry_delay_seconds: 30,
                },
                PlaybookStep {
                    id: "notify_failure".to_string(),
                    name: "Notify Failure".to_string(),
                    description: "Notify team about playbook execution failure".to_string(),
                    step_type: StepType::Automated,
                    action: PlaybookAction::NotifyTeam {
                        message: "Playbook execution failed for phishing incident ${incident_id}. Manual intervention required.".to_string(),
                        team: "security".to_string(),
                    },
                    conditions: vec![],
                    on_success: None,
                    on_failure: None,
                    timeout_seconds: 60,
                    retry_count: 1,
                    retry_delay_seconds: 0,
                },
            ],
            variables: HashMap::from([
                ("url".to_string(), PlaybookVariable {
                    name: "url".to_string(),
                    description: "Phishing URL".to_string(),
                    variable_type: VariableType::String,
                    default_value: None,
                    required: true,
                }),
                ("email_id".to_string(), PlaybookVariable {
                    name: "email_id".to_string(),
                    description: "ID of the phishing email".to_string(),
                    variable_type: VariableType::String,
                    default_value: None,
                    required: true,
                }),
                ("incident_id".to_string(), PlaybookVariable {
                    name: "incident_id".to_string(),
                    description: "ID of the incident".to_string(),
                    variable_type: VariableType::String,
                    default_value: None,
                    required: true,
                }),
            ]),
            timeout_seconds: 1800,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        });
        
        Ok(())
    }

    pub async fn execute_playbook(
        &self,
        playbook_id: &str,
        incident_id: &str,
        variables: HashMap<String, serde_json::Value>,
    ) -> AppResult<String> {
        let playbooks = self.playbooks.read().await;
        let playbook = playbooks.get(playbook_id)
            .ok_or_else(|| crate::error::AppError::NotFound(format!("Playbook not found: {}", playbook_id)))?;
        
        // Validate variables
        self.validate_variables(playbook, &variables)?;
        
        // Create execution record
        let execution_id = Uuid::new_v4().to_string();
        let execution = PlaybookExecution {
            id: execution_id.clone(),
            playbook_id: playbook_id.to_string(),
            incident_id: incident_id.to_string(),
            status: ExecutionStatus::Pending,
            current_step_id: None,
            completed_steps: Vec::new(),
            variables: variables.clone(),
            started_at: chrono::Utc::now(),
            completed_at: None,
            error_message: None,
            execution_log: Vec::new(),
        };
        
        // Store execution record
        {
            let mut history = self.execution_history.write().await;
            history.insert(execution_id.clone(), execution);
        }
        
        // Start playbook execution in background
        let playbook_clone = playbook.clone();
        let execution_id_clone = execution_id.clone();
        let history_clone = self.execution_history.clone();
        
        tokio::spawn(async move {
            if let Err(e) = Self::execute_playbook_steps(
                playbook_clone,
                execution_id_clone,
                variables,
                history_clone,
            ).await {
                eprintln!("Playbook execution failed: {}", e);
            }
        });
        
        Ok(execution_id)
    }

    async fn execute_playbook_steps(
        playbook: Playbook,
        execution_id: String,
        variables: HashMap<String, serde_json::Value>,
        history: Arc<RwLock<HashMap<String, PlaybookExecution>>>,
    ) -> AppResult<()> {
        // Update execution status to running
        {
            let mut executions = history.write().await;
            if let Some(execution) = executions.get_mut(&execution_id) {
                execution.status = ExecutionStatus::Running;
            }
        }
        
        // Find the first step
        let mut current_step_id = if let Some(first_step) = playbook.steps.first() {
            first_step.id.clone()
        } else {
            return Err(crate::error::AppError::Validation("Playbook has no steps".to_string()));
        };
        
        // Execute steps until completion or failure
        loop {
            // Find the current step
            let current_step = playbook.steps.iter()
                .find(|step| step.id == current_step_id)
                .ok_or_else(|| crate::error::AppError::NotFound(format!("Step not found: {}", current_step_id)))?;
            
            // Update current step in execution
            {
                let mut executions = history.write().await;
                if let Some(execution) = executions.get_mut(&execution_id) {
                    execution.current_step_id = Some(current_step_id.clone());
                }
            }
            
            // Log step start
            Self::log_execution(
                &history,
                &execution_id,
                &current_step_id,
                LogLevel::Info,
                format!("Executing step: {}", current_step.name),
                None,
            ).await?;
            
            // Check step conditions
            if !Self::evaluate_step_conditions(&current_step.conditions, &variables)? {
                Self::log_execution(
                    &history,
                    &execution_id,
                    &current_step_id,
                    LogLevel::Warning,
                    "Step conditions not met, skipping step".to_string(),
                    None,
                ).await?;
                
                // Find next step based on on_failure
                if let Some(ref failure_steps) = current_step.on_failure {
                    if let Some(next_step_id) = failure_steps.first() {
                        current_step_id = next_step_id.clone();
                        continue;
                    }
                }
                
                // No next step, end execution
                break;
            }
            
            // Execute the step
            let step_result = Self::execute_step(&current_step, &variables).await;
            
            match step_result {
                Ok(_) => {
                    // Step succeeded
                    Self::log_execution(
                        &history,
                        &execution_id,
                        &current_step_id,
                        LogLevel::Info,
                        "Step completed successfully".to_string(),
                        None,
                    ).await?;
                    
                    // Add to completed steps
                    {
                        let mut executions = history.write().await;
                        if let Some(execution) = executions.get_mut(&execution_id) {
                            execution.completed_steps.push(current_step_id.clone());
                        }
                    }
                    
                    // Find next step based on on_success
                    if let Some(ref success_steps) = current_step.on_success {
                        if let Some(next_step_id) = success_steps.first() {
                            current_step_id = next_step_id.clone();
                            continue;
                        }
                    }
                    
                    // No next step, end execution
                    break;
                },
                Err(e) => {
                    // Step failed
                    Self::log_execution(
                        &history,
                        &execution_id,
                        &current_step_id,
                        LogLevel::Error,
                        format!("Step failed: {}", e),
                        None,
                    ).await?;
                    
                    // Find next step based on on_failure
                    if let Some(ref failure_steps) = current_step.on_failure {
                        if let Some(next_step_id) = failure_steps.first() {
                            current_step_id = next_step_id.clone();
                            continue;
                        }
                    }
                    
                    // No next step, end execution with failure
                    {
                        let mut executions = history.write().await;
                        if let Some(execution) = executions.get_mut(&execution_id) {
                            execution.status = ExecutionStatus::Failed;
                            execution.error_message = Some(format!("Step {} failed: {}", current_step_id, e));
                            execution.completed_at = Some(chrono::Utc::now());
                        }
                    }
                    return Err(e);
                },
            }
        }
        
        // Execution completed successfully
        {
            let mut executions = history.write().await;
            if let Some(execution) = executions.get_mut(&execution_id) {
                execution.status = ExecutionStatus::Completed;
                execution.completed_at = Some(chrono::Utc::now());
            }
        }
        
        Self::log_execution(
            &history,
            &execution_id,
            &"completion".to_string(),
            LogLevel::Info,
            "Playbook execution completed successfully".to_string(),
            None,
        ).await?;
        
        Ok(())
    }

    async fn execute_step(
        step: &PlaybookStep,
        variables: &HashMap<String, serde_json::Value>,
    ) -> AppResult<()> {
        // Substitute variables in action
        let action = Self::substitute_variables(&step.action, variables)?;
        
        match action {
            PlaybookAction::IsolateHost { host_ip } => {
                println!("Isolating host: {}", host_ip);
                // Execute host isolation
                // In a real implementation, this would call the actual isolation function
            },
            PlaybookAction::BlockIp { ip_address } => {
                println!("Blocking IP: {}", ip_address);
                // Execute IP blocking
            },
            PlaybookAction::KillProcess { host_ip, process_id } => {
                println!("Killing process {} on host {}", process_id, host_ip);
                // Execute process termination
            },
            PlaybookAction::QuarantineFile { host_ip, file_path } => {
                println!("Quarantining file {} on host {}", file_path, host_ip);
                // Execute file quarantine
            },
            PlaybookAction::NotifyTeam { message, team } => {
                println!("Notifying team {}: {}", team, message);
                // Execute team notification
            },
            PlaybookAction::CreateTicket { title, description, priority } => {
                println!("Creating ticket: {} (Priority: {})", title, priority);
                println!("Description: {}", description);
                // Execute ticket creation
            },
            PlaybookAction::RunScript { script_path, arguments } => {
                println!("Running script: {} with arguments: {:?}", script_path, arguments);
                // Execute script
            },
            PlaybookAction::ApiCall { url, method, headers, body } => {
                println!("Making API call: {} {}", method, url);
                println!("Headers: {:?}", headers);
                println!("Body: {}", body);
                // Execute API call
            },
            PlaybookAction::WaitForApproval { approvers, timeout_seconds } => {
                println!("Waiting for approval from: {:?}", approvers);
                println!("Timeout: {} seconds", timeout_seconds);
                // Execute approval wait
            },
            PlaybookAction::CollectEvidence { evidence_type, source } => {
                println!("Collecting {} evidence from: {}", evidence_type, source);
                // Execute evidence collection
            },
        }
        
        Ok(())
    }

    fn substitute_variables(
        action: &PlaybookAction,
        variables: &HashMap<String, serde_json::Value>,
    ) -> AppResult<PlaybookAction> {
        // Helper function to substitute variables in strings
        let substitute_string = |s: &str| -> String {
            let mut result = s.to_string();
            for (key, value) in variables {
                let placeholder = format!("${{{}}}", key);
                if let Some(value_str) = value.as_str() {
                    result = result.replace(&placeholder, value_str);
                } else if let Some(value_num) = value.as_u64() {
                    result = result.replace(&placeholder, &value_num.to_string());
                } else if let Some(value_bool) = value.as_bool() {
                    result = result.replace(&placeholder, &value_bool.to_string());
                }
            }
            result
        };
        
        match action {
            PlaybookAction::IsolateHost { host_ip } => {
                Ok(PlaybookAction::IsolateHost {
                    host_ip: substitute_string(host_ip),
                })
            },
            PlaybookAction::BlockIp { ip_address } => {
                Ok(PlaybookAction::BlockIp {
                    ip_address: substitute_string(ip_address),
                })
            },
            PlaybookAction::KillProcess { host_ip, process_id } => {
                Ok(PlaybookAction::KillProcess {
                    host_ip: substitute_string(host_ip),
                    process_id: process_id,
                })
            },
            PlaybookAction::QuarantineFile { host_ip, file_path } => {
                Ok(PlaybookAction::QuarantineFile {
                    host_ip: substitute_string(host_ip),
                    file_path: substitute_string(file_path),
                })
            },
            PlaybookAction::NotifyTeam { message, team } => {
                Ok(PlaybookAction::NotifyTeam {
                    message: substitute_string(message),
                    team: substitute_string(team),
                })
            },
            PlaybookAction::CreateTicket { title, description, priority } => {
                Ok(PlaybookAction::CreateTicket {
                    title: substitute_string(title),
                    description: substitute_string(description),
                    priority: substitute_string(priority),
                })
            },
            PlaybookAction::RunScript { script_path, arguments } => {
                let substituted_args = arguments.iter()
                    .map(|arg| substitute_string(arg))
                    .collect();
                Ok(PlaybookAction::RunScript {
                    script_path: substitute_string(script_path),
                    arguments: substituted_args,
                })
            },
            PlaybookAction::ApiCall { url, method, headers, body } => {
                let substituted_headers = headers.iter()
                    .map(|(k, v)| (substitute_string(k), substitute_string(v)))
                    .collect();
                Ok(PlaybookAction::ApiCall {
                    url: substitute_string(url),
                    method: substitute_string(method),
                    headers: substituted_headers,
                    body: substitute_string(body),
                })
            },
            PlaybookAction::WaitForApproval { approvers, timeout_seconds } => {
                let substituted_approvers = approvers.iter()
                    .map(|approver| substitute_string(approver))
                    .collect();
                Ok(PlaybookAction::WaitForApproval {
                    approvers: substituted_approvers,
                    timeout_seconds: *timeout_seconds,
                })
            },
            PlaybookAction::CollectEvidence { evidence_type, source } => {
                Ok(PlaybookAction::CollectEvidence {
                    evidence_type: substitute_string(evidence_type),
                    source: substitute_string(source),
                })
            },
        }
    }

    fn evaluate_step_conditions(
        conditions: &[StepCondition],
        variables: &HashMap<String, serde_json::Value>,
    ) -> AppResult<bool> {
        for condition in conditions {
            match condition {
                StepCondition::FieldEquals { field, value } => {
                    if let Some(var_value) = variables.get(field) {
                        if let Some(var_str) = var_value.as_str() {
                            if var_str != value {
                                return Ok(false);
                            }
                        } else {
                            return Ok(false);
                        }
                    } else {
                        return Ok(false);
                    }
                },
                StepCondition::FieldContains { field, value } => {
                    if let Some(var_value) = variables.get(field) {
                        if let Some(var_str) = var_value.as_str() {
                            if !var_str.contains(value) {
                                return Ok(false);
                            }
                        } else {
                            return Ok(false);
                        }
                    } else {
                        return Ok(false);
                    }
                },
                StepCondition::ThresholdExceeded { field, threshold } => {
                    if let Some(var_value) = variables.get(field) {
                        if let Some(var_num) = var_value.as_f64() {
                            if var_num <= *threshold {
                                return Ok(false);
                            }
                        } else {
                            return Ok(false);
                        }
                    } else {
                        return Ok(false);
                    }
                },
                StepCondition::TimeElapsed { seconds } => {
                    // This would require tracking time in the execution context
                    // For now, we'll assume the condition is met
                },
                StepCondition::ManualApproval { approvers } => {
                    // This would require checking for manual approval
                    // For now, we'll assume the condition is not met
                    return Ok(false);
                },
            }
        }
        
        Ok(true)
    }

    fn validate_variables(
        playbook: &Playbook,
        variables: &HashMap<String, serde_json::Value>,
    ) -> AppResult<()> {
        for (var_name, variable) in &playbook.variables {
            if variable.required && !variables.contains_key(var_name) {
                return Err(crate::error::AppError::Validation(
                    format!("Required variable not provided: {}", var_name)
                ));
            }
            
            if let Some(value) = variables.get(var_name) {
                // Check variable type
                match variable.variable_type {
                    VariableType::String => {
                        if !value.is_string() {
                            return Err(crate::error::AppError::Validation(
                                format!("Variable {} must be a string", var_name)
                            ));
                        }
                    },
                    VariableType::Number => {
                        if !value.is_number() {
                            return Err(crate::error::AppError::Validation(
                                format!("Variable {} must be a number", var_name)
                            ));
                        }
                    },
                    VariableType::Boolean => {
                        if !value.is_boolean() {
                            return Err(crate::error::AppError::Validation(
                                format!("Variable {} must be a boolean", var_name)
                            ));
                        }
                    },
                    VariableType::Array => {
                        if !value.is_array() {
                            return Err(crate::error::AppError::Validation(
                                format!("Variable {} must be an array", var_name)
                            ));
                        }
                    },
                    VariableType::Object => {
                        if !value.is_object() {
                            return Err(crate::error::AppError::Validation(
                                format!("Variable {} must be an object", var_name)
                            ));
                        }
                    },
                }
            }
        }
        
        Ok(())
    }

    async fn log_execution(
        history: &Arc<RwLock<HashMap<String, PlaybookExecution>>>,
        execution_id: &str,
        step_id: &str,
        level: LogLevel,
        message: String,
        details: Option<serde_json::Value>,
    ) -> AppResult<()> {
        let log_entry = ExecutionLogEntry {
            timestamp: chrono::Utc::now(),
            step_id: step_id.to_string(),
            level,
            message,
            details,
        };
        
        let mut executions = history.write().await;
        if let Some(execution) = executions.get_mut(execution_id) {
            execution.execution_log.push(log_entry);
        }
        
        Ok(())
    }

    pub async fn get_execution_status(&self, execution_id: &str) -> AppResult<Option<PlaybookExecution>> {
        let history = self.execution_history.read().await;
        Ok(history.get(execution_id).cloned())
    }

    pub async fn cancel_execution(&self, execution_id: &str) -> AppResult<()> {
        let mut history = self.execution_history.write().await;
        if let Some(execution) = history.get_mut(execution_id) {
            if execution.status == ExecutionStatus::Running {
                execution.status = ExecutionStatus::Cancelled;
                execution.completed_at = Some(chrono::Utc::now());
                
                Self::log_execution(
                    &self.execution_history,
                    execution_id,
                    &"cancellation".to_string(),
                    LogLevel::Info,
                    "Playbook execution cancelled".to_string(),
                    None,
                ).await?;
                
                Ok(())
            } else {
                Err(crate::error::AppError::Validation(
                    format!("Cannot cancel execution with status: {:?}", execution.status)
                ))
            }
        } else {
            Err(crate::error::AppError::NotFound(
                format!("Execution not found: {}", execution_id)
            ))
        }
    }

    pub async fn get_playbook_executions(&self, incident_id: &str) -> AppResult<Vec<PlaybookExecution>> {
        let history = self.execution_history.read().await;
        let executions: Vec<PlaybookExecution> = history.values()
            .filter(|exec| exec.incident_id == incident_id)
            .cloned()
            .collect();
        
        Ok(executions)
    }

    pub async fn get_available_playbooks(&self) -> AppResult<Vec<Playbook>> {
        let playbooks = self.playbooks.read().await;
        Ok(playbooks.values().cloned().collect())
    }
}