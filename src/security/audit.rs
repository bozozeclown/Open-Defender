// src/security/audit.rs
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::error::{SecurityMonitoringError, Result};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub user_id: Option<String>,
    pub action: String,
    pub resource: String,
    pub result: String,
    pub details: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AuditEventType {
    Authentication,
    Authorization,
    DataAccess,
    ConfigurationChange,
    SecurityEvent,
}

pub struct AuditLogger {
    log_file: String,
    enabled: bool,
    sensitive_data_masking: bool,
}

impl AuditLogger {
    pub fn new(log_file: &str, enabled: bool, sensitive_data_masking: bool) -> Self {
        Self {
            log_file: log_file.to_string(),
            enabled,
            sensitive_data_masking,
        }
    }

    pub async fn log_event(&self, event: AuditEvent) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let mut event = event;
        
        // Mask sensitive data if enabled
        if self.sensitive_data_masking {
            if let Some(ref mut details) = event.details {
                *details = mask_sensitive_data(details);
            }
        }

        let log_entry = serde_json::to_string(&event)?;
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)?;
        
        file.write_all(log_entry.as_bytes())?;
        file.write_all(b"\n")?;
        
        Ok(())
    }

    pub async fn query_events(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>> {
        let file = std::fs::File::open(&self.log_file)?;
        let reader = std::io::BufReader::new(file);
        
        let mut events = Vec::new();
        
        for line in reader.lines() {
            let line = line?;
            let event: AuditEvent = serde_json::from_str(&line)?;
            
            if filter.matches(&event) {
                events.push(event);
            }
        }
        
        Ok(events)
    }
}

#[derive(Debug)]
pub struct AuditFilter {
    pub user_id: Option<String>,
    pub action: Option<String>,
    pub resource: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub result: Option<String>,
}

impl AuditFilter {
    pub fn matches(&self, event: &AuditEvent) -> bool {
        if let Some(ref user_id) = self.user_id {
            if event.user_id.as_ref() != Some(user_id) {
                return false;
            }
        }
        
        if let Some(ref action) = self.action {
            if !event.action.contains(action) {
                return false;
            }
        }
        
        if let Some(ref resource) = self.resource {
            if !event.resource.contains(resource) {
                return false;
            }
        }
        
        if let Some(start) = self.start_time {
            if event.timestamp < start {
                return false;
            }
        }
        
        if let Some(end) = self.end_time {
            if event.timestamp > end {
                return false;
            }
        }
        
        if let Some(ref result) = self.result {
            if event.result != *result {
                return false;
            }
        }
        
        true
    }
}

fn mask_sensitive_data(data: &str) -> String {
    let sensitive_patterns = vec![
        ("password", "********"),
        ("token", "********"),
        ("secret", "********"),
        ("key", "********"),
        ("credit_card", r"\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"),
        ("ssn", r"\d{3}[\s-]?\d{2}[\s-]?\d{4}"),
    ];
    
    let mut masked_data = data.to_string();
    
    for (pattern, replacement) in sensitive_patterns {
        if pattern.contains("credit_card") || pattern.contains("ssn") {
            let regex = regex::Regex::new(pattern).unwrap();
            masked_data = regex.replace_all(&masked_data, replacement).to_string();
        } else {
            masked_data = masked_data.replace(pattern, replacement);
        }
    }
    
    masked_data
}

pub async fn log_audit_event(event: AuditEvent) -> Result<()> {
    // This would typically use a shared instance of AuditLogger
    // For now, we'll create a new one for demonstration
    let logger = AuditLogger::new(
        "logs/security_audit.log",
        true,
        true,
    );
    
    logger.log_event(event).await
}
