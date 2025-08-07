use super::*;
use crate::collectors::DataEvent;
use crate::error::AppResult;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct SignatureRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub conditions: Vec<RuleCondition>,
    pub severity: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum RuleCondition {
    FieldEquals { field: String, value: String },
    FieldContains { field: String, value: String },
    FieldMatches { field: String, pattern: String },
    NumericComparison { field: String, operator: String, value: f64 },
    LogicalAnd { conditions: Vec<RuleCondition> },
    LogicalOr { conditions: Vec<RuleCondition> },
}

pub struct SignatureEngine {
    rules: Vec<SignatureRule>,
    rule_cache: HashMap<String, bool>,
}

impl SignatureEngine {
    pub fn new() -> Self {
        Self {
            rules: Self::load_default_rules(),
            rule_cache: HashMap::new(),
        }
    }

    fn load_default_rules() -> Vec<SignatureRule> {
        vec![
            SignatureRule {
                id: "rule_001".to_string(),
                name: "Suspicious PowerShell Execution".to_string(),
                description: "Detects suspicious PowerShell execution patterns".to_string(),
                conditions: vec![
                    RuleCondition::FieldEquals {
                        field: "event_type".to_string(),
                        value: "process".to_string(),
                    },
                    RuleCondition::FieldContains {
                        field: "process_name".to_string(),
                        value: "powershell.exe".to_string(),
                    },
                    RuleCondition::LogicalOr {
                        conditions: vec![
                            RuleCondition::FieldContains {
                                field: "command_line".to_string(),
                                value: "-enc".to_string(),
                            },
                            RuleCondition::FieldContains {
                                field: "command_line".to_string(),
                                value: "bypass".to_string(),
                            },
                            RuleCondition::FieldContains {
                                field: "command_line".to_string(),
                                value: "hidden".to_string(),
                            },
                        ],
                    },
                ],
                severity: "high".to_string(),
                tags: vec!["malware".to_string(), "execution".to_string()],
            },
            SignatureRule {
                id: "rule_002".to_string(),
                name: "Port Scanning Activity".to_string(),
                description: "Detects potential port scanning behavior".to_string(),
                conditions: vec![
                    RuleCondition::FieldEquals {
                        field: "event_type".to_string(),
                        value: "network".to_string(),
                    },
                    RuleCondition::NumericComparison {
                        field: "unique_dst_ports".to_string(),
                        operator: "greater_than".to_string(),
                        value: 50.0,
                    },
                ],
                severity: "medium".to_string(),
                tags: vec!["reconnaissance".to_string(), "network".to_string()],
            },
        ]
    }

    pub async fn evaluate_event(&self, event: &DataEvent) -> AppResult<Vec<DetectionResult>> {
        let mut results = Vec::new();
        
        for rule in &self.rules {
            if self.evaluate_rule(rule, event).await? {
                results.push(DetectionResult {
                    id: uuid::Uuid::new_v4().to_string(),
                    detection_type: "signature".to_string(),
                    confidence: 0.95,
                    severity: rule.severity.clone(),
                    description: rule.description.clone(),
                    metadata: HashMap::from([
                        ("rule_id".to_string(), rule.id.clone()),
                        ("rule_name".to_string(), rule.name.clone()),
                        ("tags".to_string(), rule.tags.join(",")),
                    ]),
                    timestamp: chrono::Utc::now(),
                });
            }
        }
        
        Ok(results)
    }

    async fn evaluate_rule(&self, rule: &SignatureRule, event: &DataEvent) -> AppResult<bool> {
        let cache_key = format!("{}:{}", rule.id, event.event_id);
        
        if let Some(&cached_result) = self.rule_cache.get(&cache_key) {
            return Ok(cached_result);
        }
        
        let result = self.evaluate_conditions(&rule.conditions, event).await?;
        self.rule_cache.insert(cache_key, result);
        
        Ok(result)
    }

    async fn evaluate_conditions(&self, conditions: &[RuleCondition], event: &DataEvent) -> AppResult<bool> {
        for condition in conditions {
            if !self.evaluate_condition(condition, event).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn evaluate_condition(&self, condition: &RuleCondition, event: &DataEvent) -> AppResult<bool> {
        match condition {
            RuleCondition::FieldEquals { field, value } => {
                Ok(self.get_field_value(event, field) == *value)
            }
            RuleCondition::FieldContains { field, value } => {
                Ok(self.get_field_value(event, field).contains(value))
            }
            RuleCondition::FieldMatches { field, pattern } => {
                let re = regex::Regex::new(pattern)?;
                Ok(re.is_match(&self.get_field_value(event, field)))
            }
            RuleCondition::NumericComparison { field, operator, value } => {
                let field_value = self.get_numeric_field_value(event, field)?;
                match operator.as_str() {
                    "greater_than" => Ok(field_value > *value),
                    "less_than" => Ok(field_value < *value),
                    "equal" => Ok((field_value - *value).abs() < f64::EPSILON),
                    _ => Ok(false),
                }
            }
            RuleCondition::LogicalAnd { conditions } => {
                self.evaluate_conditions(conditions, event).await
            }
            RuleCondition::LogicalOr { conditions } => {
                for condition in conditions {
                    if self.evaluate_condition(condition, event).await? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    fn get_field_value(&self, event: &DataEvent, field: &str) -> String {
        match field {
            "event_type" => event.event_type.clone(),
            "source" => event.source.clone(),
            _ => {
                // Extract from event data
                match &event.data {
                    EventData::Process { process_name, command_line, user, .. } => {
                        match field {
                            "process_name" => process_name.clone(),
                            "command_line" => command_line.clone(),
                            "user" => user.clone(),
                            _ => String::new(),
                        }
                    }
                    EventData::Network { src_ip, dst_ip, protocol, .. } => {
                        match field {
                            "src_ip" => src_ip.clone(),
                            "dst_ip" => dst_ip.clone(),
                            "protocol" => protocol.clone(),
                            _ => String::new(),
                        }
                    }
                    EventData::System { host, .. } => {
                        match field {
                            "host" => host.clone(),
                            _ => String::new(),
                        }
                    }
                    EventData::File { path, operation, .. } => {
                        match field {
                            "path" => path.clone(),
                            "operation" => operation.clone(),
                            _ => String::new(),
                        }
                    }
                }
            }
        }
    }

    fn get_numeric_field_value(&self, event: &DataEvent, field: &str) -> AppResult<f64> {
        match field {
            "unique_dst_ports" => {
                // This would require context from multiple events
                // For now, return a placeholder
                Ok(0.0)
            }
            _ => {
                // Try to parse as float
                let value = self.get_field_value(event, field);
                value.parse().map_err(|_| crate::error::AppError::Detection(
                    crate::error::DetectionError::FeatureExtraction(
                        format!("Cannot parse field '{}' as numeric: {}", field, value)
                    )
                ))
            }
        }
    }
}