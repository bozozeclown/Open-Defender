// src/integrations/mod.rs
use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::collectors::DataEvent;
use crate::config::{EmailConfig, WebhookConfig};
use crate::response::incident_response::Incident;

pub struct IntegrationManager {
    email_config: EmailConfig,
    webhook_config: WebhookConfig,
    slack_config: Option<SlackConfig>,
    teams_config: Option<TeamsConfig>,
    pagerduty_config: Option<PagerDutyConfig>,
    jira_config: Option<JiraConfig>,
    client: Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    pub webhook_url: String,
    pub channel: String,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamsConfig {
    pub webhook_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerDutyConfig {
    pub api_key: String,
    pub service_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraConfig {
    pub url: String,
    pub username: String,
    pub api_token: String,
    pub project_key: String,
}

impl IntegrationManager {
    pub fn new(
        email_config: EmailConfig,
        webhook_config: WebhookConfig,
        slack_config: Option<SlackConfig>,
        teams_config: Option<TeamsConfig>,
        pagerduty_config: Option<PagerDutyConfig>,
        jira_config: Option<JiraConfig>,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            email_config,
            webhook_config,
            slack_config,
            teams_config,
            pagerduty_config,
            jira_config,
            client,
        })
    }

    pub async fn send_email_notification(&self, to: &str, subject: &str, body: &str) -> Result<()> {
        if !self.email_config.enabled {
            return Ok(());
        }

        // Create email message
        let email = lettre::Message::builder()
            .from(self.email_config.sender_email.parse()?)
            .to(to.parse()?)
            .subject(subject)
            .body(body.to_string())?;

        // Send email
        let mailer = lettre::SmtpTransport::relay(&self.email_config.smtp_server)?
            .credentials(lettre::transport::smtp::authentication::Credentials::new(
                self.email_config.sender_email.clone(),
                self.email_config.sender_password.clone(),
            ))
            .port(self.email_config.smtp_port)
            .build();

        mailer.send(&email).await
            .context("Failed to send email")?;

        info!("Email notification sent to {}: {}", to, subject);
        Ok(())
    }

    pub async fn send_webhook_notification(&self, payload: serde_json::Value) -> Result<()> {
        if !self.webhook_config.enabled {
            return Ok(());
        }

        let response = self.client
            .post(&self.webhook_config.url)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Webhook request failed: {}", response.status()));
        }

        info!("Webhook notification sent to {}", self.webhook_config.url);
        Ok(())
    }

    pub async fn send_slack_notification(&self, message: &str, severity: &str) -> Result<()> {
        if let Some(ref config) = self.slack_config {
            let color = match severity {
                "critical" => "#ff0000",
                "high" => "#ff6600",
                "medium" => "#ffaa00",
                "low" => "#00aa00",
                _ => "#888888",
            };

            let payload = serde_json::json!({
                "channel": config.channel,
                "username": config.username,
                "attachments": [
                    {
                        "color": color,
                        "text": message
                    }
                ]
            });

            let response = self.client
                .post(&config.webhook_url)
                .json(&payload)
                .send()
                .await?;

            if !response.status().is_success() {
                return Err(anyhow::anyhow!("Slack notification failed: {}", response.status()));
            }

            info!("Slack notification sent to {}", config.channel);
        }

        Ok(())
    }

    pub async fn send_teams_notification(&self, message: &str, severity: &str) -> Result<()> {
        if let Some(ref config) = self.teams_config {
            let color = match severity {
                "critical" => "ff0000",
                "high" => "ff6600",
                "medium" => "ffaa00",
                "low" => "00aa00",
                _ => "888888",
            };

            let payload = serde_json::json!({
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "summary": "Security Alert",
                "themeColor": color,
                "sections": [
                    {
                        "activityTitle": "Security Alert",
                        "activitySubtitle": severity,
                        "text": message
                    }
                ]
            });

            let response = self.client
                .post(&config.webhook_url)
                .json(&payload)
                .send()
                .await?;

            if !response.status().is_success() {
                return Err(anyhow::anyhow!("Teams notification failed: {}", response.status()));
            }

            info!("Teams notification sent");
        }

        Ok(())
    }

    pub async fn create_pagerduty_incident(&self, title: &str, description: &str, severity: &str) -> Result<String> {
        if let Some(ref config) = self.pagerduty_config {
            let urgency = match severity {
                "critical" => "high",
                "high" => "high",
                _ => "low",
            };

            let payload = serde_json::json!({
                "incident": {
                    "type": "incident",
                    "title": title,
                    "service": {
                        "id": config.service_id,
                        "type": "service_reference"
                    },
                    "urgency": urgency,
                    "body": {
                        "type": "incident_body",
                        "details": description
                    }
                }
            });

            let response = self.client
                .post("https://api.pagerduty.com/incidents")
                .header("Authorization", format!("Token token={}", config.api_key))
                .header("Accept", "application/vnd.pagerduty+json;version=2")
                .json(&payload)
                .send()
                .await?;

            if !response.status().is_success() {
                return Err(anyhow::anyhow!("PagerDuty incident creation failed: {}", response.status()));
            }

            let incident_data: PagerDutyIncidentResponse = response.json().await?;
            info!("PagerDuty incident created: {}", incident_data.incident.id);
            Ok(incident_data.incident.id)
        } else {
            Err(anyhow::anyhow!("PagerDuty not configured"))
        }
    }

    pub async fn create_jira_ticket(&self, title: &str, description: &str, severity: &str) -> Result<String> {
        if let Some(ref config) = self.jira_config {
            let priority = match severity {
                "critical" => "Highest",
                "high" => "High",
                "medium" => "Medium",
                "low" => "Low",
                _ => "Lowest",
            };

            let payload = serde_json::json!({
                "fields": {
                    "project": {
                        "key": config.project_key
                    },
                    "summary": title,
                    "description": description,
                    "issuetype": {
                        "name": "Bug"
                    },
                    "priority": {
                        "name": priority
                    }
                }
            });

            let response = self.client
                .post(&format!("{}/rest/api/2/issue", config.url))
                .header("Authorization", format!("Basic {}", base64::encode(format!("{}:{}", config.username, config.api_token))))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if !response.status().is_success() {
                return Err(anyhow::anyhow!("Jira ticket creation failed: {}", response.status()));
            }

            let ticket_data: JiraTicketResponse = response.json().await?;
            info!("Jira ticket created: {}", ticket_data.key);
            Ok(ticket_data.key)
        } else {
            Err(anyhow::anyhow!("Jira not configured"))
        }
    }

    pub async fn notify_incident(&self, incident: &Incident) -> Result<()> {
        // Send email notification
        if self.email_config.enabled {
            let subject = format!("Security Incident: {}", incident.title);
            let body = format!(
                "A new security incident has been created:\n\nTitle: {}\nDescription: {}\nSeverity: {}\nStatus: {}\nCreated: {}\n\nPlease take appropriate action.",
                incident.title,
                incident.description,
                incident.severity,
                incident.status,
                incident.created_at
            );

            self.send_email_notification(
                &self.email_config.recipient_email,
                &subject,
                &body,
            ).await?;
        }

        // Send webhook notification
        if self.webhook_config.enabled {
            let payload = serde_json::json!({
                "incident_id": incident.id,
                "title": incident.title,
                "description": incident.description,
                "severity": incident.severity,
                "status": incident.status,
                "created_at": incident.created_at,
                "type": "incident_created"
            });

            self.send_webhook_notification(payload).await?;
        }

        // Send Slack notification
        self.send_slack_notification(
            &format!("🚨 Security Incident: {}\n{}", incident.title, incident.description),
            &incident.severity,
        ).await?;

        // Send Teams notification
        self.send_teams_notification(
            &format!("Security Incident: {}", incident.title),
            &incident.severity,
        ).await?;

        // Create PagerDuty incident for critical incidents
        if incident.severity == "critical" {
            if let Err(e) = self.create_pagerduty_incident(
                &incident.title,
                &incident.description,
                &incident.severity,
            ).await {
                warn!("Failed to create PagerDuty incident: {}", e);
            }
        }

        // Create Jira ticket for high and critical incidents
        if incident.severity == "critical" || incident.severity == "high" {
            if let Err(e) = self.create_jira_ticket(
                &incident.title,
                &format!("{}\n\nSeverity: {}\nCreated: {}", incident.description, incident.severity, incident.created_at),
                &incident.severity,
            ).await {
                warn!("Failed to create Jira ticket: {}", e);
            }
        }

        Ok(())
    }

    pub async fn notify_anomaly(&self, event: &DataEvent, score: f64) -> Result<()> {
        // Send webhook notification
        if self.webhook_config.enabled {
            let payload = serde_json::json!({
                "event_id": event.event_id,
                "event_type": event.event_type,
                "anomaly_score": score,
                "timestamp": event.timestamp,
                "type": "anomaly_detected"
            });

            self.send_webhook_notification(payload).await?;
        }

        // Send Slack notification for high-score anomalies
        if score > 0.8 {
            self.send_slack_notification(
                &format!("⚠️ High-Scoring Anomaly Detected\nEvent Type: {}\nScore: {:.2}", event.event_type, score),
                "high",
            ).await?;
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct PagerDutyIncidentResponse {
    incident: PagerDutyIncident,
}

#[derive(Debug, Deserialize)]
struct PagerDutyIncident {
    id: String,
}

#[derive(Debug, Deserialize)]
struct JiraTicketResponse {
    key: String,
}
