// src/controllers/main_controller.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use crate::analytics::AnalyticsManager;
use crate::collectors::{DataCollector, DataEvent};
use crate::config::Config;
use crate::integrations::IntegrationManager;
use crate::ml::ModelManager;
use crate::response::automation::ResponseAutomation;
use crate::response::incident_response::IncidentResponseManager;
use crate::utils::database::DatabaseManager;
use crate::utils::telemetry::TelemetryManager;
use crate::views::{ConsoleView, DashboardView};

pub struct MainController {
    model_manager: Arc<ModelManager>,
    threat_intel: Arc<crate::utils::threat_intel::ThreatIntelManager>,
    vuln_manager: Arc<crate::utils::vulnerability::VulnerabilityManager>,
    incident_manager: Arc<IncidentResponseManager>,
    analytics_manager: Arc<AnalyticsManager>,
    integration_manager: IntegrationManager,
    telemetry_manager: Option<Arc<TelemetryManager>>,
    console_view: ConsoleView,
    dashboard_view: DashboardView,
    config: Config,
    db: Arc<DatabaseManager>,
}

impl MainController {
    pub fn new(
        model_manager: Arc<ModelManager>,
        threat_intel: Arc<crate::utils::threat_intel::ThreatIntelManager>,
        vuln_manager: Arc<crate::utils::vulnerability::VulnerabilityManager>,
        incident_manager: Arc<IncidentResponseManager>,
        analytics_manager: Arc<AnalyticsManager>,
        config: Config,
        db: Arc<DatabaseManager>,
        telemetry_manager: Option<Arc<TelemetryManager>>,
    ) -> Self {
        let console_view = ConsoleView::new(&config);
        let dashboard_view = DashboardView::new(&config.dashboard, db.clone()).unwrap();
        
        let integration_manager = IntegrationManager::new(
            config.email.clone(),
            config.webhook.clone(),
            None, // Slack config would be loaded from config
            None, // Teams config would be loaded from config
            None, // PagerDuty config would be loaded from config
            None, // Jira config would be loaded from config
        ).unwrap();

        Self {
            model_manager,
            threat_intel,
            vuln_manager,
            incident_manager,
            analytics_manager,
            integration_manager,
            telemetry_manager,
            console_view,
            dashboard_view,
            config,
            db,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Starting Exploit Detector main controller");

        // Initialize components
        self.initialize().await?;

        // Create channels for communication
        let (event_sender, mut event_receiver) = mpsc::channel(1000);
        let (anomaly_sender, mut anomaly_receiver) = mpsc::channel(100);
        let (incident_sender, mut incident_receiver) = mpsc::channel(100);

        // Start data collector
        let collector = DataCollector::new(self.config.collector.clone(), self.db.clone());
        let collector_handle = tokio::spawn(async move {
            if let Err(e) = collector.run(event_sender).await {
                error!("Data collector error: {}", e);
            }
        });

        // Start threat intelligence manager
        let threat_intel = self.threat_intel.clone();
        let threat_intel_handle = tokio::spawn(async move {
            if let Err(e) = threat_intel.run().await {
                error!("Threat intelligence manager error: {}", e);
            }
        });

        // Start vulnerability manager
        let vuln_manager = self.vuln_manager.clone();
        let vuln_handle = tokio::spawn(async move {
            if let Err(e) = vuln_manager.run().await {
                error!("Vulnerability manager error: {}", e);
            }
        });

        // Start dashboard
        let dashboard_handle = tokio::spawn(async move {
            if let Err(e) = self.dashboard_view.run().await {
                error!("Dashboard error: {}", e);
            }
        });

        // Start telemetry if enabled
        let telemetry_handle = if let Some(ref telemetry) = self.telemetry_manager {
            let telemetry = telemetry.clone();
            Some(tokio::spawn(async move {
                let mut health_check_interval = interval(Duration::from_secs(60));
                let mut metrics_update_interval = interval(Duration::from_secs(30));
                
                loop {
                    tokio::select! {
                        _ = health_check_interval.tick() => {
                            if let Err(e) = telemetry.run_health_checks().await {
                                error!("Health check error: {}", e);
                            }
                        }
                        _ = metrics_update_interval.tick() => {
                            if let Err(e) = telemetry.update_system_metrics().await {
                                error!("System metrics update error: {}", e);
                            }
                        }
                    }
                }
            }))
        } else {
            None
        };

        // Set up intervals for various tasks
        let mut model_training_interval = interval(Duration::from_secs(3600)); // Train models every hour
        let mut incident_check_interval = interval(Duration::from_secs(300)); // Check incidents every 5 minutes
        let mut report_interval = interval(Duration::from_secs(self.config.controller.report_interval as u64));
        let mut analytics_report_interval = interval(Duration::from_secs(3600 * 6)); // Analytics report every 6 hours

        // Main event loop
        loop {
            tokio::select! {
                // Process events as they arrive
                Some(event) = event_receiver.recv() => {
                    if let Err(e) = self.process_event(event, &anomaly_sender).await {
                        error!("Error processing event: {}", e);
                    }
                }
                
                // Process anomalies as they arrive
                Some((event, score)) = anomaly_receiver.recv() => {
                    if let Err(e) = self.process_anomaly(event, score).await {
                        error!("Error processing anomaly: {}", e);
                    }
                }
                
                // Process incidents as they arrive
                Some(incident_id) = incident_receiver.recv() => {
                    if let Err(e) = self.process_incident(incident_id).await {
                        error!("Error processing incident: {}", e);
                    }
                }
                
                // Train models at regular intervals
                _ = model_training_interval.tick() => {
                    if let Err(e) = self.model_manager.train_models().await {
                        error!("Error training models: {}", e);
                    }
                }
                
                // Check for incident escalations
                _ = incident_check_interval.tick() => {
                    if let Err(e) = self.incident_manager.check_escalations().await {
                        error!("Error checking incident escalations: {}", e);
                    }
                }
                
                // Generate reports at regular intervals
                _ = report_interval.tick() => {
                    if let Err(e) = self.generate_report().await {
                        error!("Error generating report: {}", e);
                    }
                }
                
                // Generate analytics reports
                _ = analytics_report_interval.tick() => {
                    if let Err(e) = self.generate_analytics_report().await {
                        error!("Error generating analytics report: {}", e);
                    }
                }
                
                // Handle shutdown
                else => break,
            }
        }

        // Wait for all tasks to complete
        collector_handle.await?;
        threat_intel_handle.await?;
        vuln_handle.await?;
        dashboard_handle.await?;
        if let Some(handle) = telemetry_handle {
            handle.await?;
        }

        info!("Main controller shutdown complete");
        Ok(())
    }

    async fn initialize(&mut self) -> Result<()> {
        info!("Initializing main controller components");

        // Initialize response automation
        self.integration_manager = IntegrationManager::new(
            self.config.email.clone(),
            self.config.webhook.clone(),
            None, // Would load from config
            None, // Would load from config
            None, // Would load from config
            None, // Would load from config
        )?;

        // Load models if they exist
        if let Err(e) = self.model_manager.load_models().await {
            warn!("Failed to load models: {}", e);
        }

        // Initialize threat intelligence
        if let Err(e) = self.threat_intel.update_threat_intel().await {
            warn!("Failed to initialize threat intelligence: {}", e);
        }

        // Initialize vulnerability manager
        if let Err(e) = self.vuln_manager.scan_vulnerabilities().await {
            warn!("Failed to initialize vulnerability scanner: {}", e);
        }

        // Record telemetry event
        if let Some(ref telemetry) = self.telemetry_manager {
            telemetry.record_event(
                "system_initialized".to_string(),
                "system".to_string(),
                "Exploit Detector system initialized successfully".to_string(),
                "info".to_string(),
            ).await?;
        }

        info!("Main controller initialized successfully");
        Ok(())
    }

    async fn process_event(&self, event: DataEvent, anomaly_sender: &mpsc::Sender<(DataEvent, f64)>) -> Result<()> {
        debug!("Processing event: {}", event.event_id);

        // Record telemetry
        if let Some(ref telemetry) = self.telemetry_manager {
            telemetry.increment_counter("events_processed", 1).await?;
            telemetry.record_event(
                "event_processed".to_string(),
                "event".to_string(),
                format!("Processed event of type: {}", event.event_type),
                "debug".to_string(),
            ).await?;
        }

        // Process with analytics
        self.analytics_manager.process_event(event.clone()).await?;

        // Check against threat intelligence
        if let Some(ioc_match) = self.check_threat_intel(&event).await? {
            warn!("Threat intelligence match: {:?}", ioc_match);
            
            // Create incident for high-confidence threat matches
            let incident_id = self.incident_manager.create_incident(
                format!("Threat Detected: {}", event.event_type),
                format!("Matched threat intelligence: {:?}", ioc_match),
                "High".to_string(),
            ).await?;

            // Record telemetry
            if let Some(ref telemetry) = self.telemetry_manager {
                telemetry.increment_counter("incidents_created", 1).await?;
                telemetry.record_event(
                    "incident_created".to_string(),
                    "incident".to_string(),
                    format!("Created incident for threat match: {:?}", ioc_match),
                    "warn".to_string(),
                ).await?;
            }

            // Send to incident processor
            anomaly_sender.send((event, 1.0)).await?;
        }

        // Process with ML models
        let start = std::time::Instant::now();
        if let Some(score) = self.model_manager.process_event(event.clone()).await? {
            let duration = start.elapsed();
            
            // Record telemetry
            if let Some(ref telemetry) = self.telemetry_manager {
                telemetry.record_timing("ml_prediction", duration.as_millis() as u64).await?;
            }

            // Send to anomaly processor
            anomaly_sender.send((event, score)).await?;
        }

        Ok(())
    }

    async fn check_threat_intel(&self, event: &DataEvent) -> Result<Option<String>> {
        match &event.data {
            crate::collectors::EventData::Network { src_ip, dst_ip, .. } => {
                if self.threat_intel.check_ioc("ip", src_ip).await {
                    return Ok(Some(format!("Malicious source IP: {}", src_ip)));
                }
                if self.threat_intel.check_ioc("ip", dst_ip).await {
                    return Ok(Some(format!("Malicious destination IP: {}", dst_ip)));
                }
            }
            crate::collectors::EventData::File { hash, .. } => {
                if let Some(hash_str) = hash {
                    if self.threat_intel.check_ioc("hash", hash_str).await {
                        return Ok(Some(format!("Malicious file hash: {}", hash_str)));
                    }
                }
            }
            _ => {}
        }

        Ok(None)
    }

    async fn process_anomaly(&self, event: DataEvent, score: f64) -> Result<()> {
        warn!("Anomaly detected: {} with score: {:.4}", event.event_id, score);

        // Record telemetry
        if let Some(ref telemetry) = self.telemetry_manager {
            telemetry.increment_counter("anomalies_detected", 1).await?;
            telemetry.record_event(
                "anomaly_detected".to_string(),
                "anomaly".to_string(),
                format!("Anomaly detected with score: {:.4}", score),
                "warn".to_string(),
            ).await?;
        }

        // Record with analytics
        self.analytics_manager.record_anomaly(&event, score).await?;

        // Display anomaly in console
        self.console_view.display_anomaly(&event, score).await?;

        // Send to dashboard
        if let Err(e) = self.dashboard_view.send_event(
            crate::views::DashboardEvent::NewAnomaly(event.clone(), score)
        ).await {
            error!("Failed to send anomaly to dashboard: {}", e);
        }

        // Send integration notifications
        self.integration_manager.notify_anomaly(&event, score).await?;

        // Create incident for high-severity anomalies
        if score > 0.9 {
            let incident_id = self.incident_manager.create_incident(
                format!("High-Severity Anomaly: {}", event.event_type),
                format!("Anomaly detected with score: {:.4}", score),
                "Critical".to_string(),
            ).await?;

            // Record telemetry
            if let Some(ref telemetry) = self.telemetry_manager {
                telemetry.increment_counter("incidents_created", 1).await?;
                telemetry.record_event(
                    "incident_created".to_string(),
                    "incident".to_string(),
                    format!("Created incident for high-severity anomaly: {:.4}", score),
                    "warn".to_string(),
                ).await?;
            }

            // Execute response playbook
            self.integration_manager.execute_playbook_for_incident(
                "anomaly_response",
                &self.incident_manager.get_incident(&incident_id).await.unwrap(),
            ).await?;
        }

        // Execute response automation
        self.integration_manager.process_event(event, score).await?;

        Ok(())
    }

    async fn process_incident(&self, incident_id: String) -> Result<()> {
        info!("Processing incident: {}", incident_id);

        // Get incident details
        if let Some(incident) = self.incident_manager.get_incident(&incident_id).await {
            // Send integration notifications
            self.integration_manager.notify_incident(&incident).await?;

            // Record with analytics
            self.analytics_manager.record_incident(&incident_id).await?;

            // Record telemetry
            if let Some(ref telemetry) = self.telemetry_manager {
                telemetry.record_event(
                    "incident_processed".to_string(),
                    "incident".to_string(),
                    format!("Processed incident: {}", incident_id),
                    "info".to_string(),
                ).await?;
            }
        }

        Ok(())
    }

    async fn generate_report(&self) -> Result<()> {
        info!("Generating security report");

        // Get report data from database
        let report_data = self.db.generate_report_data().await?;

        // Generate report
        let report_path = self.config.report.output_dir.clone();
        self.console_view.generate_report(&report_data, &report_path).await?;

        // Record telemetry
        if let Some(ref telemetry) = self.telemetry_manager {
            telemetry.record_event(
                "report_generated".to_string(),
                "report".to_string(),
                "Security report generated successfully".to_string(),
                "info".to_string(),
            ).await?;
        }

        // Send report via email if configured
        if self.config.email.enabled {
            // Implementation would send email report
        }

        // Send report via webhook if configured
        if self.config.webhook.enabled {
            // Implementation would send webhook report
        }

        Ok(())
    }

    async fn generate_analytics_report(&self) -> Result<()> {
        info!("Generating analytics report");

        // Generate analytics report
        let report = self.analytics_manager.generate_report().await?;

        // Save report to file
        let report_path = format!("reports/analytics_report_{}.json", report.generated_at.format("%Y%m%d_%H%M%S"));
        tokio::fs::write(&report_path, serde_json::to_string_pretty(&report)?).await?;

        info!("Analytics report saved to: {}", report_path);

        // Record telemetry
        if let Some(ref telemetry) = self.telemetry_manager {
            telemetry.record_event(
                "analytics_report_generated".to_string(),
                "report".to_string(),
                "Analytics report generated successfully".to_string(),
                "info".to_string(),
            ).await?;
        }

        Ok(())
    }
}
