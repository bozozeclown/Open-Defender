// src/controllers/main_controller.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use crate::collectors::{DataCollector, DataEvent};
use crate::config::Config;
use crate::models::DetectorModel;
use crate::utils::database::DatabaseManager;
use crate::views::{ConsoleView, DashboardView};

pub struct MainController {
    model: DetectorModel,
    console_view: ConsoleView,
    dashboard_view: DashboardView,
    config: Config,
    db: DatabaseManager,
}

impl MainController {
    pub fn new(
        model: DetectorModel,
        console_view: ConsoleView,
        dashboard_view: DashboardView,
        config: Config,
        db: DatabaseManager,
    ) -> Self {
        Self {
            model,
            console_view,
            dashboard_view,
            config,
            db,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        let (event_sender, mut event_receiver) = mpsc::channel(100);
        
        // Start data collector
        let collector = DataCollector::new(self.config.collector.clone(), std::sync::Arc::new(self.db.clone()));
        let collector_handle = tokio::spawn(async move {
            if let Err(e) = collector.run(event_sender).await {
                error!("Data collector error: {}", e);
            }
        });

        // Set up intervals for reporting and processing
        let mut report_interval = interval(Duration::from_secs_f64(self.config.controller.report_interval));
        let mut process_interval = interval(Duration::from_secs_f64(self.config.controller.poll_interval));

        loop {
            tokio::select! {
                // Process events as they arrive
                Some(event) = event_receiver.recv() => {
                    if let Err(e) = self.process_event(event).await {
                        error!("Error processing event: {}", e);
                    }
                }
                
                // Process batched events at regular intervals
                _ = process_interval.tick() => {
                    if let Err(e) = self.process_batched_events().await {
                        error!("Error processing batched events: {}", e);
                    }
                }
                
                // Generate reports at regular intervals
                _ = report_interval.tick() => {
                    if let Err(e) = self.generate_report().await {
                        error!("Error generating report: {}", e);
                    }
                }
                
                // Handle shutdown
                else => break,
            }
        }

        // Wait for collector to finish
        collector_handle.await?;

        Ok(())
    }

    async fn process_event(&mut self, event: DataEvent) -> Result<()> {
        debug!("Processing event: {}", event.event_id);
        
        // Process event with the model
        self.model.process_event(event).await?;
        
        Ok(())
    }

    async fn process_batched_events(&mut self) -> Result<()> {
        // Process any batched events in the model
        // This would be used for batch processing of events
        debug!("Processing batched events");
        
        Ok(())
    }

    async fn generate_report(&mut self) -> Result<()> {
        info!("Generating security report");
        
        // Collect data for report
        let report_data = self.db.generate_report_data().await?;
        
        // Generate report
        let report_path = self.config.report.output_dir.clone();
        self.console_view.generate_report(&report_data, &report_path).await?;
        
        // Send report via email if configured
        if self.config.email.enabled {
            // Implementation for sending email report
        }
        
        // Send report via webhook if configured
        if self.config.webhook.enabled {
            // Implementation for sending webhook report
        }
        
        Ok(())
    }
}