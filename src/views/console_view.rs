// src/views/console_view.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

use crate::utils::database::ReportData;

pub struct ConsoleView {
    config: crate::config::Config,
}

impl ConsoleView {
    pub fn new(config: &crate::config::Config) -> Self {
        Self {
            config: config.clone(),
        }
    }

    pub async fn display_event(&self, event: &crate::collectors::DataEvent) -> Result<()> {
        println!("Event: {} at {}", event.event_type, event.timestamp);
        println!("ID: {}", event.event_id);
        println!("Data: {:?}", event.data);
        println!("---");
        Ok(())
    }

    pub async fn display_anomaly(&self, event: &crate::collectors::DataEvent, score: f64) -> Result<()> {
        warn!("Anomaly detected! Score: {}", score);
        self.display_event(event).await?;
        Ok(())
    }

    pub async fn generate_report(&self, report_data: &ReportData, output_dir: &str) -> Result<()> {
        info!("Generating report in {}", output_dir);

        // Create output directory if it doesn't exist
        fs::create_dir_all(output_dir)
            .with_context(|| format!("Failed to create output directory: {}", output_dir))?;

        // Generate report filename with timestamp
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let report_path = Path::new(output_dir).join(format!("report_{}.json", timestamp));

        // Serialize report data
        let report_json = serde_json::to_string_pretty(report_data)
            .context("Failed to serialize report data")?;

        // Write report to file
        fs::write(&report_path, report_json)
            .with_context(|| format!("Failed to write report to {:?}", report_path))?;

        info!("Report generated: {:?}", report_path);

        // Display summary to console
        println!("Security Report Summary");
        println!("======================");
        println!("Generated at: {}", report_data.generated_at);
        println!("Total anomalies: {}", report_data.total_anomalies);
        println!("Average anomaly score: {:?}", report_data.avg_score);
        println!("Event type counts:");
        
        for (event_type, count) in &report_data.event_type_counts {
            println!("  {}: {}", event_type, count);
        }

        Ok(())
    }
}
