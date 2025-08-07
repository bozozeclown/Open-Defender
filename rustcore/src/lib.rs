// src/lib.rs
pub mod collectors;
pub mod config;
pub mod controllers;
pub mod models;
pub mod response;
pub mod utils;
pub mod views;
pub mod hooks;
pub mod ml;
pub mod analytics;
pub mod integrations;

use anyhow::{Context, Result};
use clap::Parser;
use exploit_detector::controllers::MainController;
use exploit_detector::utils::database::DatabaseManager;
use exploit_detector::utils::telemetry::TelemetryManager;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info, level_filters::LevelFilter};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "exploit_detector")]
#[command(about = "Enterprise-Grade AI-Based Zero-Day Exploit Detection System", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    /// Run in test mode
    #[arg(long)]
    test_mode: bool,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Enable performance profiling
    #[arg(long)]
    profile: bool,

    /// Enable telemetry
    #[arg(long)]
    telemetry: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize telemetry if enabled
    let telemetry_manager = if args.telemetry {
        Some(Arc::new(TelemetryManager::new().await?))
    } else {
        None
    };

    // Initialize tracing with appropriate level
    let log_level = match args.log_level.as_str() {
        "trace" => LevelFilter::TRACE,
        "debug" => LevelFilter::DEBUG,
        "info" => LevelFilter::INFO,
        "warn" => LevelFilter::WARN,
        "error" => LevelFilter::ERROR,
        _ => LevelFilter::INFO,
    };

    if args.debug {
        tracing_subscriber::registry()
            .with(fmt::layer().pretty())
            .with(log_level)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(fmt::layer().json())
            .with(log_level)
            .init();
    }

    // Load configuration
    let config = exploit_detector::config::Config::load(&args.config)
        .with_context(|| format!("Failed to load config from {}", args.config))?;

    // Initialize database with connection pool
    let db_manager = Arc::new(DatabaseManager::new(&config.database).await?);

    // Initialize core components
    let threat_intel = Arc::new(exploit_detector::utils::threat_intel::ThreatIntelManager::new(
        &config.threat_intel,
    )?);

    let vuln_manager = Arc::new(exploit_detector::utils::vulnerability::VulnerabilityManager::new(
        config.cve_manager.clone(),
        config.software_inventory.clone(),
        config.vulnerability_scanner.clone(),
        config.patch_manager.clone(),
    )?);

    let incident_manager = Arc::new(exploit_detector::response::incident_response::IncidentResponseManager::new(
        config.incident_response.clone(),
        (*db_manager).clone(),
    )?);

    let model_manager = Arc::new(exploit_detector::ml::ModelManager::new(
        &config.ml,
        (*db_manager).clone(),
    ).await?);

    let analytics_manager = Arc::new(exploit_detector::analytics::AnalyticsManager::new(
        (*db_manager).clone(),
    )?);

    // Initialize main controller
    let mut controller = MainController::new(
        model_manager,
        threat_intel,
        vuln_manager,
        incident_manager,
        analytics_manager,
        config,
        db_manager,
        telemetry_manager,
    );

    // Start background tasks
    let controller_handle = tokio::spawn(async move {
        if let Err(e) = controller.run().await {
            error!("Controller error: {}", e);
        }
    });

    // Handle graceful shutdown
    tokio::select! {
        result = signal::ctrl_c() => {
            info!("Received shutdown signal");
            result?;
        }
        result = controller_handle => {
            if let Err(e) = result {
                error!("Controller task error: {}", e);
            }
        }
    }

    info!("Exploit Detector shutdown complete");
    Ok(())
}