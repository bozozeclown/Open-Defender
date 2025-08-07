// src/main.rs
use anyhow::{Context, Result};
use clap::Parser;
use exploit_detector::collectors::DataCollector;
use exploit_detector::config::Config;
use exploit_detector::controllers::MainController;
use exploit_detector::models::DetectorModel;
use exploit_detector::utils::database::DatabaseManager;
use exploit_detector::views::{ConsoleView, DashboardView};
use std::path::Path;
use tokio::signal;
use tracing::{error, info, level_filters::LevelFilter};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "exploit_detector")]
#[command(about = "AI-Based Zero-Day Exploit Detection System", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    /// Run in test mode
    #[arg(long)]
    test_mode: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(LevelFilter::INFO)
        .init();

    let args = Args::parse();

    // Load configuration
    let config_path = Path::new(&args.config);
    let config = Config::load(config_path)
        .with_context(|| format!("Failed to load config from {}", args.config))?;

    // Initialize database
    let db_manager = DatabaseManager::new(&config.database).await?;

    // Initialize components
    let model = DetectorModel::new(&config.ml, &db_manager).await?;
    let console_view = ConsoleView::new(&config);
    let dashboard_view = DashboardView::new(&config.dashboard).await?;

    // Start dashboard in a separate task
    let dashboard_handle = tokio::spawn(async move {
        if let Err(e) = dashboard_view.run().await {
            error!("Dashboard error: {}", e);
        }
    });

    // Initialize and run main controller
    let mut controller = MainController::new(model, console_view, dashboard_view, config, db_manager);

    // Handle graceful shutdown
    tokio::select! {
        result = controller.run() => {
            if let Err(e) = result {
                error!("Controller error: {}", e);
            }
        }
        _ = signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    // Wait for dashboard to shutdown
    dashboard_handle.await?;

    Ok(())
}