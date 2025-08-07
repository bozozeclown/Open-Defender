// src/collectors/data_collector.rs
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::collectors::{DataEvent, EventData};
use crate::config::CollectorConfig;
use crate::utils::database::DatabaseManager;

pub struct DataCollector {
    config: CollectorConfig,
    db: Arc<DatabaseManager>,
    event_cache: Arc<Mutex<LruCache<String, DataEvent>>>,
}

impl DataCollector {
    pub fn new(config: CollectorConfig, db: Arc<DatabaseManager>) -> Self {
        let cache_size = config.max_features;
        Self {
            config,
            db,
            event_cache: Arc::new(Mutex::new(LruCache::new(cache_size))),
        }
    }

    pub async fn run(&self, sender: mpsc::Sender<DataEvent>) -> Result<()> {
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs_f64(self.config.polling_interval),
        );

        loop {
            interval.tick().await;

            // Collect events based on configured event types
            for event_type in &self.config.event_types {
                match event_type.as_str() {
                    "process" => self.collect_process_events(&sender).await?,
                    "network" => self.collect_network_events(&sender).await?,
                    "file" => self.collect_file_events(&sender).await?,
                    "gpu" => self.collect_gpu_events(&sender).await?,
                    "feedback" => self.collect_feedback_events(&sender).await?,
                    _ => warn!("Unknown event type: {}", event_type),
                }
            }

            // Process events in batches
            self.process_batched_events(&sender).await?;
        }
    }

    async fn collect_process_events(&self, sender: &mpsc::Sender<DataEvent>) -> Result<()> {
        let processes = sysinfo::System::new_all();
        processes.refresh_all();

        for (pid, process) in processes.processes() {
            let event_data = EventData::Process {
                pid: pid.as_u32(),
                name: process.name().to_string(),
                cmd: process.cmd().to_vec(),
                cwd: process.cwd().to_string_lossy().to_string(),
                parent_pid: process.parent().map(|p| p.as_u32()),
                start_time: process.start_time(),
                cpu_usage: process.cpu_usage(),
                memory_usage: process.memory(),
                virtual_memory: process.virtual_memory(),
            };

            let event = DataEvent {
                event_id: Uuid::new_v4(),
                event_type: "process".to_string(),
                timestamp: Utc::now(),
                data: event_data,
            };

            if let Err(e) = sender.send(event).await {
                error!("Failed to send process event: {}", e);
            }
        }

        Ok(())
    }

    async fn collect_network_events(&self, sender: &mpsc::Sender<DataEvent>) -> Result<()> {
        // Implementation for network event collection
        // This would use pnet or similar crate to capture network packets
        Ok(())
    }

    async fn collect_file_events(&self, sender: &mpsc::Sender<DataEvent>) -> Result<()> {
        // Implementation for file event collection
        // This would use notify crate to monitor file system changes
        Ok(())
    }

    async fn collect_gpu_events(&self, sender: &mpsc::Sender<DataEvent>) -> Result<()> {
        // Implementation for GPU event collection
        // This would use GPU monitoring libraries
        Ok(())
    }

    async fn collect_feedback_events(&self, sender: &mpsc::Sender<DataEvent>) -> Result<()> {
        // Implementation for feedback event collection
        Ok(())
    }

    async fn process_batched_events(&self, sender: &mpsc::Sender<DataEvent>) -> Result<()> {
        // Process events in batches
        let batch_size = self.config.batch_size as usize;
        let mut batch = Vec::with_capacity(batch_size);

        // Collect events from cache
        {
            let mut cache = self.event_cache.lock().await;
            for (_, event) in cache.iter() {
                batch.push(event.clone());
                if batch.len() >= batch_size {
                    break;
                }
            }
        }

        // Process batch
        if !batch.is_empty() {
            debug!("Processing batch of {} events", batch.len());
            
            // Here we would extract features and run anomaly detection
            // For now, we'll just log the events
            for event in batch {
                if let Err(e) = sender.send(event).await {
                    error!("Failed to send batched event: {}", e);
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl EventCollector for DataCollector {
    async fn collect_events(&self, sender: mpsc::Sender<DataEvent>) -> Result<()> {
        self.run(sender).await
    }
}

#[async_trait]
pub trait EventCollector: Send + Sync {
    async fn collect_events(&self, sender: mpsc::Sender<DataEvent>) -> Result<()>;
}