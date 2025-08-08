// src/collectors/data_collector.rs
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lru::LruCache;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use windows::Win32::System::Diagnostics::Etw::*;
use windows::Win32::System::Threading::*;
use windows::core::*;

use crate::collectors::{DataEvent, EventData};
use crate::config::CollectorConfig;
use crate::utils::database::DatabaseManager;

pub struct DataCollector {
    config: CollectorConfig,
    db: Arc<DatabaseManager>,
    event_cache: Arc<Mutex<LruCache<String, DataEvent>>>,
    etw_session: Option<EtwSession>,
    network_interface: Option<String>,
}

impl DataCollector {
    pub fn new(config: CollectorConfig, db: Arc<DatabaseManager>) -> Result<Self> {
        let cache_size = config.max_features;
        let network_interface = config.network_filter.clone();
        
        Ok(Self {
            config,
            db,
            event_cache: Arc::new(Mutex::new(LruCache::new(cache_size))),
            etw_session: None,
            network_interface,
        })
    }

    pub async fn run(&self, sender: mpsc::Sender<DataEvent>) -> Result<()> {
        // Initialize ETW session if on Windows
        #[cfg(target_os = "windows")]
        {
            if !self.config.etw_providers.is_empty() {
                self.init_etw_session().await?;
            }
        }

        // Initialize network capture
        let network_handle = if self.config.event_types.contains(&"network".to_string()) {
            Some(self.start_network_capture(sender.clone()).await?)
        } else {
            None
        };

        // Initialize file system watcher
        let file_handle = if self.config.event_types.contains(&"file".to_string()) {
            Some(self.start_file_watcher(sender.clone()).await?)
        } else {
            None
        };

        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs_f64(self.config.polling_interval),
        );

        loop {
            interval.tick().await;

            // Collect events based on configured event types
            if self.config.event_types.contains(&"process".to_string()) {
                self.collect_process_events(&sender).await?;
            }

            if self.config.event_types.contains(&"gpu".to_string()) {
                self.collect_gpu_events(&sender).await?;
            }

            if self.config.event_types.contains(&"feedback".to_string()) {
                self.collect_feedback_events(&sender).await?;
            }

            // Process events in batches
            self.process_batched_events(&sender).await?;
        }
    }

    #[cfg(target_os = "windows")]
    async fn init_etw_session(&mut self) -> Result<()> {
        use windows::Win32::System::Diagnostics::Etw::*;

        // Create ETW session
        let session = EtwSession::new(&self.config.etw_providers)?;
        self.etw_session = Some(session);
        info!("ETW session initialized");
        Ok(())
    }

    async fn start_network_capture(&self, sender: mpsc::Sender<DataEvent>) -> Result<task::JoinHandle<()>> {
        let interface_name = self.network_interface.clone();
        let config = self.config.clone();
        
        let handle = task::spawn(async move {
            if let Ok(interface_name) = interface_name {
                // Find the network interface
                let interface_names_match = |iface: &datalink::NetworkInterface| iface.name == interface_name;
                
                let interfaces = datalink::interfaces();
                let interface = interfaces.into_iter()
                    .find(interface_names_match)
                    .unwrap_or_else(|| {
                        warn!("Network interface {} not found, using default", interface_name);
                        datalink::interfaces()
                            .into_iter()
                            .next()
                            .expect("No network interface available")
                    });

                // Create a channel to receive packets
                let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                    Ok(Ethernet(tx, rx)) => (tx, rx),
                    Ok(_) => panic!("Unsupported channel type"),
                    Err(e) => {
                        error!("Failed to create datalink channel: {}", e);
                        return;
                    }
                };

                loop {
                    match rx.next() {
                        Ok(packet) => {
                            if let Some(event) = Self::process_network_packet(packet, &config) {
                                if let Err(e) = sender.send(event).await {
                                    error!("Failed to send network event: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to receive packet: {}", e);
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    fn process_network_packet(packet: &[u8], config: &CollectorConfig) -> Option<DataEvent> {
        let ethernet_packet = EthernetPacket::new(packet)?;
        
        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;
                
                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;
                        
                        Some(DataEvent {
                            event_id: Uuid::new_v4(),
                            event_type: "network".to_string(),
                            timestamp: Utc::now(),
                            data: EventData::Network {
                                src_ip: ipv4_packet.get_source().to_string(),
                                src_port: tcp_packet.get_source(),
                                dst_ip: ipv4_packet.get_destination().to_string(),
                                dst_port: tcp_packet.get_destination(),
                                protocol: "TCP".to_string(),
                                packet_size: packet.len() as u32,
                                flags: format!("{:?}", tcp_packet.get_flags()),
                            },
                        })
                    }
                    IpNextHeaderProtocols::Udp => {
                        let udp_packet = UdpPacket::new(ipv4_packet.payload())?;
                        
                        Some(DataEvent {
                            event_id: Uuid::new_v4(),
                            event_type: "network".to_string(),
                            timestamp: Utc::now(),
                            data: EventData::Network {
                                src_ip: ipv4_packet.get_source().to_string(),
                                src_port: udp_packet.get_source(),
                                dst_ip: ipv4_packet.get_destination().to_string(),
                                dst_port: udp_packet.get_destination(),
                                protocol: "UDP".to_string(),
                                packet_size: packet.len() as u32,
                                flags: "".to_string(),
                            },
                        })
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    async fn start_file_watcher(&self, sender: mpsc::Sender<DataEvent>) -> Result<task::JoinHandle<()>> {
        use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
        
        let monitor_dir = self.config.monitor_dir.clone();
        let config = self.config.clone();
        
        let handle = task::spawn(async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel(100);
            
            let mut watcher: RecommendedWatcher = Watcher::new(
                move |res: Result<Event, _>| {
                    if let Ok(event) = res {
                        let _ = tx.blocking_send(event);
                    }
                },
                notify::Config::default(),
            ).unwrap();

            watcher.watch(&monitor_dir, RecursiveMode::Recursive).unwrap();

            while let Some(event) = rx.recv().await {
                if let Some(file_event) = Self::process_file_event(event, &config) {
                    if let Err(e) = sender.send(file_event).await {
                        error!("Failed to send file event: {}", e);
                    }
                }
            }
        });

        Ok(handle)
    }

    fn process_file_event(event: notify::Event, config: &CollectorConfig) -> Option<DataEvent> {
        let path = event.paths.first()?.clone();
        let operation = match event.kind {
            EventKind::Create(_) => "create",
            EventKind::Modify(_) => "modify",
            EventKind::Remove(_) => "delete",
            EventKind::Access(_) => "access",
            _ => return None,
        };

        // Get file size if file exists
        let size = std::fs::metadata(&path).ok()?.len();

        // Get file hash if it's a regular file
        let hash = if path.is_file() {
            Self::calculate_file_hash(&path).ok()
        } else {
            None
        };

        Some(DataEvent {
            event_id: Uuid::new_v4(),
            event_type: "file".to_string(),
            timestamp: Utc::now(),
            data: EventData::File {
                path: path.to_string_lossy().to_string(),
                operation: operation.to_string(),
                size,
                process_id: 0, // Would need to get from system
                hash,
            },
        })
    }

    fn calculate_file_hash(path: &std::path::Path) -> Result<String> {
        use std::io::Read;
        use sha2::{Digest, Sha256};
        
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 4096];
        
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        
        Ok(format!("{:x}", hasher.finalize()))
    }

    async fn collect_process_events(&self, sender: &mpsc::Sender<DataEvent>) -> Result<()> {
        let mut system = sysinfo::System::new_all();
        system.refresh_all();

        for (pid, process) in system.processes() {
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

    async fn collect_gpu_events(&self, sender: &mpsc::Sender<DataEvent>) -> Result<()> {
        // Implementation for GPU monitoring
        // This would use GPU-specific libraries like nvml for NVIDIA GPUs
        Ok(())
    }

    async fn collect_feedback_events(&self, sender: &mpsc::Sender<DataEvent>) -> Result<()> {
        // Implementation for feedback events
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
            for event in batch {
                if let Err(e) = sender.send(event).await {
                    error!("Failed to send batched event: {}", e);
                }
            }
        }

        Ok(())
    }
}

#[cfg(target_os = "windows")]
struct EtwSession {
    // ETW session implementation would go here
}

#[cfg(target_os = "windows")]
impl EtwSession {
    fn new(providers: &[crate::config::EtwProvider]) -> Result<Self> {
        // Initialize ETW session with providers
        Ok(EtwSession {})
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
