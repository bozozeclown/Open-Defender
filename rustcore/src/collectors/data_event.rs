// src/collectors/data_event.rs
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEvent {
    pub event_id: Uuid,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub data: EventData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EventData {
    Process {
        pid: u32,
        name: String,
        cmd: Vec<String>,
        cwd: String,
        parent_pid: Option<u32>,
        start_time: u64,
        cpu_usage: f32,
        memory_usage: u64,
        virtual_memory: u64,
    },
    Network {
        src_ip: String,
        src_port: u16,
        dst_ip: String,
        dst_port: u16,
        protocol: String,
        packet_size: u32,
        flags: String,
    },
    File {
        path: String,
        operation: String,
        size: u64,
        process_id: u32,
        hash: Option<String>,
    },
    Gpu {
        process_id: u32,
        gpu_id: u32,
        memory_usage: u64,
        utilization: f32,
        temperature: f32,
    },
    Feedback {
        event_id: Uuid,
        is_anomaly: bool,
        user_id: Option<String>,
        comment: Option<String>,
    },
}