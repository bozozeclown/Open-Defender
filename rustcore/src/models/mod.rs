// src/models/mod.rs
use std::sync::Arc;
use crate::config::Config;
use crate::collectors::DataEvent;
use crate::utils::database::DatabaseManager;
use anyhow::{Context, Result};
use ndarray::{Array1, Array2};
use linfa::prelude::*;
use linfa_clustering::{KMeans, KMeansHyperParams};
use linfa_nn::distance::L2Dist;
use serde::{Deserialize, Serialize};

pub struct ModelManager {
    config: Arc<Config>,
    db: Arc<DatabaseManager>,
    anomaly_detector: AnomalyDetector,
    feature_extractor: FeatureExtractor,
}

impl ModelManager {
    pub fn new(config: Arc<Config>, db: Arc<DatabaseManager>) -> Self {
        let anomaly_detector = AnomalyDetector::new(config.clone());
        let feature_extractor = FeatureExtractor::new(config.clone());
        
        Self {
            config,
            db,
            anomaly_detector,
            feature_extractor,
        }
    }
    
    pub async fn process_events(&self, events: &[DataEvent]) -> Result<Vec<AnomalyResult>> {
        // Extract features from events
        let features = self.feature_extractor.extract_features(events).await?;
        
        // Detect anomalies
        let anomalies = self.anomaly_detector.detect_anomalies(&features).await?;
        
        Ok(anomalies)
    }
    
    pub async fn train_model(&self, training_data: &[DataEvent]) -> Result<()> {
        // Extract features from training data
        let features = self.feature_extractor.extract_features(training_data).await?;
        
        // Train the anomaly detection model
        self.anomaly_detector.train(&features).await?;
        
        Ok(())
    }
}

pub struct AnomalyDetector {
    config: Arc<Config>,
    model: Option<KMeans<f64, L2Dist>>,
    threshold: f64,
}

impl AnomalyDetector {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            model: None,
            threshold: config.ml.anomaly_threshold,
        }
    }
    
    pub async fn detect_anomalies(&self, features: &Array2<f64>) -> Result<Vec<AnomalyResult>> {
        if self.model.is_none() {
            return Ok(vec![]);
        }
        
        let model = self.model.as_ref().unwrap();
        let mut results = Vec::new();
        
        for (i, feature) in features.rows().into_iter().enumerate() {
            // Find the nearest cluster centroid
            let prediction = model.predict(feature);
            let centroid = model.centroids().row(prediction);
            
            // Calculate distance to centroid (anomaly score)
            let distance = L2Dist.distance(feature, centroid);
            
            // Determine if it's an anomaly
            let is_anomaly = distance > self.threshold;
            
            results.push(AnomalyResult {
                event_id: format!("event_{}", i), // In real implementation, get from event
                anomaly_score: distance,
                is_anomaly,
                cluster_id: prediction,
                timestamp: chrono::Utc::now(),
            });
        }
        
        Ok(results)
    }
    
    pub async fn train(&mut self, training_data: &Array2<f64>) -> Result<()> {
        let n_clusters = self.config.clustering.n_clusters;
        
        // Create and train K-means model
        let model = KMeans::params(n_clusters)
            .max_n_iterations(self.config.clustering.max_iter)
            .tolerance(self.config.clustering.tol)
            .fit(training_data)
            .context("Failed to train K-means model")?;
        
        self.model = Some(model);
        
        // Save the model
        self.save_model().await?;
        
        Ok(())
    }
    
    async fn save_model(&self) -> Result<()> {
        if let Some(model) = &self.model {
            let model_path = &self.config.ml.model_path;
            
            // Ensure the directory exists
            if let Some(parent) = model_path.parent() {
                std::fs::create_dir_all(parent)
                    .context("Failed to create model directory")?;
            }
            
            // Serialize the model
            let serialized = serde_json::to_string(model)
                .context("Failed to serialize model")?;
            
            std::fs::write(model_path, serialized)
                .context("Failed to save model")?;
        }
        
        Ok(())
    }
    
    pub async fn load_model(&mut self) -> Result<()> {
        let model_path = &self.config.ml.model_path;
        
        if !model_path.exists() {
            return Ok(());
        }
        
        let serialized = std::fs::read_to_string(model_path)
            .context("Failed to read model file")?;
        
        let model: KMeans<f64, L2Dist> = serde_json::from_str(&serialized)
            .context("Failed to deserialize model")?;
        
        self.model = Some(model);
        
        Ok(())
    }
}

pub struct FeatureExtractor {
    config: Arc<Config>,
}

impl FeatureExtractor {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
    
    pub async fn extract_features(&self, events: &[DataEvent]) -> Result<Array2<f64>> {
        let mut features = Vec::new();
        
        for event in events {
            let feature_vector = match &event.data {
                crate::collectors::EventData::Process { pid, name, cmd, parent_pid, user, path, cmdline } => {
                    self.extract_process_features(pid, name, cmd, parent_pid, user, path, cmdline)
                },
                crate::collectors::EventData::Network { src_ip, dst_ip, src_port, dst_port, protocol, packet_size, flags } => {
                    self.extract_network_features(src_ip, dst_ip, src_port, dst_port, protocol, packet_size, flags)
                },
                crate::collectors::EventData::File { path, operation, process_id, user } => {
                    self.extract_file_features(path, operation, process_id, user)
                },
                crate::collectors::EventData::Gpu { process_id, gpu_usage, memory_usage, temperature } => {
                    self.extract_gpu_features(process_id, gpu_usage, memory_usage, temperature)
                },
                _ => {
                    // Default feature vector for unknown event types
                    vec![0.0; self.config.ml.input_dim]
                }
            };
            
            features.push(feature_vector);
        }
        
        // Convert to Array2
        let n_samples = features.len();
        let n_features = self.config.ml.input_dim;
        let mut array = Array2::zeros((n_samples, n_features));
        
        for (i, feature_vec) in features.into_iter().enumerate() {
            for (j, val) in feature_vec.into_iter().enumerate() {
                if j < n_features {
                    array[[i, j]] = val;
                }
            }
        }
        
        Ok(array)
    }
    
    fn extract_process_features(&self, pid: &u32, name: &str, cmd: &[String], parent_pid: &u32, user: &str, path: &str, cmdline: &str) -> Vec<f64> {
        let mut features = Vec::with_capacity(self.config.ml.input_dim);
        
        // PID (normalized)
        features.push(*pid as f64 / 10000.0);
        
        // Process name hash (normalized)
        let name_hash = self.hash_string(name);
        features.push(name_hash as f64 / u32::MAX as f64);
        
        // Command line length
        features.push(cmdline.len() as f64 / 1000.0);
        
        // Parent PID (normalized)
        features.push(*parent_pid as f64 / 10000.0);
        
        // User hash (normalized)
        let user_hash = self.hash_string(user);
        features.push(user_hash as f64 / u32::MAX as f64);
        
        // Path length
        features.push(path.len() as f64 / 1000.0);
        
        // Suspicious flags (binary features)
        features.push(self.is_suspicious_process(name) as u8 as f64);
        features.push(self.has_suspicious_args(cmdline) as u8 as f64);
        
        // Fill remaining features with zeros
        while features.len() < self.config.ml.input_dim {
            features.push(0.0);
        }
        
        features
    }
    
    fn extract_network_features(&self, src_ip: &str, dst_ip: &str, src_port: &u16, dst_port: &u16, protocol: &str, packet_size: &u32, flags: &str) -> Vec<f64> {
        let mut features = Vec::with_capacity(self.config.ml.input_dim);
        
        // Source IP hash (normalized)
        let src_ip_hash = self.hash_string(src_ip);
        features.push(src_ip_hash as f64 / u32::MAX as f64);
        
        // Destination IP hash (normalized)
        let dst_ip_hash = self.hash_string(dst_ip);
        features.push(dst_ip_hash as f64 / u32::MAX as f64);
        
        // Source port (normalized)
        features.push(*src_port as f64 / 65535.0);
        
        // Destination port (normalized)
        features.push(*dst_port as f64 / 65535.0);
        
        // Protocol (one-hot encoded)
        match protocol {
            "TCP" => {
                features.push(1.0);
                features.push(0.0);
                features.push(0.0);
            },
            "UDP" => {
                features.push(0.0);
                features.push(1.0);
                features.push(0.0);
            },
            "ICMP" => {
                features.push(0.0);
                features.push(0.0);
                features.push(1.0);
            },
            _ => {
                features.push(0.0);
                features.push(0.0);
                features.push(0.0);
            }
        }
        
        // Packet size (normalized)
        features.push(*packet_size as f64 / 1000000.0);
        
        // Flags (binary features)
        features.push(flags.contains("SYN") as u8 as f64);
        features.push(flags.contains("ACK") as u8 as f64);
        features.push(flags.contains("FIN") as u8 as f64);
        features.push(flags.contains("RST") as u8 as f64);
        
        // Fill remaining features with zeros
        while features.len() < self.config.ml.input_dim {
            features.push(0.0);
        }
        
        features
    }
    
    fn extract_file_features(&self, path: &str, operation: &str, process_id: &u32, user: &str) -> Vec<f64> {
        let mut features = Vec::with_capacity(self.config.ml.input_dim);
        
        // Path hash (normalized)
        let path_hash = self.hash_string(path);
        features.push(path_hash as f64 / u32::MAX as f64);
        
        // Operation (one-hot encoded)
        match operation {
            "create" => {
                features.push(1.0);
                features.push(0.0);
                features.push(0.0);
                features.push(0.0);
            },
            "modify" => {
                features.push(0.0);
                features.push(1.0);
                features.push(0.0);
                features.push(0.0);
            },
            "delete" => {
                features.push(0.0);
                features.push(0.0);
                features.push(1.0);
                features.push(0.0);
            },
            "read" => {
                features.push(0.0);
                features.push(0.0);
                features.push(0.0);
                features.push(1.0);
            },
            _ => {
                features.push(0.0);
                features.push(0.0);
                features.push(0.0);
                features.push(0.0);
            }
        }
        
        // Process ID (normalized)
        features.push(*process_id as f64 / 10000.0);
        
        // User hash (normalized)
        let user_hash = self.hash_string(user);
        features.push(user_hash as f64 / u32::MAX as f64);
        
        // File extension (binary features)
        let extension = std::path::Path::new(path)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");
        
        features.push(self.is_executable_extension(extension) as u8 as f64);
        features.push(self.is_script_extension(extension) as u8 as f64);
        features.push(self.is_document_extension(extension) as u8 as f64);
        
        // Fill remaining features with zeros
        while features.len() < self.config.ml.input_dim {
            features.push(0.0);
        }
        
        features
    }
    
    fn extract_gpu_features(&self, process_id: &u32, gpu_usage: &f32, memory_usage: &f32, temperature: &f32) -> Vec<f64> {
        let mut features = Vec::with_capacity(self.config.ml.input_dim);
        
        // Process ID (normalized)
        features.push(*process_id as f64 / 10000.0);
        
        // GPU usage (percentage)
        features.push(*gpu_usage as f64 / 100.0);
        
        // Memory usage (percentage)
        features.push(*memory_usage as f64 / 100.0);
        
        // Temperature (normalized)
        features.push(*temperature as f64 / 100.0);
        
        // Fill remaining features with zeros
        while features.len() < self.config.ml.input_dim {
            features.push(0.0);
        }
        
        features
    }
    
    fn hash_string(&self, s: &str) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish() as u32
    }
    
    fn is_suspicious_process(&self, name: &str) -> bool {
        let suspicious_processes = [
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe"
        ];
        
        suspicious_processes.contains(&name.to_lowercase().as_str())
    }
    
    fn has_suspicious_args(&self, cmdline: &str) -> bool {
        let suspicious_args = [
            "-enc", "-nop", "-w hidden", "bypass", "downloadstring", "iex",
            "reg add", "reg delete", "net user", "net localgroup"
        ];
        
        let cmdline_lower = cmdline.to_lowercase();
        suspicious_args.iter().any(|&arg| cmdline_lower.contains(arg))
    }
    
    fn is_executable_extension(&self, ext: &str) -> bool {
        let executable_extensions = ["exe", "dll", "sys", "scr", "com", "pif"];
        executable_extensions.contains(&ext.to_lowercase().as_str())
    }
    
    fn is_script_extension(&self, ext: &str) -> bool {
        let script_extensions = ["ps1", "vbs", "js", "bat", "cmd", "sh", "py"];
        script_extensions.contains(&ext.to_lowercase().as_str())
    }
    
    fn is_document_extension(&self, ext: &str) -> bool {
        let document_extensions = ["doc", "docx", "pdf", "txt", "rtf", "odt"];
        document_extensions.contains(&ext.to_lowercase().as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResult {
    pub event_id: String,
    pub anomaly_score: f64,
    pub is_anomaly: bool,
    pub cluster_id: usize,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}