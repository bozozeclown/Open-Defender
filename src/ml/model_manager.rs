// src/ml/model_manager.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use linfa::Dataset;
use linfa_clustering::{KMeans, KMeansHyperParams};
use ndarray::{Array2, Array3, ArrayView1, ArrayView2};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tch::{nn, nn::ModuleT, Device, Tensor, Kind};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::collectors::DataEvent;
use crate::config::MlConfig;
use crate::utils::database::DatabaseManager;

pub struct ModelManager {
    config: MlConfig,
    db: DatabaseManager,
    models: HashMap<String, Box<dyn MLModel>>,
    feature_extractor: FeatureExtractor,
    model_metrics: ModelMetrics,
}

pub trait MLModel: Send + Sync {
    fn train(&mut self, data: &Array2<f64>) -> Result<()>;
    fn predict(&self, data: &Array2<f64>) -> Result<Array1<f64>>;
    fn save(&self, path: &Path) -> Result<()>;
    fn load(&mut self, path: &Path) -> Result<()>;
    fn get_metrics(&self) -> ModelMetrics;
}

pub struct AutoencoderModel {
    var_store: nn::VarStore,
    encoder: nn::Sequential,
    decoder: nn::Sequential,
    device: Device,
    input_dim: usize,
    latent_dim: usize,
    training_history: Vec<TrainingEpoch>,
}

pub struct TransformerModel {
    // Implementation for transformer-based model
}

pub struct IsolationForestModel {
    // Implementation for isolation forest model
}

pub struct FeatureExtractor {
    feature_maps: HashMap<String, Box<dyn FeatureMap>>,
}

pub trait FeatureMap: Send + Sync {
    fn extract(&self, event: &DataEvent) -> Result<Array2<f64>>;
    fn get_feature_names(&self) -> Vec<String>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetrics {
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub auc_roc: f64,
    pub last_trained: DateTime<Utc>,
    pub training_samples: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingEpoch {
    pub epoch: usize,
    pub loss: f64,
    pub timestamp: DateTime<Utc>,
}

impl ModelManager {
    pub async fn new(config: &MlConfig, db: DatabaseManager) -> Result<Self> {
        let mut models = HashMap::new();
        
        // Initialize autoencoder
        let autoencoder = Self::initialize_autoencoder(config)?;
        models.insert("autoencoder".to_string(), Box::new(autoencoder));
        
        // Initialize isolation forest
        let isolation_forest = Self::initialize_isolation_forest(config)?;
        models.insert("isolation_forest".to_string(), Box::new(isolation_forest));
        
        // Initialize feature extractor
        let feature_extractor = Self::initialize_feature_extractor(config)?;
        
        Ok(Self {
            config: config.clone(),
            db,
            models,
            feature_extractor,
            model_metrics: ModelMetrics {
                accuracy: 0.0,
                precision: 0.0,
                recall: 0.0,
                f1_score: 0.0,
                auc_roc: 0.0,
                last_trained: Utc::now(),
                training_samples: 0,
            },
        })
    }

    fn initialize_autoencoder(config: &MlConfig) -> Result<AutoencoderModel> {
        let device = Device::Cpu;
        let vs = nn::VarStore::new(device);
        
        let latent_dim = config.input_dim / 2;
        
        let encoder = nn::seq()
            .add(nn::linear(&vs / "encoder_l1", config.input_dim as i64, 64, Default::default()))
            .add_fn(|x| x.relu())
            .add(nn::linear(&vs / "encoder_l2", 64, 32, Default::default()))
            .add_fn(|x| x.relu())
            .add(nn::linear(&vs / "encoder_l3", 32, latent_dim as i64, Default::default()));

        let decoder = nn::seq()
            .add(nn::linear(&vs / "decoder_l1", latent_dim as i64, 32, Default::default()))
            .add_fn(|x| x.relu())
            .add(nn::linear(&vs / "decoder_l2", 32, 64, Default::default()))
            .add_fn(|x| x.relu())
            .add(nn::linear(&vs / "decoder_l3", 64, config.input_dim as i64, Default::default()));

        Ok(AutoencoderModel {
            var_store: vs,
            encoder,
            decoder,
            device,
            input_dim: config.input_dim,
            latent_dim,
            training_history: Vec::new(),
        })
    }

    fn initialize_isolation_forest(config: &MlConfig) -> Result<IsolationForestModel> {
        // Implementation for isolation forest initialization
        Ok(IsolationForestModel {})
    }

    fn initialize_feature_extractor(config: &MlConfig) -> Result<FeatureExtractor> {
        let mut feature_maps = HashMap::new();
        
        // Add process feature map
        feature_maps.insert("process".to_string(), Box::new(ProcessFeatureMap::new(config.input_dim)));
        
        // Add network feature map
        feature_maps.insert("network".to_string(), Box::new(NetworkFeatureMap::new(config.input_dim)));
        
        // Add file feature map
        feature_maps.insert("file".to_string(), Box::new(FileFeatureMap::new(config.input_dim)));
        
        // Add GPU feature map
        feature_maps.insert("gpu".to_string(), Box::new(GpuFeatureMap::new(config.input_dim)));
        
        Ok(FeatureExtractor { feature_maps })
    }

    pub async fn process_event(&mut self, event: DataEvent) -> Result<Option<f64>> {
        // Extract features
        let features = self.feature_extractor.extract(&event).await?;
        
        // Get predictions from all models
        let mut predictions = Vec::new();
        for (name, model) in &mut self.models {
            match model.predict(&features) {
                Ok(pred) => {
                    predictions.push((name.clone(), pred[0]));
                }
                Err(e) => {
                    warn!("Model {} prediction failed: {}", name, e);
                }
            }
        }
        
        // Ensemble prediction (simple average)
        if !predictions.is_empty() {
            let ensemble_score = predictions.iter().map(|(_, score)| score).sum::<f64>() / predictions.len() as f64;
            
            // Check if it's an anomaly
            if ensemble_score > self.config.anomaly_threshold {
                // Store anomaly in database
                self.db.store_anomaly(&event, ensemble_score).await?;
                
                // Update model metrics
                self.update_metrics(&event, ensemble_score).await?;
                
                return Ok(Some(ensemble_score));
            }
        }
        
        Ok(None)
    }

    pub async fn train_models(&mut self) -> Result<()> {
        info!("Training ML models");
        
        // Get training data from database
        let training_data = self.db.get_training_data(self.config.min_features_train).await?;
        
        if training_data.is_empty() {
            info!("Not enough training data");
            return Ok(());
        }
        
        // Extract features for all events
        let mut feature_matrix = Array2::zeros((training_data.len(), self.config.input_dim));
        
        for (i, event) in training_data.iter().enumerate() {
            let features = self.feature_extractor.extract(event).await?;
            feature_matrix.row_mut(i).assign(&features.row(0));
        }
        
        // Train each model
        for (name, model) in &mut self.models {
            info!("Training model: {}", name);
            if let Err(e) = model.train(&feature_matrix) {
                error!("Failed to train model {}: {}", name, e);
            }
        }
        
        // Update metrics
        self.model_metrics.last_trained = Utc::now();
        self.model_metrics.training_samples = training_data.len();
        
        info!("Model training completed");
        Ok(())
    }

    pub async fn update_metrics(&mut self, event: &DataEvent, score: f64) -> Result<()> {
        // Update model metrics based on new anomaly
        // This would typically involve comparing with ground truth labels
        // For now, we'll just update the timestamp
        self.model_metrics.last_trained = Utc::now();
        Ok(())
    }

    pub async fn save_models(&self) -> Result<()> {
        let model_dir = Path::new(&self.config.model_path).parent().unwrap();
        std::fs::create_dir_all(model_dir)?;
        
        for (name, model) in &self.models {
            let model_path = model_dir.join(format!("{}.pt", name));
            model.save(&model_path)?;
        }
        
        info!("Models saved to {}", model_dir.display());
        Ok(())
    }

    pub async fn load_models(&mut self) -> Result<()> {
        let model_dir = Path::new(&self.config.model_path).parent().unwrap();
        
        for (name, model) in &mut self.models {
            let model_path = model_dir.join(format!("{}.pt", name));
            if model_path.exists() {
                model.load(&model_path)?;
                info!("Loaded model: {}", name);
            }
        }
        
        Ok(())
    }
}

impl MLModel for AutoencoderModel {
    fn train(&mut self, data: &Array2<f64>) -> Result<()> {
        let device = self.device;
        
        // Convert to tensor
        let xs = Tensor::from_slice(
            data.as_slice().unwrap(),
            &[data.nrows() as i64, data.ncols() as i64],
            device,
        );

        // Training loop
        let mut opt = nn::Adam::default().build(&self.var_store, 1e-3)?;
        
        for epoch in 1..=10 {
            let loss = self.forward(&xs);
            opt.backward_step(&loss);
            
            let loss_value = f64::from(loss);
            self.training_history.push(TrainingEpoch {
                epoch,
                loss: loss_value,
                timestamp: Utc::now(),
            });
            
            if epoch % 10 == 0 {
                info!("Autoencoder Epoch: {}, Loss: {:.6}", epoch, loss_value);
            }
        }
        
        Ok(())
    }

    fn predict(&self, data: &Array2<f64>) -> Result<Array1<f64>> {
        let device = self.device;
        
        // Convert to tensor
        let xs = Tensor::from_slice(
            data.as_slice().unwrap(),
            &[data.nrows() as i64, data.ncols() as i64],
            device,
        );

        // Forward pass
        let reconstructed = self.forward(&xs);
        let mse = (xs - reconstructed).pow(2).mean_dim([1], false, Kind::Float);
        
        // Convert back to ndarray
        let mse_vec = mse.into_vec();
        Ok(Array1::from_vec(mse_vec))
    }

    fn save(&self, path: &Path) -> Result<()> {
        self.var_store.save(path)?;
        Ok(())
    }

    fn load(&mut self, path: &Path) -> Result<()> {
        self.var_store.load(path)?;
        Ok(())
    }

    fn get_metrics(&self) -> ModelMetrics {
        ModelMetrics {
            accuracy: 0.0,
            precision: 0.0,
            recall: 0.0,
            f1_score: 0.0,
            auc_roc: 0.0,
            last_trained: Utc::now(),
            training_samples: 0,
        }
    }
}

impl AutoencoderModel {
    fn forward(&self, xs: &Tensor) -> Tensor {
        let encoded = self.encoder.forward(xs);
        self.decoder.forward(&encoded)
    }
}

impl MLModel for IsolationForestModel {
    fn train(&mut self, _data: &Array2<f64>) -> Result<()> {
        // Implementation for isolation forest training
        Ok(())
    }

    fn predict(&self, _data: &Array2<f64>) -> Result<Array1<f64>> {
        // Implementation for isolation forest prediction
        Ok(Array1::zeros(_data.nrows()))
    }

    fn save(&self, _path: &Path) -> Result<()> {
        // Implementation for isolation forest saving
        Ok(())
    }

    fn load(&mut self, _path: &Path) -> Result<()> {
        // Implementation for isolation forest loading
        Ok(())
    }

    fn get_metrics(&self) -> ModelMetrics {
        ModelMetrics {
            accuracy: 0.0,
            precision: 0.0,
            recall: 0.0,
            f1_score: 0.0,
            auc_roc: 0.0,
            last_trained: Utc::now(),
            training_samples: 0,
        }
    }
}

impl FeatureExtractor {
    async fn extract(&self, event: &DataEvent) -> Result<Array2<f64>> {
        if let Some(feature_map) = self.feature_maps.get(&event.event_type) {
            feature_map.extract(event)
        } else {
            Err(anyhow::anyhow!("No feature map for event type: {}", event.event_type))
        }
    }
}

pub struct ProcessFeatureMap {
    input_dim: usize,
}

impl ProcessFeatureMap {
    pub fn new(input_dim: usize) -> Self {
        Self { input_dim }
    }
}

impl FeatureMap for ProcessFeatureMap {
    fn extract(&self, event: &DataEvent) -> Result<Array2<f64>> {
        if let crate::collectors::EventData::Process {
            pid,
            name,
            cmd,
            cwd,
            parent_pid,
            start_time,
            cpu_usage,
            memory_usage,
            virtual_memory,
        } = &event.data
        {
            let mut features = Vec::with_capacity(self.input_dim);
            
            // Basic features
            features.push(*pid as f64);
            features.push(parent_pid.unwrap_or(0) as f64);
            features.push(*start_time as f64);
            features.push(*cpu_usage as f64);
            features.push(*memory_usage as f64);
            features.push(*virtual_memory as f64);
            
            // Command line features
            let cmd_str = cmd.join(" ");
            features.push(cmd_str.len() as f64);
            features.push(cmd_str.matches(' ').count() as f64);
            
            // Path features
            features.push(cwd.len() as f64);
            features.push(cwd.matches('/').count() as f64);
            
            // Process name features
            features.push(name.len() as f64);
            features.push(name.chars().filter(|c| c.is_alphabetic()).count() as f64);
            
            // Advanced features
            features.push(self.calculate_entropy(name));
            features.push(self.calculate_entropy(&cmd_str));
            
            // Pad to required input dimension
            while features.len() < self.input_dim {
                features.push(0.0);
            }
            
            // Truncate if too long
            features.truncate(self.input_dim);
            
            Ok(Array2::from_shape_vec((1, self.input_dim), features)?)
        } else {
            Err(anyhow::anyhow!("Invalid process event data"))
        }
    }

    fn get_feature_names(&self) -> Vec<String> {
        vec![
            "pid".to_string(),
            "parent_pid".to_string(),
            "start_time".to_string(),
            "cpu_usage".to_string(),
            "memory_usage".to_string(),
            "virtual_memory".to_string(),
            "cmd_length".to_string(),
            "cmd_args_count".to_string(),
            "cwd_length".to_string(),
            "cwd_depth".to_string(),
            "name_length".to_string(),
            "name_alpha_count".to_string(),
            "name_entropy".to_string(),
            "cmd_entropy".to_string(),
        ]
    }

    fn calculate_entropy(&self, s: &str) -> f64 {
        let mut counts = [0u32; 256];
        for &b in s.as_bytes() {
            counts[b as usize] += 1;
        }
        
        let len = s.len() as f64;
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
}

pub struct NetworkFeatureMap {
    input_dim: usize,
}

impl NetworkFeatureMap {
    pub fn new(input_dim: usize) -> Self {
        Self { input_dim }
    }
}

impl FeatureMap for NetworkFeatureMap {
    fn extract(&self, event: &DataEvent) -> Result<Array2<f64>> {
        if let crate::collectors::EventData::Network {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
            packet_size,
            flags,
        } = &event.data
        {
            let mut features = Vec::with_capacity(self.input_dim);
            
            // IP features
            features.push(Self::ip_to_numeric(src_ip)?);
            features.push(Self::ip_to_numeric(dst_ip)?);
            
            // Port features
            features.push(*src_port as f64);
            features.push(*dst_port as f64);
            
            // Protocol features
            features.push(match protocol.as_str() {
                "TCP" => 1.0,
                "UDP" => 2.0,
                "ICMP" => 3.0,
                _ => 0.0,
            });
            
            // Size features
            features.push(*packet_size as f64);
            features.push((*packet_size as f64).log2());
            
            // Flag features
            features.push(flags.len() as f64);
            features.push(flags.matches('S').count() as f64); // SYN
            features.push(flags.matches('A').count() as f64); // ACK
            features.push(flags.matches('F').count() as f64); // FIN
            features.push(flags.matches('R').count() as f64); // RST
            features.push(flags.matches('P').count() as f64); // PSH
            features.push(flags.matches('U').count() as f64); // URG
            
            // Port category features
            features.push(Self::categorize_port(*src_port));
            features.push(Self::categorize_port(*dst_port));
            
            // IP entropy
            features.push(Self::calculate_ip_entropy(src_ip));
            features.push(Self::calculate_ip_entropy(dst_ip));
            
            // Pad to required input dimension
            while features.len() < self.input_dim {
                features.push(0.0);
            }
            
            // Truncate if too long
            features.truncate(self.input_dim);
            
            Ok(Array2::from_shape_vec((1, self.input_dim), features)?)
        } else {
            Err(anyhow::anyhow!("Invalid network event data"))
        }
    }

    fn get_feature_names(&self) -> Vec<String> {
        vec![
            "src_ip".to_string(),
            "dst_ip".to_string(),
            "src_port".to_string(),
            "dst_port".to_string(),
            "protocol".to_string(),
            "packet_size".to_string(),
            "packet_size_log".to_string(),
            "flags_count".to_string(),
            "syn_flags".to_string(),
            "ack_flags".to_string(),
            "fin_flags".to_string(),
            "rst_flags".to_string(),
            "psh_flags".to_string(),
            "urg_flags".to_string(),
            "src_port_category".to_string(),
            "dst_port_category".to_string(),
            "src_ip_entropy".to_string(),
            "dst_ip_entropy".to_string(),
        ]
    }

    fn ip_to_numeric(ip: &str) -> Result<f64> {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return Err(anyhow::anyhow!("Invalid IP address"));
        }
        
        let mut result = 0.0;
        for (i, part) in parts.iter().enumerate() {
            let octet = part.parse::<u8>()?;
            result += (octet as f64) * 256.0f64.powi(3 - i as i32);
        }
        
        Ok(result)
    }

    fn categorize_port(port: u16) -> f64 {
        match port {
            0..=1023 => 1.0, // Well-known ports
            1024..=49151 => 2.0, // Registered ports
            49152..=65535 => 3.0, // Dynamic/private ports
        }
    }

    fn calculate_ip_entropy(ip: &str) -> f64 {
        let bytes: Vec<u8> = ip.split('.')
            .filter_map(|s| s.parse::<u8>().ok())
            .collect();
        
        let mut counts = [0u32; 256];
        for &b in &bytes {
            counts[b as usize] += 1;
        }
        
        let len = bytes.len() as f64;
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
}

pub struct FileFeatureMap {
    input_dim: usize,
}

impl FileFeatureMap {
    pub fn new(input_dim: usize) -> Self {
        Self { input_dim }
    }
}

impl FeatureMap for FileFeatureMap {
    fn extract(&self, event: &DataEvent) -> Result<Array2<f64>> {
        if let crate::collectors::EventData::File {
            path,
            operation,
            size,
            process_id,
            hash,
        } = &event.data
        {
            let mut features = Vec::with_capacity(self.input_dim);
            
            // Path features
            features.push(path.len() as f64);
            features.push(path.matches('/').count() as f64);
            features.push(path.matches('.').count() as f64);
            features.push(path.matches('\\').count() as f64);
            
            // Operation features
            features.push(match operation.as_str() {
                "create" => 1.0,
                "modify" => 2.0,
                "delete" => 3.0,
                "access" => 4.0,
                "rename" => 5.0,
                _ => 0.0,
            });
            
            // Size features
            features.push(*size as f64);
            features.push((*size as f64).log2().max(0.0));
            
            // Process features
            features.push(*process_id as f64);
            
            // Hash features
            if let Some(hash_str) = hash {
                features.push(hash_str.len() as f64);
                features.push(hash_str.chars().filter(|c| c.is_digit(16)).count() as f64);
                features.push(Self::calculate_hash_entropy(hash_str));
            } else {
                features.push(0.0);
                features.push(0.0);
                features.push(0.0);
            }
            
            // File extension features
            if let Some(ext) = path.split('.').last() {
                features.push(ext.len() as f64);
                features.push(ext.chars().filter(|c| c.is_alphabetic()).count() as f64);
                features.push(Self::calculate_extension_risk(ext));
            } else {
                features.push(0.0);
                features.push(0.0);
                features.push(0.0);
            }
            
            // Path depth
            features.push(path.split('/').count() as f64);
            
            // Filename features
            if let Some(filename) = path.split('/').last() {
                features.push(filename.len() as f64);
                features.push(Self::calculate_entropy(filename));
            } else {
                features.push(0.0);
                features.push(0.0);
            }
            
            // Pad to required input dimension
            while features.len() < self.input_dim {
                features.push(0.0);
            }
            
            // Truncate if too long
            features.truncate(self.input_dim);
            
            Ok(Array2::from_shape_vec((1, self.input_dim), features)?)
        } else {
            Err(anyhow::anyhow!("Invalid file event data"))
        }
    }

    fn get_feature_names(&self) -> Vec<String> {
        vec![
            "path_length".to_string(),
            "path_depth".to_string(),
            "path_dots".to_string(),
            "path_backslashes".to_string(),
            "operation".to_string(),
            "file_size".to_string(),
            "file_size_log".to_string(),
            "process_id".to_string(),
            "hash_length".to_string(),
            "hash_hex_chars".to_string(),
            "hash_entropy".to_string(),
            "ext_length".to_string(),
            "ext_alpha_chars".to_string(),
            "ext_risk".to_string(),
            "path_depth_count".to_string(),
            "filename_length".to_string(),
            "filename_entropy".to_string(),
        ]
    }

    fn calculate_hash_entropy(hash: &str) -> f64 {
        let mut counts = [0u32; 256];
        for &b in hash.as_bytes() {
            counts[b as usize] += 1;
        }
        
        let len = hash.len() as f64;
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }

    fn calculate_extension_risk(ext: &str) -> f64 {
        match ext.to_lowercase().as_str() {
            "exe" | "dll" | "sys" | "com" | "scr" | "bat" | "cmd" | "pif" => 1.0,
            "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "pdf" => 0.8,
            "js" | "vbs" | "ps1" | "py" | "sh" => 0.9,
            "zip" | "rar" | "7z" | "tar" | "gz" => 0.7,
            "txt" | "log" | "ini" | "cfg" => 0.3,
            _ => 0.5,
        }
    }

    fn calculate_entropy(s: &str) -> f64 {
        let mut counts = [0u32; 256];
        for &b in s.as_bytes() {
            counts[b as usize] += 1;
        }
        
        let len = s.len() as f64;
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
}

pub struct GpuFeatureMap {
    input_dim: usize,
}

impl GpuFeatureMap {
    pub fn new(input_dim: usize) -> Self {
        Self { input_dim }
    }
}

impl FeatureMap for GpuFeatureMap {
    fn extract(&self, event: &DataEvent) -> Result<Array2<f64>> {
        if let crate::collectors::EventData::Gpu {
            process_id,
            gpu_id,
            memory_usage,
            utilization,
            temperature,
        } = &event.data
        {
            let mut features = Vec::with_capacity(self.input_dim);
            
            // Basic features
            features.push(*process_id as f64);
            features.push(*gpu_id as f64);
            features.push(*memory_usage as f64);
            features.push(*utilization);
            features.push(*temperature);
            
            // Derived features
            features.push((*memory_usage as f64).log2().max(0.0));
            features.push(*utilization / 100.0);
            features.push((*temperature - 30.0) / 70.0); // Normalized temperature
            
            // Pad to required input dimension
            while features.len() < self.input_dim {
                features.push(0.0);
            }
            
            // Truncate if too long
            features.truncate(self.input_dim);
            
            Ok(Array2::from_shape_vec((1, self.input_dim), features)?)
        } else {
            Err(anyhow::anyhow!("Invalid GPU event data"))
        }
    }

    fn get_feature_names(&self) -> Vec<String> {
        vec![
            "process_id".to_string(),
            "gpu_id".to_string(),
            "memory_usage".to_string(),
            "utilization".to_string(),
            "temperature".to_string(),
            "memory_usage_log".to_string(),
            "utilization_pct".to_string(),
            "temperature_norm".to_string(),
        ]
    }
}
