// src/models/detector_model.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use linfa::Dataset;
use linfa_clustering::{KMeans, KMeansHyperParams};
use ndarray::{Array2, Array3, ArrayView1, ArrayView2};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tch::{nn, nn::ModuleT, Device, Tensor, Kind};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::collectors::DataEvent;
use crate::config::MlConfig;
use crate::utils::database::DatabaseManager;

pub struct DetectorModel {
    config: MlConfig,
    db: DatabaseManager,
    autoencoder: Option<Autoencoder>,
    kmeans: Option<KMeans<f64, ndarray::Dim<[usize; 2]>>>,
    feature_cache: Vec<Array2<f64>>,
    is_trained: bool,
}

impl DetectorModel {
    pub async fn new(config: &MlConfig, db: &DatabaseManager) -> Result<Self> {
        let mut model = Self {
            config: config.clone(),
            db: db.clone(),
            autoencoder: None,
            kmeans: None,
            feature_cache: Vec::new(),
            is_trained: false,
        };

        // Load model if it exists
        if Path::new(&config.model_path).exists() {
            model.load_model().await?;
        } else {
            model.initialize_model().await?;
        }

        Ok(model)
    }

    async fn initialize_model(&mut self) -> Result<()> {
        let device = Device::Cpu;
        
        // Initialize autoencoder
        let vs = nn::VarStore::new(device);
        let autoencoder = Autoencoder::new(&vs.root(), self.config.input_dim);
        self.autoencoder = Some(autoencoder);

        // Initialize KMeans clustering
        let hyperparams = KMeansHyperParams::new()
            .n_clusters(self.config.input_dim)
            .max_n_iterations(self.config.epochs as usize)
            .tolerance(self.config.anomaly_threshold);

        self.kmeans = Some(KMeans::new(hyperparams));

        info!("Model initialized");
        Ok(())
    }

    async fn load_model(&mut self) -> Result<()> {
        let device = Device::Cpu;
        
        // Load autoencoder
        let vs = nn::VarStore::new(device);
        vs.load(&self.config.model_path)
            .context("Failed to load model weights")?;
        let autoencoder = Autoencoder::new(&vs.root(), self.config.input_dim);
        self.autoencoder = Some(autoencoder);

        // Initialize KMeans clustering
        let hyperparams = KMeansHyperParams::new()
            .n_clusters(self.config.input_dim)
            .max_n_iterations(self.config.epochs as usize)
            .tolerance(self.config.anomaly_threshold);

        self.kmeans = Some(KMeans::new(hyperparams));
        self.is_trained = true;

        info!("Model loaded successfully");
        Ok(())
    }

    pub async fn save_model(&self) -> Result<()> {
        if let Some(ref autoencoder) = self.autoencoder {
            autoencoder.var_store.save(&self.config.model_path)
                .context("Failed to save model")?;
            info!("Model saved to {}", self.config.model_path);
        }
        Ok(())
    }

    pub async fn process_event(&mut self, event: DataEvent) -> Result<()> {
        // Extract features from event
        let features = self.extract_features(&event).await?;

        // Add to feature cache
        self.feature_cache.push(features);

        // If we have enough features, train the model
        if !self.is_trained && self.feature_cache.len() >= self.config.min_features_train {
            self.train_model().await?;
        }

        // If model is trained, detect anomalies
        if self.is_trained {
            let anomaly_score = self.detect_anomaly(&features).await?;
            
            if anomaly_score > self.config.anomaly_threshold {
                warn!("Anomaly detected with score: {}", anomaly_score);
                self.handle_anomaly(event, anomaly_score).await?;
            }
        }

        Ok(())
    }

    async fn extract_features(&self, event: &DataEvent) -> Result<Array2<f64>> {
        // Extract features based on event type
        match event.event_type.as_str() {
            "process" => self.extract_process_features(event).await,
            "network" => self.extract_network_features(event).await,
            "file" => self.extract_file_features(event).await,
            "gpu" => self.extract_gpu_features(event).await,
            _ => Err(anyhow::anyhow!("Unknown event type: {}", event.event_type)),
        }
    }

    async fn extract_process_features(&self, event: &DataEvent) -> Result<Array2<f64>> {
        if let EventData::Process {
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
            // Create feature vector from process data
            let mut features = Vec::with_capacity(self.config.input_dim);
            
            // Basic features
            features.push(*pid as f64);
            features.push(parent_pid.unwrap_or(0) as f64);
            features.push(*start_time as f64);
            features.push(*cpu_usage as f64);
            features.push(*memory_usage as f64);
            features.push(*virtual_memory as f64);
            
            // Command line features (simplified)
            let cmd_str = cmd.join(" ");
            features.push(cmd_str.len() as f64);
            features.push(cmd_str.matches(' ').count() as f64);
            
            // Path features
            features.push(cwd.len() as f64);
            features.push(cwd.matches('/').count() as f64);
            
            // Process name features
            features.push(name.len() as f64);
            features.push(name.chars().filter(|c| c.is_alphabetic()).count() as f64);
            
            // Pad to required input dimension
            while features.len() < self.config.input_dim {
                features.push(0.0);
            }
            
            // Truncate if too long
            features.truncate(self.config.input_dim);
            
            Ok(Array2::from_shape_vec((1, self.config.input_dim), features)?)
        } else {
            Err(anyhow::anyhow!("Invalid process event data"))
        }
    }

    async fn extract_network_features(&self, event: &DataEvent) -> Result<Array2<f64>> {
        if let EventData::Network {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
            packet_size,
            flags,
        } = &event.data
        {
            let mut features = Vec::with_capacity(self.config.input_dim);
            
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
                _ => 0.0,
            });
            
            // Size features
            features.push(*packet_size as f64);
            
            // Flag features (simplified)
            features.push(flags.len() as f64);
            features.push(flags.matches('S').count() as f64); // SYN
            features.push(flags.matches('A').count() as f64); // ACK
            features.push(flags.matches('F').count() as f64); // FIN
            features.push(flags.matches('R').count() as f64); // RST
            
            // Pad to required input dimension
            while features.len() < self.config.input_dim {
                features.push(0.0);
            }
            
            // Truncate if too long
            features.truncate(self.config.input_dim);
            
            Ok(Array2::from_shape_vec((1, self.config.input_dim), features)?)
        } else {
            Err(anyhow::anyhow!("Invalid network event data"))
        }
    }

    async fn extract_file_features(&self, event: &DataEvent) -> Result<Array2<f64>> {
        if let EventData::File {
            path,
            operation,
            size,
            process_id,
            hash,
        } = &event.data
        {
            let mut features = Vec::with_capacity(self.config.input_dim);
            
            // Path features
            features.push(path.len() as f64);
            features.push(path.matches('/').count() as f64);
            features.push(path.matches('.').count() as f64);
            
            // Operation features
            features.push(match operation.as_str() {
                "create" => 1.0,
                "modify" => 2.0,
                "delete" => 3.0,
                "access" => 4.0,
                _ => 0.0,
            });
            
            // Size features
            features.push(*size as f64);
            features.push((*size as f64).log2());
            
            // Process features
            features.push(*process_id as f64);
            
            // Hash features (if available)
            if let Some(hash_str) = hash {
                features.push(hash_str.len() as f64);
                features.push(hash_str.chars().filter(|c| c.is_digit(16)).count() as f64);
            } else {
                features.push(0.0);
                features.push(0.0);
            }
            
            // File extension features
            if let Some(ext) = path.split('.').last() {
                features.push(ext.len() as f64);
                features.push(ext.chars().filter(|c| c.is_alphabetic()).count() as f64);
            } else {
                features.push(0.0);
                features.push(0.0);
            }
            
            // Pad to required input dimension
            while features.len() < self.config.input_dim {
                features.push(0.0);
            }
            
            // Truncate if too long
            features.truncate(self.config.input_dim);
            
            Ok(Array2::from_shape_vec((1, self.config.input_dim), features)?)
        } else {
            Err(anyhow::anyhow!("Invalid file event data"))
        }
    }

    async fn extract_gpu_features(&self, event: &DataEvent) -> Result<Array2<f64>> {
        // Implementation for GPU feature extraction
        Ok(Array2::zeros((1, self.config.input_dim)))
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

    async fn train_model(&mut self) -> Result<()> {
        if self.feature_cache.is_empty() {
            return Ok(());
        }

        // Combine features into a dataset
        let features = Array2::from_shape_vec(
            (self.feature_cache.len(), self.config.input_dim),
            self.feature_cache.iter().flat_map(|f| f.iter().cloned()).collect(),
        )?;

        let dataset = Dataset::from(features);

        // Train KMeans clustering
        if let Some(ref mut kmeans) = self.kmeans {
            kmeans.fit(&dataset)?;
            info!("KMeans model trained with {} samples", dataset.nsamples());
        }

        // Train autoencoder
        if let Some(ref mut autoencoder) = self.autoencoder {
            let device = Device::Cpu;
            
            // Convert features to tensor
            let xs = Tensor::from_slice(
                &features.as_slice().unwrap(),
                &[features.nrows() as i64, features.ncols() as i64],
                device,
            );

            // Training loop
            let mut opt = nn::Adam::default().build(&autoencoder.var_store, 1e-3)?;
            
            for epoch in 1..=self.config.epochs {
                let loss = autoencoder.forward(&xs);
                opt.backward_step(&loss);
                
                if epoch % 10 == 0 {
                    info!("Epoch: {}, Loss: {:.6}", epoch, f64::from(loss));
                }
            }
            
            info!("Autoencoder model trained");
        }

        // Clear feature cache
        self.feature_cache.clear();
        self.is_trained = true;

        // Save model
        self.save_model().await?;

        Ok(())
    }

    async fn detect_anomaly(&self, features: &Array2<f64>) -> Result<f64> {
        let mut score = 0.0;

        // Calculate reconstruction error using autoencoder
        if let Some(ref autoencoder) = self.autoencoder {
            let device = Device::Cpu;
            
            // Convert features to tensor
            let xs = Tensor::from_slice(
                features.as_slice().unwrap(),
                &[features.nrows() as i64, features.ncols() as i64],
                device,
            );

            // Forward pass
            let reconstructed = autoencoder.forward(&xs);
            let mse = (xs - reconstructed).pow(2).mean(Kind::Float);
            score += f64::from(mse);
        }

        // Calculate distance to nearest cluster using KMeans
        if let Some(ref kmeans) = self.kmeans {
            let distances = kmeans.predict(features)?;
            let min_distance = distances.iter().cloned().fold(f64::INFINITY, f64::min);
            score += min_distance;
        }

        // Normalize score
        score /= 2.0;

        Ok(score)
    }

    async fn handle_anomaly(&self, event: DataEvent, score: f64) -> Result<()> {
        // Store anomaly in database
        self.db.store_anomaly(&event, score).await?;

        // Trigger alert if needed
        // This would integrate with the alert system

        Ok(())
    }
}

struct Autoencoder {
    var_store: nn::VarStore,
    encoder: nn::Sequential,
    decoder: nn::Sequential,
}

impl Autoencoder {
    fn new(vs: &nn::Path, input_dim: usize) -> Self {
        let encoder = nn::seq()
            .add(nn::linear(vs / "encoder_l1", input_dim as i64, 32, Default::default()))
            .add_fn(|x| x.relu())
            .add(nn::linear(vs / "encoder_l2", 32, 16, Default::default()))
            .add_fn(|x| x.relu())
            .add(nn::linear(vs / "encoder_l3", 16, 8, Default::default()));

        let decoder = nn::seq()
            .add(nn::linear(vs / "decoder_l1", 8, 16, Default::default()))
            .add_fn(|x| x.relu())
            .add(nn::linear(vs / "decoder_l2", 16, 32, Default::default()))
            .add_fn(|x| x.relu())
            .add(nn::linear(vs / "decoder_l3", 32, input_dim as i64, Default::default()));

        Autoencoder {
            var_store: vs.var_store(),
            encoder,
            decoder,
        }
    }

    fn forward(&self, xs: &Tensor) -> Tensor {
        let encoded = self.encoder.forward(xs);
        self.decoder.forward(&encoded)
    }
}