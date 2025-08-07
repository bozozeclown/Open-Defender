// src/utils/database.rs
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool, Row};
use std::path::PathBuf;
use crate::config::Config;
use crate::collectors::DataEvent;
use anyhow::{Context, Result};
use crypto::buffer::{ReadBuffer, WriteBuffer};
use crypto::{aes, blockmodes, buffer, symmetriccipher};

pub struct DatabaseManager {
    pool: SqlitePool,
    encryption_key: Vec<u8>,
}

impl DatabaseManager {
    pub async fn new(config: &Config) -> Result<Self> {
        let db_path = &config.database.path;
        let encryption_key = &config.database.encryption_key;
        
        // Ensure the directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create database directory")?;
        }
        
        let pool = SqlitePoolOptions::new()
            .max_connections(config.database.max_connections)
            .connect(&format!("sqlite://{}", db_path.display()))
            .await
            .context("Failed to create database pool")?;
        
        // Initialize database schema
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            "#
        )
        .execute(&pool)
        .await
        .context("Failed to create events table")?;
        
        // Create other tables as needed...
        
        Ok(Self {
            pool,
            encryption_key: Self::derive_key(encryption_key)?,
        })
    }
    
    fn derive_key(password: &str) -> Result<Vec<u8>> {
        // Use PBKDF2 to derive a key from the password
        let salt = b"exploit_detector_salt"; // In production, use a random salt
        let iterations = 10000;
        let key = pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
            password.as_bytes(),
            salt,
            iterations,
            32, // 256 bits
        );
        Ok(key.to_vec())
    }
    
    pub async fn store_event(&self, event: &DataEvent) -> Result<()> {
        let event_json = serde_json::to_string(event)
            .context("Failed to serialize event")?;
        
        let encrypted_data = self.encrypt(&event_json)
            .context("Failed to encrypt event data")?;
        
        sqlx::query(
            r#"
            INSERT INTO events (id, event_type, timestamp, data, created_at)
            VALUES (?, ?, ?, ?, ?)
            "#
        )
        .bind(&event.event_id)
        .bind(&event.event_type)
        .bind(event.timestamp.to_rfc3339())
        .bind(&encrypted_data)
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await
        .context("Failed to store event")?;
        
        Ok(())
    }
    
    pub async fn get_recent_events(&self, limit: i32) -> Result<Vec<DataEvent>> {
        let rows = sqlx::query(
            r#"
            SELECT data FROM events
            ORDER BY created_at DESC
            LIMIT ?
            "#
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch events")?;
        
        let mut events = Vec::new();
        for row in rows {
            let encrypted_data: Vec<u8> = row.get("data");
            let decrypted_data = self.decrypt(&encrypted_data)
                .context("Failed to decrypt event data")?;
            
            let event: DataEvent = serde_json::from_str(&decrypted_data)
                .context("Failed to deserialize event")?;
            
            events.push(event);
        }
        
        Ok(events)
    }
    
    fn encrypt(&self, data: &str) -> Result<Vec<u8>> {
        let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            &self.encryption_key,
            &[0u8; 16], // IV - in production, use a random IV
            blockmodes::PkcsPadding,
        );
        
        let mut buffer = [0; 4096];
        let mut read_buffer = buffer::RefReadBuffer::new(data.as_bytes());
        let mut result = Vec::new();
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
        
        loop {
            let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)
                .map_err(|e| anyhow::anyhow!("Encryption error: {:?}", e))?;
            
            result.read_buffer().take_into(&mut result);
            result.write_buffer().take_into(&mut result);
            
            if result.is_finished() {
                break;
            }
        }
        
        Ok(result)
    }
    
    fn decrypt(&self, encrypted_data: &[u8]) -> Result<String> {
        let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            &self.encryption_key,
            &[0u8; 16], // IV - must match the one used for encryption
            blockmodes::PkcsPadding,
        );
        
        let mut buffer = [0; 4096];
        let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
        let mut result = Vec::new();
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
        
        loop {
            let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)
                .map_err(|e| anyhow::anyhow!("Decryption error: {:?}", e))?;
            
            result.read_buffer().take_into(&mut result);
            result.write_buffer().take_into(&mut result);
            
            if result.is_finished() {
                break;
            }
        }
        
        String::from_utf8(result)
            .context("Failed to convert decrypted data to UTF-8")
    }
}