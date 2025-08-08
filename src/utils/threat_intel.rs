// src/utils/threat_intel.rs
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};

use crate::config::ThreatIntelConfig;

pub struct ThreatIntelManager {
    config: ThreatIntelConfig,
    client: Client,
    ioc_cache: Arc<RwLock<IocCache>>,
    cti_cache: Arc<RwLock<CtiCache>>,
    last_updated: Arc<RwLock<DateTime<Utc>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocCache {
    pub ips: HashSet<String>,
    pub domains: HashSet<String>,
    pub hashes: HashSet<String>,
    pub urls: HashSet<String>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtiCache {
    pub campaigns: HashMap<String, Campaign>,
    pub actors: HashMap<String, ThreatActor>,
    pub malware: HashMap<String, MalwareFamily>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    pub id: String,
    pub name: String,
    pub description: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub associated_actors: Vec<String>,
    pub associated_malware: Vec<String>,
    pub tags: Vec<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    pub id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub description: String,
    pub country: Option<String>,
    pub motivation: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub associated_campaigns: Vec<String>,
    pub associated_malware: Vec<String>,
    pub tags: Vec<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareFamily {
    pub id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub description: String,
    pub malware_types: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub associated_actors: Vec<String>,
    pub associated_campaigns: Vec<String>,
    pub tags: Vec<String>,
    pub references: Vec<String>,
}

impl ThreatIntelManager {
    pub fn new(config: &ThreatIntelConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        Ok(Self {
            config: config.clone(),
            client,
            ioc_cache: Arc::new(RwLock::new(IocCache {
                ips: HashSet::new(),
                domains: HashSet::new(),
                hashes: HashSet::new(),
                urls: HashSet::new(),
                last_updated: Utc::now(),
            })),
            cti_cache: Arc::new(RwLock::new(CtiCache {
                campaigns: HashMap::new(),
                actors: HashMap::new(),
                malware: HashMap::new(),
                last_updated: Utc::now(),
            })),
            last_updated: Arc::new(RwLock::new(Utc::now())),
        })
    }

    pub async fn run(&self) -> Result<()> {
        let mut update_interval = interval(Duration::from_secs(3600)); // Update every hour

        loop {
            update_interval.tick().await;

            if let Err(e) = self.update_threat_intel().await {
                error!("Failed to update threat intelligence: {}", e);
            }

            // Sleep for a short time to prevent tight loop
            sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn update_threat_intel(&self) -> Result<()> {
        info!("Updating threat intelligence feeds");

        // Update IOC data
        self.update_ioc_data().await?;

        // Update CTI data
        self.update_cti_data().await?;

        // Update last updated timestamp
        let mut last_updated = self.last_updated.write().await;
        *last_updated = Utc::now();

        info!("Threat intelligence updated successfully");
        Ok(())
    }

    async fn update_ioc_data(&self) -> Result<()> {
        let mut ioc_cache = self.ioc_cache.write().await;

        // Update from VirusTotal
        if let Some(api_key) = &self.config.api_keys.virustotal {
            self.update_virustotal_iocs(api_key, &mut ioc_cache).await?;
        }

        // Update from other sources
        // Implementation for other threat intel sources would go here

        ioc_cache.last_updated = Utc::now();
        Ok(())
    }

    async fn update_virustotal_iocs(&self, api_key: &str, ioc_cache: &mut IocCache) -> Result<()> {
        // Get latest malicious IPs
        let ip_response = self
            .client
            .get(&format!(
                "https://www.virustotal.com/vtapi/v2/ip-addresses/recent?apikey={}",
                api_key
            ))
            .send()
            .await?;

        if ip_response.status().is_success() {
            let ip_data: VirusTotalIPResponse = ip_response.json().await?;
            for ip in ip_data.ip_addresses {
                ioc_cache.ips.insert(ip);
            }
        }

        // Get latest malicious domains
        let domain_response = self
            .client
            .get(&format!(
                "https://www.virustotal.com/vtapi/v2/domains/recent?apikey={}",
                api_key
            ))
            .send()
            .await?;

        if domain_response.status().is_success() {
            let domain_data: VirusTotalDomainResponse = domain_response.json().await?;
            for domain in domain_data.domains {
                ioc_cache.domains.insert(domain);
            }
        }

        // Get latest file hashes
        let file_response = self
            .client
            .get(&format!(
                "https://www.virustotal.com/vtapi/v2/file/recent?apikey={}",
                api_key
            ))
            .send()
            .await?;

        if file_response.status().is_success() {
            let file_data: VirusTotalFileResponse = file_response.json().await?;
            for file in file_data.hashes {
                ioc_cache.hashes.insert(file);
            }
        }

        Ok(())
    }

    async fn update_cti_data(&self) -> Result<()> {
        let mut cti_cache = self.cti_cache.write().await;

        // Update from MITRE ATT&CK
        self.update_mitre_data(&mut cti_cache).await?;

        // Update from other CTI sources
        // Implementation for other CTI sources would go here

        cti_cache.last_updated = Utc::now();
        Ok(())
    }

    async fn update_mitre_data(&self, cti_cache: &mut CtiCache) -> Result<()> {
        // Fetch MITRE ATT&CK data
        let enterprise_response = self
            .client
            .get("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
            .send()
            .await?;

        if enterprise_response.status().is_success() {
            let attack_data: MitreAttackData = enterprise_response.json().await?;
            
            for object in attack_data.objects {
                match object.type_.as_str() {
                    "campaign" => {
                        if let Ok(campaign) = serde_json::from_value::<Campaign>(object) {
                            cti_cache.campaigns.insert(campaign.id.clone(), campaign);
                        }
                    }
                    "intrusion-set" => {
                        if let Ok(actor) = serde_json::from_value::<ThreatActor>(object) {
                            cti_cache.actors.insert(actor.id.clone(), actor);
                        }
                    }
                    "malware" => {
                        if let Ok(malware) = serde_json::from_value::<MalwareFamily>(object) {
                            cti_cache.malware.insert(malware.id.clone(), malware);
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    pub async fn check_ioc(&self, ioc_type: &str, value: &str) -> bool {
        let ioc_cache = self.ioc_cache.read().await;
        
        match ioc_type {
            "ip" => ioc_cache.ips.contains(value),
            "domain" => ioc_cache.domains.contains(value),
            "hash" => ioc_cache.hashes.contains(value),
            "url" => ioc_cache.urls.contains(value),
            _ => false,
        }
    }

    pub async fn get_campaigns(&self) -> Vec<Campaign> {
        let cti_cache = self.cti_cache.read().await;
        cti_cache.campaigns.values().cloned().collect()
    }

    pub async fn get_threat_actors(&self) -> Vec<ThreatActor> {
        let cti_cache = self.cti_cache.read().await;
        cti_cache.actors.values().cloned().collect()
    }

    pub async fn get_malware_families(&self) -> Vec<MalwareFamily> {
        let cti_cache = self.cti_cache.read().await;
        cti_cache.malware.values().cloned().collect()
    }

    pub async fn get_ioc_stats(&self) -> IocStats {
        let ioc_cache = self.ioc_cache.read().await;
        IocStats {
            ip_count: ioc_cache.ips.len(),
            domain_count: ioc_cache.domains.len(),
            hash_count: ioc_cache.hashes.len(),
            url_count: ioc_cache.urls.len(),
            last_updated: ioc_cache.last_updated,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct VirusTotalIPResponse {
    ip_addresses: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VirusTotalDomainResponse {
    domains: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VirusTotalFileResponse {
    hashes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct MitreAttackData {
    objects: Vec<MitreAttackObject>,
}

#[derive(Debug, Serialize, Deserialize)]
struct MitreAttackObject {
    #[serde(rename = "type")]
    type_: String,
    #[serde(flatten)]
    data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocStats {
    pub ip_count: usize,
    pub domain_count: usize,
    pub hash_count: usize,
    pub url_count: usize,
    pub last_updated: DateTime<Utc>,
}
