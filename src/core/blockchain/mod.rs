// src/core/blockchain/mod.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::BlockchainConfig;
use crate::collectors::DataEvent;
use crate::core::ai::AIAnalysisResult;

pub struct SecurityBlockchain {
    config: BlockchainConfig,
    network: Arc<BlockchainNetwork>,
    smart_contracts: Arc<SmartContractManager>,
    consensus: Arc<ConsensusEngine>,
    identity_manager: Arc<IdentityManager>,
    audit_trail: Arc<RwLock<Vec<BlockchainEntry>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainEntry {
    pub block_hash: String,
    pub transaction_hash: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_id: uuid::Uuid,
    pub analysis_result: AIAnalysisResult,
    pub risk_score: f64,
    pub actions_taken: Vec<String>,
    pub validator_signatures: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub previous_hash: String,
    pub hash: String,
    pub transactions: Vec<Transaction>,
    pub nonce: u64,
    pub difficulty: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub sender: String,
    pub receiver: String,
    pub data: TransactionData,
    pub signature: String,
    pub gas_limit: u64,
    pub gas_used: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionData {
    EventRecord {
        event_id: uuid::Uuid,
        analysis_result: AIAnalysisResult,
        risk_score: f64,
    },
    SmartContractCall {
        contract_address: String,
        function_name: String,
        parameters: Vec<serde_json::Value>,
    },
    IdentityVerification {
        identity_id: String,
        verification_data: serde_json::Value,
    },
    ComplianceReport {
        report_id: String,
        report_data: serde_json::Value,
    },
}

impl SecurityBlockchain {
    pub async fn new(config: &BlockchainConfig) -> Result<Self> {
        let network = Arc::new(BlockchainNetwork::new(config).await?);
        let smart_contracts = Arc::new(SmartContractManager::new(config).await?);
        let consensus = Arc::new(ConsensusEngine::new(config).await?);
        let identity_manager = Arc::new(IdentityManager::new(config).await?);
        let audit_trail = Arc::new(RwLock::new(Vec::new()));

        Ok(Self {
            config: config.clone(),
            network,
            smart_contracts,
            consensus,
            identity_manager,
            audit_trail,
        })
    }

    pub async fn record_event(&self, event: &DataEvent, analysis_result: &AIAnalysisResult, risk_score: f64) -> Result<String> {
        debug!("Recording event {} on blockchain", event.event_id);

        // Create transaction data
        let transaction_data = TransactionData::EventRecord {
            event_id: event.event_id,
            analysis_result: analysis_result.clone(),
            risk_score,
        };

        // Create transaction
        let transaction = self.create_transaction(
            self.identity_manager.get_system_identity().await?,
            "blockchain".to_string(),
            transaction_data,
        ).await?;

        // Validate and add to pending transactions
        self.network.add_pending_transaction(transaction.clone()).await?;

        // Mine block with consensus
        let block = self.consensus.mine_block(vec![transaction]).await?;

        // Add block to blockchain
        self.network.add_block(block).await?;

        // Create audit trail entry
        let entry = BlockchainEntry {
            block_hash: block.hash.clone(),
            transaction_hash: transaction.id.clone(),
            timestamp: chrono::Utc::now(),
            event_id: event.event_id,
            analysis_result: analysis_result.clone(),
            risk_score,
            actions_taken: analysis_result.actions_taken.clone(),
            validator_signatures: block.validator_signatures.clone(),
            metadata: {
                let mut metadata = HashMap::new();
                metadata.insert("event_type".to_string(), serde_json::Value::String(event.event_type.clone()));
                metadata.insert("timestamp".to_string(), serde_json::Value::String(event.timestamp.to_rfc3339()));
                metadata
            },
        };

        // Add to audit trail
        {
            let mut audit_trail = self.audit_trail.write().await;
            audit_trail.push(entry.clone());
        }

        // Execute smart contracts if needed
        if risk_score > self.config.smart_contract.threshold {
            self.smart_contracts.execute_response_contract(
                &block.hash,
                &transaction.id,
                risk_score,
            ).await?;
        }

        info!("Event {} recorded on blockchain in block {}", event.event_id, block.hash);
        Ok(block.hash)
    }

    async fn create_transaction(&self, sender: String, receiver: String, data: TransactionData) -> Result<Transaction> {
        let transaction_id = format!("tx_{}", uuid::Uuid::new_v4());
        let timestamp = chrono::Utc::now();

        // Serialize transaction data
        let data_json = serde_json::to_value(&data)?;
        let data_str = data_json.to_string();

        // Create transaction hash
        let transaction_hash = self.calculate_hash(&format!("{}{}{}{}", transaction_id, timestamp, sender, data_str));

        // Sign transaction
        let signature = self.identity_manager.sign_transaction(&transaction_hash).await?;

        Ok(Transaction {
            id: transaction_id,
            timestamp,
            sender,
            receiver,
            data,
            signature,
            gas_limit: 1000000,
            gas_used: 0,
        })
    }

    fn calculate_hash(&self, data: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub async fn verify_blockchain_integrity(&self) -> Result<bool> {
        let blocks = self.network.get_blocks().await?;
        
        if blocks.is_empty() {
            return Ok(true);
        }

        // Verify genesis block
        let genesis_block = &blocks[0];
        if !self.verify_block_hash(genesis_block) {
            warn!("Genesis block hash verification failed");
            return Ok(false);
        }

        // Verify chain integrity
        for i in 1..blocks.len() {
            let current_block = &blocks[i];
            let previous_block = &blocks[i - 1];

            // Verify previous hash reference
            if current_block.previous_hash != previous_block.hash {
                warn!("Block {} previous hash mismatch", current_block.index);
                return Ok(false);
            }

            // Verify current block hash
            if !self.verify_block_hash(current_block) {
                warn!("Block {} hash verification failed", current_block.index);
                return Ok(false);
            }
        }

        info!("Blockchain integrity verification passed");
        Ok(true)
    }

    fn verify_block_hash(&self, block: &Block) -> bool {
        let expected_hash = self.calculate_block_hash(block);
        expected_hash == block.hash
    }

    fn calculate_block_hash(&self, block: &Block) -> String {
        let block_data = format!(
            "{}{}{}{}{}",
            block.index,
            block.timestamp.timestamp(),
            block.previous_hash,
            serde_json::to_string(&block.transactions).unwrap_or_default(),
            block.nonce
        );
        self.calculate_hash(&block_data)
    }

    pub async fn get_audit_trail(&self, limit: Option<usize>) -> Vec<BlockchainEntry> {
        let audit_trail = self.audit_trail.read().await;
        match limit {
            Some(l) => audit_trail.iter().rev().take(l).cloned().collect(),
            None => audit_trail.iter().rev().cloned().collect(),
        }
    }

    pub async fn get_blockchain_stats(&self) -> BlockchainStats {
        let blocks = self.network.get_blocks().await;
        let audit_trail = self.audit_trail.read().await;

        BlockchainStats {
            total_blocks: blocks.len(),
            total_transactions: blocks.iter().map(|b| b.transactions.len()).sum(),
            total_audit_entries: audit_trail.len(),
            latest_block_timestamp: blocks.last().map(|b| b.timestamp),
            average_block_time: self.calculate_average_block_time(&blocks),
            network_hash_rate: self.network.get_hash_rate().await,
            network_difficulty: blocks.last().map(|b| b.difficulty).unwrap_or(0),
        }
    }

    fn calculate_average_block_time(&self, blocks: &[Block]) -> Option<f64> {
        if blocks.len() < 2 {
            return None;
        }

        let mut total_time = 0.0;
        for i in 1..blocks.len() {
            let time_diff = (blocks[i].timestamp - blocks[i - 1].timestamp).num_seconds();
            total_time += time_diff;
        }

        Some(total_time / (blocks.len() - 1) as f64)
    }

    pub async fn health_check(&self) -> HealthStatus {
        // Check network connectivity
        if !self.network.is_connected().await {
            warn!("Blockchain network not connected");
            return HealthStatus::Unhealthy;
        }

        // Check consensus health
        if !self.consensus.is_healthy().await {
            warn!("Blockchain consensus not healthy");
            return HealthStatus::Degraded;
        }

        // Check smart contracts
        if !self.smart_contracts.is_healthy().await {
            warn!("Smart contracts not healthy");
            return HealthStatus::Degraded;
        }

        // Verify blockchain integrity
        if !self.verify_blockchain_integrity().await.unwrap_or(false) {
            warn!("Blockchain integrity verification failed");
            return HealthStatus::Unhealthy;
        }

        HealthStatus::Healthy
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainStats {
    pub total_blocks: usize,
    pub total_transactions: usize,
    pub total_audit_entries: usize,
    pub latest_block_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub average_block_time: Option<f64>,
    pub network_hash_rate: f64,
    pub network_difficulty: u32,
}

pub struct BlockchainNetwork {
    config: BlockchainConfig,
    blocks: Arc<RwLock<Vec<Block>>>,
    pending_transactions: Arc<RwLock<Vec<Transaction>>>,
    peers: Arc<RwLock<Vec<String>>>,
}

impl BlockchainNetwork {
    pub async fn new(config: &BlockchainConfig) -> Result<Self> {
        let genesis_block = Block {
            index: 0,
            timestamp: chrono::Utc::now(),
            previous_hash: "0".to_string(),
            hash: Self::calculate_genesis_hash(),
            transactions: Vec::new(),
            nonce: 0,
            difficulty: config.consensus.initial_difficulty,
        };

        Ok(Self {
            config: config.clone(),
            blocks: Arc::new(RwLock::new(vec![genesis_block])),
            pending_transactions: Arc::new(RwLock::new(Vec::new())),
            peers: Arc::new(RwLock::new(Vec::new())),
        })
    }

    pub async fn add_pending_transaction(&self, transaction: Transaction) -> Result<()> {
        let mut pending = self.pending_transactions.write().await;
        pending.push(transaction);
        Ok(())
    }

    pub async fn get_pending_transactions(&self) -> Vec<Transaction> {
        let pending = self.pending_transactions.read().await;
        pending.clone()
    }

    pub async fn add_block(&self, block: Block) -> Result<()> {
        let mut blocks = self.blocks.write().await;
        blocks.push(block);
        Ok(())
    }

    pub async fn get_blocks(&self) -> Vec<Block> {
        let blocks = self.blocks.read().await;
        blocks.clone()
    }

    pub async fn is_connected(&self) -> bool {
        let peers = self.peers.read().await;
        !peers.is_empty()
    }

    pub async fn get_hash_rate(&self) -> f64 {
        // Simplified hash rate calculation
        let blocks = self.blocks.read().await;
        if blocks.len() < 2 {
            return 0.0;
        }

        let time_diff = (blocks.last().unwrap().timestamp - blocks[blocks.len() - 2].timestamp).num_seconds();
        if time_diff > 0 {
            1.0 / time_diff
        } else {
            0.0
        }
    }

    fn calculate_genesis_hash() -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"genesis_block");
        format!("{:x}", hasher.finalize())
    }
}

pub struct ConsensusEngine {
    config: BlockchainConfig,
    validators: Arc<RwLock<Vec<Validator>>>,
}

impl ConsensusEngine {
    pub async fn new(config: &BlockchainConfig) -> Result<Self> {
        let validators = Arc::new(RwLock::new(config.consensus.validators.clone()));

        Ok(Self {
            config: config.clone(),
            validators,
        })
    }

    pub async fn mine_block(&self, transactions: Vec<Transaction>) -> Result<Block> {
        let blocks = self.network.get_blocks().await;
        let previous_block = blocks.last().unwrap();
        let index = previous_block.index + 1;
        let previous_hash = previous_block.hash.clone();
        let timestamp = chrono::Utc::now();

        // Proof of Work mining
        let (nonce, hash) = self.proof_of_work(&previous_hash, &transactions, timestamp, index).await?;

        // Collect validator signatures
        let validator_signatures = self.collect_validator_signatures(&hash).await?;

        Ok(Block {
            index,
            timestamp,
            previous_hash,
            hash,
            transactions,
            nonce,
            difficulty: self.config.consensus.difficulty,
        })
    }

    async fn proof_of_work(&self, previous_hash: &str, transactions: &[Transaction], timestamp: chrono::DateTime<chrono::Utc>, index: u64) -> Result<(u64, String)> {
        let transactions_json = serde_json::to_string(transactions)?;
        let block_data = format!("{}{}{}{}", index, timestamp.timestamp(), previous_hash, transactions_json);
        
        let target = self.calculate_target(self.config.consensus.difficulty);
        
        let mut nonce = 0u64;
        loop {
            let data = format!("{}{}", block_data, nonce);
            let hash = Self::calculate_hash(&data);
            
            if self.hash_meets_target(&hash, &target) {
                return Ok((nonce, hash));
            }
            
            nonce += 1;
            
            // Prevent infinite loop in testing
            if nonce > 1000000 {
                return Err(anyhow::anyhow!("Proof of work failed"));
            }
        }
    }

    fn calculate_target(&self, difficulty: u32) -> String {
        let target = (2u64.pow(256) - 1) / difficulty as u64;
        format!("{:064x}", target)
    }

    fn hash_meets_target(&self, hash: &str, target: &str) -> bool {
        hash < target
    }

    fn calculate_hash(data: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    async fn collect_validator_signatures(&self, block_hash: &str) -> Result<Vec<String>> {
        let validators = self.validators.read().await;
        let mut signatures = Vec::new();

        for validator in &*validators {
            // In a real implementation, this would collect actual signatures
            signatures.push(format!("signature_{}_{}", validator.id, block_hash));
        }

        Ok(signatures)
    }

    pub async fn is_healthy(&self) -> bool {
        let validators = self.validators.read().await;
        !validators.is_empty() && validators.len() >= self.config.consensus.min_validators
    }
}

pub struct SmartContractManager {
    config: BlockchainConfig,
    contracts: Arc<RwLock<HashMap<String, SmartContract>>>,
}

impl SmartContractManager {
    pub async fn new(config: &BlockchainConfig) -> Result<Self> {
        let contracts = Arc::new(RwLock::new(HashMap::new()));

        Ok(Self {
            config: config.clone(),
            contracts,
        })
    }

    pub async fn execute_response_contract(&self, block_hash: &str, transaction_id: &str, risk_score: f64) -> Result<()> {
        if risk_score > self.config.smart_contract.threshold {
            // Execute response contract
            let contract = self.get_contract("auto_response").await?;
            
            let result = contract.execute_function(
                "trigger_response",
                vec![
                    serde_json::Value::String(block_hash.to_string()),
                    serde_json::Value::String(transaction_id.to_string()),
                    serde_json::Value::Number(serde_json::Number::from_f64(risk_score).unwrap()),
                ],
            ).await?;

            info!("Response contract executed: {:?}", result);
        }

        Ok(())
    }

    async fn get_contract(&self, name: &str) -> Result<SmartContract> {
        let contracts = self.contracts.read().await;
        contracts.get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Contract not found: {}", name))
    }

    pub async fn is_healthy(&self) -> bool {
        let contracts = self.contracts.read().await;
        !contracts.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartContract {
    pub address: String,
    pub abi: Vec<FunctionABI>,
    pub bytecode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionABI {
    pub name: String,
    pub inputs: Vec<Parameter>,
    pub outputs: Vec<Parameter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub type_: String,
}

impl SmartContract {
    pub async fn execute_function(&self, name: &str, parameters: Vec<serde_json::Value>) -> Result<serde_json::Value> {
        // Simplified smart contract execution
        // In a real implementation, this would use Ethereum or similar blockchain
        Ok(serde_json::Value::String(format!("Executed {} with params: {:?}", name, parameters)))
    }
}

pub struct IdentityManager {
    config: BlockchainConfig,
    identities: Arc<RwLock<HashMap<String, Identity>>>,
}

impl IdentityManager {
    pub async fn new(config: &BlockchainConfig) -> Result<Self> {
        let identities = Arc::new(RwLock::new(HashMap::new()));

        Ok(Self {
            config: config.clone(),
            identities,
        })
    }

    pub async fn get_system_identity(&self) -> Result<String> {
        Ok("system_identity".to_string())
    }

    pub async fn sign_transaction(&self, transaction_hash: &str) -> Result<String> {
        // Simplified signing
        Ok(format!("signed_{}", transaction_hash))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub public_key: String,
    pub private_key: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub id: String,
    pub public_key: String,
    pub stake: u64,
    pub reputation: f64,
}