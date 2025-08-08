// src/distributed/message_queue.rs
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::config::MessageQueueConfig;
use crate::collectors::DataEvent;

#[async_trait]
pub trait MessageQueue: Send + Sync {
    async fn publish(&self, topic: &str, message: &[u8]) -> Result<()>;
    async fn subscribe(&self, topic: &str, consumer_group: &str) -> Result<Box<dyn MessageConsumer>>;
    async fn create_topic(&self, topic: &str) -> Result<()>;
    async fn delete_topic(&self, topic: &str) -> Result<()>;
    async fn list_topics(&self) -> Result<Vec<String>>;
}

#[async_trait]
pub trait MessageConsumer: Send + Sync {
    async fn receive(&mut self) -> Result<Option<Vec<u8>>>;
    async fn commit(&self) -> Result<()>;
    async fn close(&self) -> Result<()>;
}

pub struct MessageQueueManager {
    config: MessageQueueConfig,
    queue: Arc<dyn MessageQueue>,
    publishers: HashMap<String, Arc<dyn MessagePublisher>>,
    consumers: HashMap<String, Arc<dyn MessageConsumer>>,
}

#[async_trait]
pub trait MessagePublisher: Send + Sync {
    async fn publish(&self, message: &DataEvent) -> Result<()>;
    async fn publish_batch(&self, messages: &[DataEvent]) -> Result<()>;
}

impl MessageQueueManager {
    pub async fn new(config: MessageQueueConfig) -> Result<Self> {
        let queue: Arc<dyn MessageQueue> = match config.backend.as_str() {
            "kafka" => Arc::new(KafkaQueue::new(&config).await?),
            "redis" => Arc::new(RedisQueue::new(&config).await?),
            "nats" => Arc::new(NatsQueue::new(&config).await?),
            _ => return Err(anyhow::anyhow!("Unsupported message queue backend: {}", config.backend)),
        };

        Ok(Self {
            config,
            queue,
            publishers: HashMap::new(),
            consumers: HashMap::new(),
        })
    }

    pub async fn create_publisher(&self, topic: &str) -> Result<Arc<dyn MessagePublisher>> {
        let publisher = match self.config.backend.as_str() {
            "kafka" => Arc::new(KafkaPublisher::new(self.queue.clone(), topic).await?),
            "redis" => Arc::new(RedisPublisher::new(self.queue.clone(), topic).await?),
            "nats" => Arc::new(NatsPublisher::new(self.queue.clone(), topic).await?),
            _ => return Err(anyhow::anyhow!("Unsupported message queue backend: {}", self.config.backend)),
        };

        Ok(publisher)
    }

    pub async fn create_consumer(&self, topic: &str, consumer_group: &str) -> Result<Arc<dyn MessageConsumer>> {
        let consumer = self.queue.subscribe(topic, consumer_group).await?;
        Ok(Arc::from(consumer))
    }

    pub async fn publish_event(&self, topic: &str, event: &DataEvent) -> Result<()> {
        let message = serde_json::to_vec(event)?;
        self.queue.publish(topic, &message).await
    }

    pub async fn publish_events(&self, topic: &str, events: &[DataEvent]) -> Result<()> {
        for event in events {
            self.publish_event(topic, event).await?;
        }
        Ok(())
    }
}

// Kafka Implementation
pub struct KafkaQueue {
    config: MessageQueueConfig,
    producer: Arc<rdkafka::producer::FutureProducer<rdkafka::producer::DefaultProducerContext>>,
    consumer: Arc<RwLock<Option<rdkafka::consumer::StreamConsumer<rdkafka::consumer::DefaultConsumerContext>>>>,
}

impl KafkaQueue {
    pub async fn new(config: &MessageQueueConfig) -> Result<Self> {
        let producer_config = rdkafka::config::ClientConfig::new()
            .set("bootstrap.servers", &config.brokers.join(","))
            .set("message.timeout.ms", "5000")
            .set("enable.idempotence", "true")
            .set("acks", "all")
            .set("retries", "2147483647")
            .set("max.in.flight.requests.per.connection", "5")
            .set("linger.ms", "0")
            .set("enable.auto.commit", "false")
            .set("compression.type", "lz4");

        let producer: Arc<rdkafka::producer::FutureProducer<_>> = producer_config.create()?;

        Ok(Self {
            config: config.clone(),
            producer,
            consumer: Arc::new(RwLock::new(None)),
        })
    }
}

#[async_trait]
impl MessageQueue for KafkaQueue {
    async fn publish(&self, topic: &str, message: &[u8]) -> Result<()> {
        let record = rdkafka::producer::FutureRecord::to(topic)
            .key("")
            .payload(message);

        self.producer.send(record, 0).await?;
        Ok(())
    }

    async fn subscribe(&self, topic: &str, consumer_group: &str) -> Result<Box<dyn MessageConsumer>> {
        let consumer_config = rdkafka::config::ClientConfig::new()
            .set("bootstrap.servers", &self.config.brokers.join(","))
            .set("group.id", consumer_group)
            .set("enable.auto.commit", "false")
            .set("auto.offset.reset", "earliest");

        let consumer: rdkafka::consumer::StreamConsumer<_> = consumer_config.create()?;
        consumer.subscribe(&[topic])?;

        let kafka_consumer = KafkaConsumer {
            consumer: Arc::new(consumer),
        };

        Ok(Box::new(kafka_consumer))
    }

    async fn create_topic(&self, topic: &str) -> Result<()> {
        // Implementation would use Kafka AdminClient
        Ok(())
    }

    async fn delete_topic(&self, topic: &str) -> Result<()> {
        // Implementation would use Kafka AdminClient
        Ok(())
    }

    async fn list_topics(&self) -> Result<Vec<String>> {
        // Implementation would use Kafka AdminClient
        Ok(vec![])
    }
}

pub struct KafkaConsumer {
    consumer: Arc<rdkafka::consumer::StreamConsumer<rdkafka::consumer::DefaultConsumerContext>>,
}

#[async_trait]
impl MessageConsumer for KafkaConsumer {
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        match self.consumer.recv().await {
            Ok(message) => {
                let payload = message.payload();
                Ok(payload.map(|p| p.to_vec()))
            }
            Err(e) => match e {
                rdkafka::error::KafkaError::PartitionEOF(_) => Ok(None),
                _ => Err(e.into()),
            },
        }
    }

    async fn commit(&self) -> Result<()> {
        self.consumer.commit_message(&self.consumer.recv().await?)?;
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

pub struct KafkaPublisher {
    queue: Arc<dyn MessageQueue>,
    topic: String,
}

impl KafkaPublisher {
    pub async fn new(queue: Arc<dyn MessageQueue>, topic: &str) -> Result<Self> {
        Ok(Self {
            queue,
            topic: topic.to_string(),
        })
    }
}

#[async_trait]
impl MessagePublisher for KafkaPublisher {
    async fn publish(&self, message: &DataEvent) -> Result<()> {
        let message_bytes = serde_json::to_vec(message)?;
        self.queue.publish(&self.topic, &message_bytes).await
    }

    async fn publish_batch(&self, messages: &[DataEvent]) -> Result<()> {
        for message in messages {
            self.publish(message).await?;
        }
        Ok(())
    }
}

// Redis Implementation
pub struct RedisQueue {
    config: MessageQueueConfig,
    client: Arc<redis::Client>,
}

impl RedisQueue {
    pub async fn new(config: &MessageQueueConfig) -> Result<Self> {
        let client = redis::Client::open(config.brokers[0].as_str())?;
        Ok(Self {
            config: config.clone(),
            client: Arc::new(client),
        })
    }
}

#[async_trait]
impl MessageQueue for RedisQueue {
    async fn publish(&self, topic: &str, message: &[u8]) -> Result<()> {
        let mut conn = self.client.get_async_connection().await?;
        redis::cmd("XADD")
            .arg(topic)
            .arg("*")
            .arg("data")
            .arg(message)
            .query_async(&mut conn)
            .await?;
        Ok(())
    }

    async fn subscribe(&self, topic: &str, _consumer_group: &str) -> Result<Box<dyn MessageConsumer>> {
        let consumer = RedisConsumer {
            client: self.client.clone(),
            topic: topic.to_string(),
            last_id: "$".to_string(),
        };
        Ok(Box::new(consumer))
    }

    async fn create_topic(&self, _topic: &str) -> Result<()> {
        // Redis streams don't need explicit topic creation
        Ok(())
    }

    async fn delete_topic(&self, topic: &str) -> Result<()> {
        let mut conn = self.client.get_async_connection().await?;
        redis::cmd("DEL").arg(topic).query_async(&mut conn).await?;
        Ok(())
    }

    async fn list_topics(&self) -> Result<Vec<String>> {
        let mut conn = self.client.get_async_connection().await?;
        let topics: Vec<String> = redis::cmd("KEYS").arg("*").query_async(&mut conn).await?;
        Ok(topics)
    }
}

pub struct RedisConsumer {
    client: Arc<redis::Client>,
    topic: String,
    last_id: String,
}

#[async_trait]
impl MessageConsumer for RedisConsumer {
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        let mut conn = self.client.get_async_connection().await?;
        let streams: redis::RedisResult<HashMap<String, Vec<HashMap<String, redis::Value>>>> = redis::cmd("XREAD")
            .arg("STREAMS")
            .arg(&self.topic)
            .arg(&self.last_id)
            .query_async(&mut conn)
            .await;

        match streams {
            Ok(mut stream_data) => {
                if let Some(entries) = stream_data.get_mut(&self.topic) {
                    if let Some(first_entry) = entries.first() {
                        if let Some(id) = first_entry.keys().next() {
                            self.last_id = id.clone();
                        }
                        if let Some(data) = first_entry.get("data") {
                            if let redis::Value::Data(bytes) = data {
                                return Ok(Some(bytes.clone()));
                            }
                        }
                    }
                }
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn commit(&self) -> Result<()> {
        // Redis streams don't need explicit commits
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

pub struct RedisPublisher {
    queue: Arc<dyn MessageQueue>,
    topic: String,
}

impl RedisPublisher {
    pub async fn new(queue: Arc<dyn MessageQueue>, topic: &str) -> Result<Self> {
        Ok(Self {
            queue,
            topic: topic.to_string(),
        })
    }
}

#[async_trait]
impl MessagePublisher for RedisPublisher {
    async fn publish(&self, message: &DataEvent) -> Result<()> {
        let message_bytes = serde_json::to_vec(message)?;
        self.queue.publish(&self.topic, &message_bytes).await
    }

    async fn publish_batch(&self, messages: &[DataEvent]) -> Result<()> {
        for message in messages {
            self.publish(message).await?;
        }
        Ok(())
    }
}

// NATS Implementation
pub struct NatsQueue {
    config: MessageQueueConfig,
    connection: Arc<async_nats::Client>,
}

impl NatsQueue {
    pub async fn new(config: &MessageQueueConfig) -> Result<Self> {
        let connection = async_nats::connect(&config.brokers.join(",")).await?;
        Ok(Self {
            config: config.clone(),
            connection: Arc::new(connection),
        })
    }
}

#[async_trait]
impl MessageQueue for NatsQueue {
    async fn publish(&self, topic: &str, message: &[u8]) -> Result<()> {
        self.connection.publish(topic, message).await?;
        Ok(())
    }

    async fn subscribe(&self, topic: &str, _consumer_group: &str) -> Result<Box<dyn MessageConsumer>> {
        let subscription = self.connection.subscribe(topic).await?;
        let consumer = NatsConsumer {
            subscription: Arc::new(subscription),
        };
        Ok(Box::new(consumer))
    }

    async fn create_topic(&self, _topic: &str) -> Result<()> {
        // NATS doesn't need explicit topic creation
        Ok(())
    }

    async fn delete_topic(&self, _topic: &str) -> Result<()> {
        // NATS doesn't support topic deletion
        Ok(())
    }

    async fn list_topics(&self) -> Result<Vec<String>> {
        // NATS doesn't have a way to list topics
        Ok(vec![])
    }
}

pub struct NatsConsumer {
    subscription: Arc<async_nats::Subscriber>,
}

#[async_trait]
impl MessageConsumer for NatsConsumer {
    async fn receive(&mut self) -> Result<Option<Vec<u8>>> {
        match self.subscription.next().await {
            Some(message) => Ok(Some(message.payload.to_vec())),
            None => Ok(None),
        }
    }

    async fn commit(&self) -> Result<()> {
        // NATS doesn't need explicit commits
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

pub struct NatsPublisher {
    queue: Arc<dyn MessageQueue>,
    topic: String,
}

impl NatsPublisher {
    pub async fn new(queue: Arc<dyn MessageQueue>, topic: &str) -> Result<Self> {
        Ok(Self {
            queue,
            topic: topic.to_string(),
        })
    }
}

#[async_trait]
impl MessagePublisher for NatsPublisher {
    async fn publish(&self, message: &DataEvent) -> Result<()> {
        let message_bytes = serde_json::to_vec(message)?;
        self.queue.publish(&self.topic, &message_bytes).await
    }

    async fn publish_batch(&self, messages: &[DataEvent]) -> Result<()> {
        for message in messages {
            self.publish(message).await?;
        }
        Ok(())
    }
}
