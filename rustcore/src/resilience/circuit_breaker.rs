// src/resilience/circuit_breaker.rs
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use std::collections::VecDeque;
use tracing::{info, warn, error};

#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: usize,
    pub success_threshold: usize,
    pub timeout: Duration,
    pub max_retries: u32,
    pub backoff_multiplier: f64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(60),
            max_retries: 3,
            backoff_multiplier: 2.0,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitState>>,
    failures: Arc<RwLock<VecDeque<Instant>>>,
    successes: Arc<RwLock<VecDeque<Instant>>>,
    last_failure_time: Arc<RwLock<Option<Instant>>>,
    retry_count: Arc<RwLock<u32>>,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            failures: Arc::new(RwLock::new(VecDeque::new())),
            successes: Arc::new(RwLock::new(VecDeque::new())),
            last_failure_time: Arc::new(RwLock::new(None)),
            retry_count: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn call<F, T, E>(&self, operation: F) -> Result<T, E>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        let state = self.state.read().await;
        
        match *state {
            CircuitState::Open => {
                if self.should_attempt_reset().await {
                    drop(state);
                    self.transition_to_half_open().await;
                    self.execute_with_retry(operation).await
                } else {
                    Err(self.create_circuit_error("Circuit breaker is open"))
                }
            }
            CircuitState::HalfOpen => {
                drop(state);
                self.execute_with_retry(operation).await
            }
            CircuitState::Closed => {
                drop(state);
                self.execute_with_retry(operation).await
            }
        }
    }

    async fn execute_with_retry<F, T, E>(&self, operation: F) -> Result<T, E>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        let mut retries = 0;
        let mut backoff = Duration::from_millis(100);

        loop {
            match operation.await {
                Ok(result) => {
                    self.record_success().await;
                    return Ok(result);
                }
                Err(e) => {
                    retries += 1;
                    
                    if retries >= self.config.max_retries {
                        self.record_failure().await;
                        return Err(e);
                    }
                    
                    warn!("Operation failed, retrying in {:?} (attempt {}/{})", 
                          backoff, retries, self.config.max_retries);
                    
                    tokio::time::sleep(backoff).await;
                    backoff = Duration::from_millis(
                        (backoff.as_millis() as f64 * self.config.backoff_multiplier) as u64
                    );
                }
            }
        }
    }

    async fn should_attempt_reset(&self) -> bool {
        let last_failure = self.last_failure_time.read().await;
        if let Some(failure_time) = *last_failure {
            failure_time.elapsed() > self.config.timeout
        } else {
            false
        }
    }

    async fn transition_to_half_open(&self) {
        let mut state = self.state.write().await;
        *state = CircuitState::HalfOpen;
        info!("Circuit breaker transitioned to half-open state");
    }

    async fn record_success(&self) {
        let mut state = self.state.write().await;
        let mut successes = self.successes.write().await;
        let mut failures = self.failures.write().await;
        let mut retry_count = self.retry_count.write().await;

        successes.push_back(Instant::now());
        *retry_count = 0;

        // Keep only recent successes
        while successes.len() > self.config.success_threshold {
            successes.pop_front();
        }

        // Clear old failures
        failures.clear();

        // If we have enough successes, close the circuit
        if successes.len() >= self.config.success_threshold {
            *state = CircuitState::Closed;
            info!("Circuit breaker closed after {} successes", successes.len());
        } else if *state == CircuitState::HalfOpen {
            // Stay in half-open until we have enough successes
            info!("Circuit breaker remains in half-open state ({} successes)", successes.len());
        }
    }

    async fn record_failure(&self) {
        let mut state = self.state.write().await;
        let mut failures = self.failures.write().await;
        let mut successes = self.successes.write().await;
        let mut last_failure = self.last_failure_time.write().await;
        let mut retry_count = self.retry_count.write().await;

        failures.push_back(Instant::now());
        *last_failure = Some(Instant::now());
        *retry_count += 1;

        // Keep only recent failures
        while failures.len() > self.config.failure_threshold {
            failures.pop_front();
        }

        // Clear old successes
        successes.clear();

        // If we have enough failures, open the circuit
        if failures.len() >= self.config.failure_threshold {
            *state = CircuitState::Open;
            error!("Circuit breaker opened after {} failures", failures.len());
        }
    }

    fn create_circuit_error<E>(&self, message: &str) -> E
    where
        E: std::fmt::Display + From<String>,
    {
        E::from(format!("Circuit breaker error: {}", message))
    }

    pub async fn get_state(&self) -> CircuitState {
        self.state.read().await.clone()
    }

    pub async fn get_metrics(&self) -> CircuitBreakerMetrics {
        let state = self.state.read().await;
        let failures = self.failures.read().await;
        let successes = self.successes.read().await;
        let last_failure = self.last_failure_time.read().await;

        CircuitBreakerMetrics {
            state: state.clone(),
            failure_count: failures.len(),
            success_count: successes.len(),
            last_failure_time: *last_failure,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerMetrics {
    pub state: CircuitState,
    pub failure_count: usize,
    pub success_count: usize,
    pub last_failure_time: Option<Instant>,
}