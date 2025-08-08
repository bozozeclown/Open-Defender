// src/resilience/retry.rs
use std::time::Duration;
use std::future::Future;
use tokio::time::sleep;
use tracing::{warn, info};

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

pub struct RetryPolicy {
    config: RetryConfig,
}

impl RetryPolicy {
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    pub async fn execute<F, T, E, R>(&self, operation: F, is_retryable: R) -> Result<T, E>
    where
        F: Future<Output = Result<T, E>>,
        R: Fn(&E) -> bool,
        E: std::fmt::Debug,
    {
        let mut attempt = 0;
        let mut delay = self.config.base_delay;

        loop {
            attempt += 1;

            match operation.await {
                Ok(result) => {
                    if attempt > 1 {
                        info!("Operation succeeded after {} attempts", attempt);
                    }
                    return Ok(result);
                }
                Err(error) => {
                    if attempt >= self.config.max_attempts || !is_retryable(&error) {
                        warn!("Operation failed after {} attempts: {:?}", attempt, error);
                        return Err(error);
                    }

                    let delay_ms = delay.as_millis() as u64;
                    let actual_delay = if self.config.jitter {
                        let jitter = (delay_ms as f64 * 0.1) as u64;
                        Duration::from_millis(delay_ms + (rand::random::<u64>() % (2 * jitter + 1)) - jitter)
                    } else {
                        delay
                    };

                    warn!("Operation failed (attempt {}/{}), retrying in {:?}: {:?}",
                          attempt, self.config.max_attempts, actual_delay, error);

                    sleep(actual_delay).await;

                    // Calculate next delay with exponential backoff
                    delay = std::cmp::min(
                        Duration::from_millis((delay.as_millis() as f64 * self.config.backoff_multiplier) as u64),
                        self.config.max_delay,
                    );
                }
            }
        }
    }
}

// Helper function for common retry scenarios
pub async fn retry_operation<F, T, E>(
    operation: F,
    max_attempts: u32,
    base_delay: Duration,
) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
    E: std::fmt::Debug,
{
    let config = RetryConfig {
        max_attempts,
        base_delay,
        ..Default::default()
    };

    let policy = RetryPolicy::new(config);
    policy.execute(operation, |_| true).await
}
