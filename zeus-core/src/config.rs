use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackConfig {
    pub concurrency: usize,
    /// Maximum number of concurrent worker tasks. Mirrors `concurrency`.
    pub max_tasks: usize,
    pub timeout: Duration,
    pub retry_count: u32,
    pub retry_delay: Duration,
    pub exit_on_first: bool,
    /// Halt the attack after the first successful credential is found.
    pub stop_on_first: bool,
    pub rate_limit: Option<u64>,
    pub verbose: bool,
    /// Target requests per second (0 = unlimited).
    pub target_rps: u64,
    /// Maximum retries on transient errors (not rate-limit, not success).
    pub max_retries: u32,
}

impl Default for AttackConfig {
    fn default() -> Self {
        Self {
            concurrency: 16,
            max_tasks: 16,
            timeout: Duration::from_secs(10),
            retry_count: 1,
            retry_delay: Duration::from_millis(500),
            exit_on_first: true,
            stop_on_first: true,
            rate_limit: None,
            verbose: false,
            target_rps: 0,
            max_retries: 2,
        }
    }
}

#[derive(Default)]
pub struct AttackConfigBuilder {
    inner: AttackConfig,
}

impl AttackConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn concurrency(mut self, n: usize) -> Self {
        self.inner.concurrency = n;
        self.inner.max_tasks = n;
        self
    }
    pub fn max_tasks(mut self, n: usize) -> Self {
        self.inner.max_tasks = n;
        self.inner.concurrency = n;
        self
    }
    pub fn timeout(mut self, d: Duration) -> Self {
        self.inner.timeout = d;
        self
    }
    pub fn retry_count(mut self, n: u32) -> Self {
        self.inner.retry_count = n;
        self
    }
    pub fn retry_delay(mut self, d: Duration) -> Self {
        self.inner.retry_delay = d;
        self
    }
    pub fn exit_on_first(mut self, v: bool) -> Self {
        self.inner.exit_on_first = v;
        self.inner.stop_on_first = v;
        self
    }
    pub fn stop_on_first(mut self, v: bool) -> Self {
        self.inner.stop_on_first = v;
        self.inner.exit_on_first = v;
        self
    }
    pub fn rate_limit(mut self, rps: u64) -> Self {
        self.inner.rate_limit = Some(rps);
        self
    }
    pub fn verbose(mut self, v: bool) -> Self {
        self.inner.verbose = v;
        self
    }
    pub fn target_rps(mut self, rps: u64) -> Self {
        self.inner.target_rps = rps;
        self
    }
    pub fn max_retries(mut self, n: u32) -> Self {
        self.inner.max_retries = n;
        self
    }
    pub fn build(self) -> AttackConfig {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults() {
        let cfg = AttackConfigBuilder::new().build();
        assert_eq!(cfg.concurrency, 16);
        assert_eq!(cfg.max_tasks, 16);
        assert!(cfg.exit_on_first);
        assert!(cfg.stop_on_first);
    }

    #[test]
    fn builder_override() {
        let cfg = AttackConfigBuilder::new()
            .concurrency(4)
            .verbose(true)
            .build();
        assert_eq!(cfg.concurrency, 4);
        assert_eq!(cfg.max_tasks, 4);
        assert!(cfg.verbose);
    }

    #[test]
    fn stop_on_first_syncs_exit_on_first() {
        let cfg = AttackConfigBuilder::new().stop_on_first(false).build();
        assert!(!cfg.stop_on_first);
        assert!(!cfg.exit_on_first);
    }

    #[test]
    fn max_tasks_syncs_concurrency() {
        let cfg = AttackConfigBuilder::new().max_tasks(8).build();
        assert_eq!(cfg.max_tasks, 8);
        assert_eq!(cfg.concurrency, 8);
    }
}
