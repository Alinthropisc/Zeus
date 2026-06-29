//! Multi-target engine — Orchestrator pattern.
//!
//! Attacks multiple targets simultaneously, bounded by `max_parallel_targets`.
//! Uses `FuturesUnordered` for maximum concurrency and a `Semaphore` to cap
//! the number of in-flight target attacks.

use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;
use zeus_attack::AttackStrategy;
use zeus_core::{AttackConfig, Credential, ProgressEvent, Target};
use zeus_services::registry::ProtocolRegistry;

use crate::Engine;

/// Results of attacking a single target.
pub struct MultiAttackResult {
    pub target: Target,
    pub found: Vec<Credential>,
    /// Number of credential attempts made (populated from SessionFinished event).
    pub attempts: u64,
    pub elapsed: std::time::Duration,
}

/// Orchestrates attacks against multiple targets simultaneously.
pub struct MultiEngine {
    registry: Arc<ProtocolRegistry>,
    config: AttackConfig,
    /// Maximum number of targets to attack at the same time.
    max_parallel_targets: usize,
}

impl MultiEngine {
    pub fn new(
        registry: Arc<ProtocolRegistry>,
        config: AttackConfig,
        max_parallel_targets: usize,
    ) -> Self {
        Self {
            registry,
            config,
            max_parallel_targets: max_parallel_targets.max(1),
        }
    }

    /// Attack multiple targets. `strategy_factory` is called once per target to
    /// produce a fresh strategy instance.
    ///
    /// Blocks until every target has been attempted (or cancels early if
    /// `stop_on_first` is set in the config).
    pub async fn run_all<F>(
        &self,
        targets: Vec<Target>,
        strategy_factory: F,
    ) -> Vec<MultiAttackResult>
    where
        F: Fn(&Target) -> Box<dyn AttackStrategy> + Send + Sync + 'static,
    {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_parallel_targets));
        let factory = Arc::new(strategy_factory);
        let mut futures: FuturesUnordered<_> = FuturesUnordered::new();

        for target in targets {
            let sem = Arc::clone(&semaphore);
            let factory = Arc::clone(&factory);
            let engine = Engine::new(Arc::clone(&self.registry), self.config.clone());

            futures.push(async move {
                let _permit = match sem.acquire_owned().await {
                    Ok(p) => p,
                    // Semaphore is only closed if its owner is dropped,
                    // which cannot happen while this future is alive.
                    Err(_) => {
                        return MultiAttackResult {
                            target,
                            found: vec![],
                            attempts: 0,
                            elapsed: std::time::Duration::ZERO,
                        };
                    }
                };
                let strategy = factory(&target);
                let start = std::time::Instant::now();
                let (found, mut rx) = engine.run(target.clone(), strategy).await;

                // Extract attempt count from SessionFinished event.
                let mut attempts = 0u64;
                while let Ok(ev) = rx.try_recv() {
                    if let zeus_core::ProgressEvent::SessionFinished { total_attempts, .. } = ev {
                        attempts = total_attempts;
                    }
                }

                MultiAttackResult {
                    target,
                    found,
                    attempts,
                    elapsed: start.elapsed(),
                }
            });
        }

        let mut results = Vec::new();
        while let Some(result) = futures.next().await {
            results.push(result);
        }
        results
    }

    /// Non-blocking variant: spawns the attack in the background and returns
    /// a broadcast receiver for live `ProgressEvent`s alongside a join handle.
    pub fn run_all_streaming<F>(
        &self,
        targets: Vec<Target>,
        strategy_factory: F,
    ) -> (
        broadcast::Receiver<ProgressEvent>,
        tokio::task::JoinHandle<Vec<MultiAttackResult>>,
    )
    where
        F: Fn(&Target) -> Box<dyn AttackStrategy> + Send + Sync + 'static,
    {
        let (tx, rx) = broadcast::channel::<ProgressEvent>(4096);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_parallel_targets));
        let factory = Arc::new(strategy_factory);
        let registry = Arc::clone(&self.registry);
        let config = self.config.clone();

        let handle = tokio::spawn(async move {
            let mut futures: FuturesUnordered<_> = FuturesUnordered::new();

            for target in targets {
                let sem = Arc::clone(&semaphore);
                let factory = Arc::clone(&factory);
                let engine = Engine::new(Arc::clone(&registry), config.clone());
                let tx = tx.clone();

                futures.push(async move {
                    let _permit = match sem.acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => {
                            return MultiAttackResult {
                                target,
                                found: vec![],
                                attempts: 0,
                                elapsed: std::time::Duration::ZERO,
                            };
                        }
                    };
                    let strategy = factory(&target);
                    let start = std::time::Instant::now();
                    let (found, mut inner_rx) = engine.run(target.clone(), strategy).await;

                    // Forward all events to the outer broadcast channel.
                    let mut attempts = 0u64;
                    while let Ok(ev) = inner_rx.try_recv() {
                        if let ProgressEvent::SessionFinished { total_attempts, .. } = &ev {
                            attempts = *total_attempts;
                        }
                        let _ = tx.send(ev);
                    }

                    MultiAttackResult {
                        target,
                        found,
                        attempts,
                        elapsed: start.elapsed(),
                    }
                });
            }

            let mut results = Vec::new();
            while let Some(result) = futures.next().await {
                results.push(result);
            }
            results
        });

        (rx, handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use tokio_stream::iter as stream_iter;
    use zeus_attack::{AttackStrategy, CredentialStream};
    use zeus_core::{
        AttackConfig, AttackConfigBuilder, AttackResult, Credential, Protocol, Target, ZeusError,
    };
    use zeus_services::registry::ProtocolRegistry;

    struct MockFailureProtocol;

    #[async_trait]
    impl Protocol for MockFailureProtocol {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn default_port(&self) -> u16 {
            9999
        }
        async fn authenticate(
            &self,
            _target: &Target,
            _cred: &Credential,
            _config: &AttackConfig,
        ) -> Result<AttackResult, ZeusError> {
            Ok(AttackResult::Failure)
        }
    }

    struct StaticStrategy {
        creds: Vec<Credential>,
    }

    impl StaticStrategy {
        fn new(creds: Vec<Credential>) -> Self {
            Self { creds }
        }
    }

    impl AttackStrategy for StaticStrategy {
        fn name(&self) -> &'static str {
            "static"
        }
        fn credentials(&self) -> CredentialStream {
            Box::pin(stream_iter(self.creds.clone()))
        }
        fn estimated_count(&self) -> Option<u64> {
            Some(self.creds.len() as u64)
        }
    }

    fn mock_registry() -> Arc<ProtocolRegistry> {
        let reg = ProtocolRegistry::new();
        reg.register(Arc::new(MockFailureProtocol));
        Arc::new(reg)
    }

    fn config() -> AttackConfig {
        AttackConfigBuilder::new().stop_on_first(false).build()
    }

    fn target(port: u16) -> Target {
        Target::new("127.0.0.1", port, "mock")
    }

    fn creds(n: usize) -> Vec<Credential> {
        (0..n)
            .map(|i| Credential::new(format!("u{i}"), format!("p{i}")))
            .collect()
    }

    #[tokio::test]
    async fn multi_engine_empty_targets() {
        let engine = MultiEngine::new(mock_registry(), config(), 4);
        let results = engine
            .run_all(vec![], |_| Box::new(StaticStrategy::new(vec![])))
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn multi_engine_single_target_mock() {
        let engine = MultiEngine::new(mock_registry(), config(), 4);
        let targets = vec![target(9999)];
        let results = engine
            .run_all(targets, |_| Box::new(StaticStrategy::new(creds(3))))
            .await;
        assert_eq!(results.len(), 1);
        assert!(results[0].found.is_empty()); // failure protocol
        assert_eq!(results[0].attempts, 3);
    }

    #[tokio::test]
    async fn multi_engine_parallel_limit() {
        // Launch 6 targets but cap at 2 parallel — should still complete all.
        let engine = MultiEngine::new(mock_registry(), config(), 2);
        let targets: Vec<Target> = (0..6).map(|i| target(9000 + i as u16)).collect();
        let results = engine
            .run_all(targets, |_| Box::new(StaticStrategy::new(creds(1))))
            .await;
        assert_eq!(results.len(), 6);
        for r in &results {
            assert_eq!(r.attempts, 1);
        }
    }
}
