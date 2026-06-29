//! Zeus Engine — orchestrates attack sessions.
//!
//! Patterns applied:
//!   - **Orchestrator/Facade**: `Engine` hides concurrency complexity behind a
//!     simple `run()` call.
//!   - **Observer**: live `ProgressEvent`s flow out via a tokio broadcast
//!     channel so callers can react without polling.
//!   - **Strategy (dispatch)**: `dyn DispatchStrategy` controls when to stop
//!     and how to batch credentials — swappable without touching `Engine`.
//!   - **Strategy (attack)**: `dyn AttackStrategy` produces the credential
//!     stream — decoupled from the engine entirely.
//!   - **Command + Cancellation**: `CancellationToken` lets any worker signal
//!     all peers to stop.
//!
//! ## Single Responsibility breakdown
//!
//! | Unit                  | Responsibility                                    |
//! |-----------------------|---------------------------------------------------|
//! | [`Engine`]            | Thin coordinator — wires components, emits events |
//! | [`SessionCounters`]   | Atomic bookkeeping for one session                |
//! | [`WorkerContext`]     | Immutable snapshot shared by every worker task    |
//! | [`retry_authenticate`]| Retry + back-off logic for one credential         |
//! | [`record_result`]     | Counter updates + event emission for one result   |
//! | [`run_worker`]        | Single worker task: pause gate → retry → record   |
//! | [`run_scheduler`]     | Outer throttled loop that spawns workers          |

pub mod checkpoint;
pub mod multi_engine;
pub mod net;
pub mod output;
pub mod priority;
pub mod probe_runner;
pub mod session;
pub mod strategy;

pub use checkpoint::{AttackCheckpoint, CheckpointManager};
pub use multi_engine::{MultiAttackResult, MultiEngine};
pub use priority::PriorityStrategy;
pub use session::{AttackSession, LegacySession, LegacyStatus, SessionState, SessionStats, SessionStatus};
pub use strategy::{DispatchStrategy, SequentialStrategy, StopOnFirstStrategy};

use futures::stream::StreamExt;
use std::ops::Not;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use zeus_attack::AttackStrategy;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, ProgressEvent, Target, ZeusError};
use zeus_services::registry::ProtocolRegistry;

// ─────────────────────────────────────────────────────────────────────────────
// SessionCounters — atomic bookkeeping for one attack session
// ─────────────────────────────────────────────────────────────────────────────

/// Groups all per-session atomic counters so they can be passed as a single
/// `Arc` rather than six separate `Arc<AtomicU64>` values.
struct SessionCounters {
    attempts:    AtomicU64,
    successes:   AtomicU64,
    failures:    AtomicU64,
    errors:      AtomicU64,
    rate_limits: AtomicU64,
    timeouts:    AtomicU64,
}

impl SessionCounters {
    fn new() -> Self {
        Self {
            attempts:    AtomicU64::new(0),
            successes:   AtomicU64::new(0),
            failures:    AtomicU64::new(0),
            errors:      AtomicU64::new(0),
            rate_limits: AtomicU64::new(0),
            timeouts:    AtomicU64::new(0),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkerContext — immutable snapshot passed into every spawned task
// ─────────────────────────────────────────────────────────────────────────────

/// Everything a worker task needs, bundled behind a single `Arc` clone.
///
/// All fields are individually `Arc`-wrapped or `Clone`, so the struct itself
/// is cheap to clone across task boundaries.
struct WorkerContext {
    proto:             Arc<dyn Protocol>,
    target:            Target,
    config:            AttackConfig,
    tx:                broadcast::Sender<ProgressEvent>,
    counters:          Arc<SessionCounters>,
    found:             Arc<parking_lot::Mutex<Vec<Credential>>>,
    cancel:            CancellationToken,
    paused:            Arc<AtomicBool>,
    dispatch_strategy: Arc<dyn DispatchStrategy>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Engine
// ─────────────────────────────────────────────────────────────────────────────

/// Orchestrates a single-target attack session.
///
/// The engine is **open for extension** via [`DispatchStrategy`] and
/// [`AttackStrategy`] without modifying this struct (OCP).
pub struct Engine {
    registry:          Arc<ProtocolRegistry>,
    config:            AttackConfig,
    /// Pause flag — worker tasks spin-wait while this is `true`.
    paused:            Arc<AtomicBool>,
    /// Controls early-stop semantics; defaults to [`SequentialStrategy`].
    dispatch_strategy: Arc<dyn DispatchStrategy>,
}

impl Engine {
    /// Create an engine with the default [`SequentialStrategy`].
    pub fn new(registry: Arc<ProtocolRegistry>, config: AttackConfig) -> Self {
        Self {
            registry,
            config,
            paused:            Arc::new(AtomicBool::new(false)),
            dispatch_strategy: Arc::new(SequentialStrategy),
        }
    }

    /// Replace the dispatch strategy (builder-style, consumes `self`).
    ///
    /// # Example
    /// ```rust,ignore
    /// let engine = Engine::new(registry, config)
    ///     .with_dispatch_strategy(Arc::new(StopOnFirstStrategy));
    /// ```
    pub fn with_dispatch_strategy(mut self, strategy: Arc<dyn DispatchStrategy>) -> Self {
        self.dispatch_strategy = strategy;
        self
    }

    /// Pause all in-flight workers (they spin-wait until resumed).
    pub fn pause(&self) { self.paused.store(true, Ordering::Relaxed); }

    /// Resume paused workers.
    pub fn resume(&self) { self.paused.store(false, Ordering::Relaxed); }

    /// Returns `true` if the engine is currently paused.
    pub fn is_paused(&self) -> bool { self.paused.load(Ordering::Relaxed) }

    /// Run an attack against `target` using the given credential `strategy`.
    ///
    /// Returns the found credentials and a live-event receiver.  The receiver
    /// begins receiving before this call returns because events are sent from
    /// spawned tasks.
    pub async fn run(
        &self,
        target: Target,
        strategy: Box<dyn AttackStrategy>,
    ) -> (Vec<Credential>, broadcast::Receiver<ProgressEvent>) {
        let (tx, rx) = broadcast::channel(1024);
        let estimated = strategy.estimated_count();

        let proto = match self.registry.get(&target.protocol) {
            Some(p) => p,
            None => {
                error!(protocol = %target.protocol, "unknown protocol");
                return (vec![], rx);
            }
        };

        let _ = tx.send(ProgressEvent::SessionStarted {
            target:          target.clone(),
            estimated_total: estimated,
        });

        let cancel   = CancellationToken::new();
        let counters = Arc::new(SessionCounters::new());
        let found    = Arc::new(parking_lot::Mutex::new(Vec::<Credential>::new()));
        let start    = Instant::now();

        run_scheduler(
            proto,
            target.clone(),
            strategy,
            self.config.clone(),
            tx.clone(),
            cancel,
            Arc::clone(&counters),
            Arc::clone(&found),
            Arc::clone(&self.paused),
            Arc::clone(&self.dispatch_strategy),
            start,
        ).await;

        emit_session_finished(&tx, &counters, &found, start);

        let found_creds = std::mem::take(&mut *found.lock());
        info!(attempts = counters.attempts.load(Ordering::Relaxed), found = found_creds.len(), "session finished");

        (found_creds, rx)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// run_scheduler — outer throttled loop (Single Responsibility: dispatching)
// ─────────────────────────────────────────────────────────────────────────────

/// Drives the credential stream, enforces the RPS budget, acquires semaphore
/// permits, and spawns a [`run_worker`] task per credential.
///
/// Responsibility: scheduling and rate-limiting only.  No retry logic, no
/// counter updates — those live in the worker.
#[allow(clippy::too_many_arguments)]
async fn run_scheduler(
    proto:             Arc<dyn Protocol>,
    target:            Target,
    attack_strategy:   Box<dyn AttackStrategy>,
    config:            AttackConfig,
    tx:                broadcast::Sender<ProgressEvent>,
    cancel:            CancellationToken,
    counters:          Arc<SessionCounters>,
    found:             Arc<parking_lot::Mutex<Vec<Credential>>>,
    paused:            Arc<AtomicBool>,
    dispatch_strategy: Arc<dyn DispatchStrategy>,
    start:             Instant,
) {
    let semaphore   = Arc::new(tokio::sync::Semaphore::new(config.max_tasks));
    let mut stream  = attack_strategy.credentials();
    let mut join_set: JoinSet<()> = JoinSet::new();
    let mut dispatched: u64 = 0;

    while let Some(cred) = stream.next().await {
        if cancel.is_cancelled() {
            debug!("cancellation signalled — draining credential stream");
            break;
        }

        throttle_rps(&config, &mut dispatched, start).await;

        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p)  => p,
            Err(_) => { warn!("semaphore closed — stopping early"); break; }
        };

        let ctx = Arc::new(WorkerContext {
            proto:             Arc::clone(&proto),
            target:            target.clone(),
            config:            config.clone(),
            tx:                tx.clone(),
            counters:          Arc::clone(&counters),
            found:             Arc::clone(&found),
            cancel:            cancel.clone(),
            paused:            Arc::clone(&paused),
            dispatch_strategy: Arc::clone(&dispatch_strategy),
        });

        join_set.spawn(async move {
            let _permit = permit;   // released when this task ends
            run_worker(ctx, cred).await;
        });
    }

    // Wait for all in-flight workers to complete.
    while join_set.join_next().await.is_some() {}
}

// ─────────────────────────────────────────────────────────────────────────────
// throttle_rps — token-bucket schedule helper
// ─────────────────────────────────────────────────────────────────────────────

/// Sleep if we are dispatching credentials faster than `config.target_rps`.
///
/// Responsibility: RPS enforcement only.
async fn throttle_rps(config: &AttackConfig, dispatched: &mut u64, start: Instant) {
    if config.target_rps == 0 {
        return;
    }
    *dispatched += 1;
    let expected_ms = (*dispatched * 1_000) / config.target_rps;
    let actual_ms   = start.elapsed().as_millis() as u64;
    if actual_ms < expected_ms {
        tokio::time::sleep(Duration::from_millis(expected_ms - actual_ms)).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// run_worker — spawned task body (Single Responsibility: one credential attempt)
// ─────────────────────────────────────────────────────────────────────────────

/// Handles pause gating, then delegates to [`retry_authenticate`] and
/// [`record_result`].
///
/// Responsibility: task lifecycle and sequencing only.
async fn run_worker(ctx: Arc<WorkerContext>, cred: Credential) {
    if ctx.cancel.is_cancelled() {
        return;
    }

    // Spin-wait while the engine is paused.
    while ctx.cancel.is_cancelled().not() && ctx.paused.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if ctx.cancel.is_cancelled() {
        return;
    }

    let attempt_start  = Instant::now();
    let attack_result  = retry_authenticate(&ctx, &cred).await;
    let done           = ctx.counters.attempts.fetch_add(1, Ordering::Relaxed) + 1;

    record_result(&ctx, &cred, &attack_result, done, attempt_start);
}

// ─────────────────────────────────────────────────────────────────────────────
// retry_authenticate — retry + back-off (Single Responsibility: resilience)
// ─────────────────────────────────────────────────────────────────────────────

/// Calls `Protocol::authenticate` and retries on transient errors.
///
/// - Transient `Error` variants are retried up to `config.max_retries` times.
/// - `RateLimit` results trigger exponential back-off (capped at 30 s) and
///   increment the rate-limit counter immediately.
/// - All other variants are returned immediately.
///
/// Responsibility: retry and back-off logic only.
async fn retry_authenticate(ctx: &WorkerContext, cred: &Credential) -> AttackResult {
    let mut retry = 0u32;

    loop {
        let raw = ctx.proto.authenticate(&ctx.target, cred, &ctx.config).await;
        let result = map_protocol_result(raw);

        match &result {
            AttackResult::Error(_) if retry < ctx.config.max_retries => {
                retry += 1;
                warn!(attempt = retry, "transient error — retrying");
                tokio::time::sleep(ctx.config.retry_delay).await;
            }
            AttackResult::RateLimit => {
                let hits        = ctx.counters.rate_limits.fetch_add(1, Ordering::Relaxed) + 1;
                let backoff_ms  = backoff_ms_for_hit(hits);
                warn!(backoff_ms, rate_limit_hits = hits, "rate limited — backing off");
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                return result;   // counter already bumped; stop retrying
            }
            _ => return result,
        }
    }
}

/// Map a protocol `Result` into a flat `AttackResult`.
#[inline]
fn map_protocol_result(raw: Result<AttackResult, ZeusError>) -> AttackResult {
    match raw {
        Ok(r)                      => r,
        Err(ZeusError::Timeout(_)) => AttackResult::Timeout,
        Err(ZeusError::RateLimit)  => AttackResult::RateLimit,
        Err(e)                     => AttackResult::Error(e.to_string()),
    }
}

/// Exponential back-off capped at 30 s: `100ms * 2^(hits-1)`.
#[inline]
fn backoff_ms_for_hit(hits: u64) -> u64 {
    std::cmp::min(100u64.saturating_mul(1u64 << (hits - 1).min(8)), 30_000)
}

// ─────────────────────────────────────────────────────────────────────────────
// record_result — counter updates + event emission (Single Responsibility)
// ─────────────────────────────────────────────────────────────────────────────

/// Updates per-category counters, pushes successes to the found list, triggers
/// cancellation via the dispatch strategy, and emits an `Attempt` event.
///
/// Responsibility: result accounting and event emission only.
fn record_result(
    ctx:           &WorkerContext,
    cred:          &Credential,
    result:        &AttackResult,
    done:          u64,
    attempt_start: Instant,
) {
    match result {
        AttackResult::Success { .. } => {
            ctx.counters.successes.fetch_add(1, Ordering::Relaxed);
            info!(credential = %cred, "found valid credential");
            ctx.found.lock().push(cred.clone());

            // Both the config flag and the pluggable strategy can trigger a stop.
            let strategy_stop = ctx.dispatch_strategy.should_stop(result, &ctx.config);
            if ctx.config.stop_on_first || strategy_stop {
                ctx.cancel.cancel();
            }
        }
        AttackResult::Failure        => { ctx.counters.failures.fetch_add(1, Ordering::Relaxed); }
        AttackResult::Error(_)       => { ctx.counters.errors.fetch_add(1, Ordering::Relaxed); }
        AttackResult::Timeout        => { ctx.counters.timeouts.fetch_add(1, Ordering::Relaxed); }
        // RateLimit counter is bumped inside retry_authenticate before returning.
        AttackResult::RateLimit      => {}
    }

    let _ = ctx.tx.send(ProgressEvent::Attempt {
        credential:    cred.clone(),
        result:        result.clone(),
        attempts_done: done,
        started_at:    attempt_start,
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// emit_session_finished — final event helper
// ─────────────────────────────────────────────────────────────────────────────

/// Reads the final counter snapshot and sends a `SessionFinished` event.
///
/// Responsibility: building and sending the terminal event only.
fn emit_session_finished(
    tx:       &broadcast::Sender<ProgressEvent>,
    counters: &SessionCounters,
    found:    &parking_lot::Mutex<Vec<Credential>>,
    start:    Instant,
) {
    let total   = counters.attempts.load(Ordering::Relaxed);
    let elapsed = start.elapsed();
    let rate    = if elapsed.as_secs_f64() > 0.0 {
        total as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    // Clone the found list for the event; the caller will `mem::take` it.
    let found_snapshot = found.lock().clone();

    let _ = tx.send(ProgressEvent::SessionFinished {
        found:            found_snapshot,
        total_attempts:   total,
        elapsed,
        successes:        counters.successes.load(Ordering::Relaxed),
        failures:         counters.failures.load(Ordering::Relaxed),
        errors:           counters.errors.load(Ordering::Relaxed),
        rate_limits:      counters.rate_limits.load(Ordering::Relaxed),
        timeouts:         counters.timeouts.load(Ordering::Relaxed),
        rate_per_second:  rate,
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::time::Duration;
    use tokio_stream::iter as stream_iter;
    use zeus_attack::{AttackStrategy, CredentialStream};
    use zeus_core::{AttackConfig, AttackConfigBuilder, AttackResult, Credential, Protocol, Target, ZeusError};
    use zeus_services::registry::ProtocolRegistry;

    struct MockSuccessProtocol;

    #[async_trait]
    impl Protocol for MockSuccessProtocol {
        fn name(&self) -> &'static str { "mock" }
        fn default_port(&self) -> u16 { 9999 }
        async fn authenticate(
            &self,
            _target: &Target,
            cred: &Credential,
            _config: &AttackConfig,
        ) -> Result<AttackResult, ZeusError> {
            tokio::time::sleep(Duration::from_millis(1)).await;
            Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: Duration::from_millis(1),
            })
        }
    }

    struct MockFailureProtocol;

    #[async_trait]
    impl Protocol for MockFailureProtocol {
        fn name(&self) -> &'static str { "mock" }
        fn default_port(&self) -> u16 { 9999 }
        async fn authenticate(
            &self,
            _target: &Target,
            _cred: &Credential,
            _config: &AttackConfig,
        ) -> Result<AttackResult, ZeusError> {
            Ok(AttackResult::Failure)
        }
    }

    struct MockErrorProtocol;

    #[async_trait]
    impl Protocol for MockErrorProtocol {
        fn name(&self) -> &'static str { "mock" }
        fn default_port(&self) -> u16 { 9999 }
        async fn authenticate(
            &self,
            _target: &Target,
            _cred: &Credential,
            _config: &AttackConfig,
        ) -> Result<AttackResult, ZeusError> {
            Err(ZeusError::Protocol("transient".to_string()))
        }
    }

    struct MockRateLimitProtocol {
        calls: Arc<AtomicU64>,
    }

    #[async_trait]
    impl Protocol for MockRateLimitProtocol {
        fn name(&self) -> &'static str { "mock" }
        fn default_port(&self) -> u16 { 9999 }
        async fn authenticate(
            &self,
            _target: &Target,
            _cred: &Credential,
            _config: &AttackConfig,
        ) -> Result<AttackResult, ZeusError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(ZeusError::RateLimit)
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
        fn name(&self) -> &'static str { "static" }
        fn credentials(&self) -> CredentialStream {
            Box::pin(stream_iter(self.creds.clone()))
        }
        fn estimated_count(&self) -> Option<u64> {
            Some(self.creds.len() as u64)
        }
    }

    fn mock_registry(proto: Arc<dyn Protocol>) -> Arc<ProtocolRegistry> {
        let reg = ProtocolRegistry::new();
        reg.register(proto);
        Arc::new(reg)
    }

    fn target() -> Target {
        Target::new("127.0.0.1", 9999, "mock")
    }

    fn creds(n: usize) -> Vec<Credential> {
        (0..n)
            .map(|i| Credential::new(format!("user{i}"), format!("pass{i}")))
            .collect()
    }

    #[tokio::test]
    async fn success_mock_finds_credential() {
        let registry = mock_registry(Arc::new(MockSuccessProtocol));
        let config = AttackConfigBuilder::new().stop_on_first(false).build();
        let engine = Engine::new(registry, config);
        let strategy = Box::new(StaticStrategy::new(creds(3)));

        let (found, _rx) = engine.run(target(), strategy).await;
        assert!(!found.is_empty(), "expected at least one found credential");
    }

    #[tokio::test]
    async fn stop_on_first_halts_after_one_success() {
        let registry = mock_registry(Arc::new(MockSuccessProtocol));
        let config = AttackConfigBuilder::new().stop_on_first(true).max_tasks(1).build();
        let engine = Engine::new(registry, config);
        let strategy = Box::new(StaticStrategy::new(creds(10)));

        let (found, _rx) = engine.run(target(), strategy).await;
        assert_eq!(found.len(), 1, "stop_on_first should stop after first hit");
    }

    #[tokio::test]
    async fn failure_mock_finds_nothing() {
        let registry = mock_registry(Arc::new(MockFailureProtocol));
        let config = AttackConfigBuilder::new().build();
        let engine = Engine::new(registry, config);
        let strategy = Box::new(StaticStrategy::new(creds(5)));

        let (found, _rx) = engine.run(target(), strategy).await;
        assert!(found.is_empty(), "failure protocol should yield no credentials");
    }

    #[tokio::test]
    async fn unknown_protocol_returns_empty() {
        let reg = ProtocolRegistry::new();
        let engine = Engine::new(Arc::new(reg), AttackConfig::default());
        let strategy = Box::new(StaticStrategy::new(creds(2)));
        let bad_target = Target::new("127.0.0.1", 80, "nonexistent");

        let (found, _rx) = engine.run(bad_target, strategy).await;
        assert!(found.is_empty());
    }

    #[tokio::test]
    async fn error_protocol_retries_and_records_errors() {
        let registry = mock_registry(Arc::new(MockErrorProtocol));
        let config = AttackConfigBuilder::new()
            .max_retries(1)
            .stop_on_first(false)
            .build();
        let engine = Engine::new(registry, config);
        let strategy = Box::new(StaticStrategy::new(creds(2)));

        let (found, mut rx) = engine.run(target(), strategy).await;
        assert!(found.is_empty());

        let mut finished = None;
        while let Ok(ev) = rx.try_recv() {
            if let ProgressEvent::SessionFinished { errors, .. } = ev {
                finished = Some(errors);
            }
        }
        assert_eq!(finished, Some(2));
    }

    #[tokio::test]
    async fn rate_limit_protocol_bumps_counter() {
        let calls = Arc::new(AtomicU64::new(0));
        let proto = MockRateLimitProtocol { calls: Arc::clone(&calls) };
        let registry = mock_registry(Arc::new(proto));
        let config = AttackConfigBuilder::new()
            .max_retries(0)
            .stop_on_first(false)
            .build();
        let engine = Engine::new(registry, config);
        let strategy = Box::new(StaticStrategy::new(creds(1)));

        let (found, mut rx) = engine.run(target(), strategy).await;
        assert!(found.is_empty());

        let mut rl_count = 0u64;
        while let Ok(ev) = rx.try_recv() {
            if let ProgressEvent::SessionFinished { rate_limits, .. } = ev {
                rl_count = rate_limits;
            }
        }
        assert!(rl_count >= 1, "expected at least one rate_limit recorded");
    }

    #[tokio::test]
    async fn session_finished_carries_stats() {
        let registry = mock_registry(Arc::new(MockFailureProtocol));
        let config = AttackConfigBuilder::new().stop_on_first(false).build();
        let engine = Engine::new(registry, config);
        let strategy = Box::new(StaticStrategy::new(creds(4)));

        let (_found, mut rx) = engine.run(target(), strategy).await;

        let mut finished = false;
        while let Ok(ev) = rx.try_recv() {
            if let ProgressEvent::SessionFinished {
                total_attempts,
                failures,
                successes,
                ..
            } = ev
            {
                assert_eq!(total_attempts, 4);
                assert_eq!(failures, 4);
                assert_eq!(successes, 0);
                finished = true;
            }
        }
        assert!(finished, "SessionFinished not received");
    }

    #[tokio::test]
    async fn stop_on_first_strategy_wired_to_engine() {
        // StopOnFirstStrategy should trigger cancellation independently of
        // config.stop_on_first — wire it to an engine with stop_on_first=false
        // to verify the strategy alone is sufficient.
        let registry = mock_registry(Arc::new(MockSuccessProtocol));
        let config = AttackConfigBuilder::new()
            .stop_on_first(false)
            .max_tasks(1)
            .build();
        let engine = Engine::new(registry, config)
            .with_dispatch_strategy(Arc::new(StopOnFirstStrategy));
        let strategy = Box::new(StaticStrategy::new(creds(10)));

        let (found, _rx) = engine.run(target(), strategy).await;
        assert_eq!(found.len(), 1, "StopOnFirstStrategy must stop after first success");
    }
}
