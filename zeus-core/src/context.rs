//! `ZeusContext` — facade pattern for shared worker state.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use uuid::Uuid;

use crate::credential_store::{CredentialStore, FoundCredential};

/// Shared state across all workers in an attack session.
///
/// All fields are wrapped in `Arc` so `worker_handle()` / `Clone` are cheap —
/// they share the same underlying state rather than copying it.
pub struct ZeusContext {
    /// Unique identifier for this session.
    pub session_id: String,
    /// Set to `true` to signal all workers to stop.
    cancel: Arc<AtomicBool>,
    /// Shared credential store — holds all found credentials.
    store: Arc<RwLock<CredentialStore>>,
    /// Total authentication attempts recorded.
    attempts: Arc<AtomicU64>,
    /// Successful authentications recorded.
    successes: Arc<AtomicU64>,
    /// Errors recorded.
    errors: Arc<AtomicU64>,
    /// When `true`, workers should pause their loop.
    paused: Arc<AtomicBool>,
    /// Wall-clock time when the context was first created.
    started_at: Instant,
}

impl ZeusContext {
    /// Create a context with a randomly-generated session ID.
    pub fn new() -> Self {
        Self::new_with_id(Uuid::new_v4().to_string())
    }

    /// Create a context with an explicit session ID.
    pub fn new_with_id(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            cancel: Arc::new(AtomicBool::new(false)),
            store: Arc::new(RwLock::new(CredentialStore::new())),
            attempts: Arc::new(AtomicU64::new(0)),
            successes: Arc::new(AtomicU64::new(0)),
            errors: Arc::new(AtomicU64::new(0)),
            paused: Arc::new(AtomicBool::new(false)),
            started_at: Instant::now(),
        }
    }

    // -----------------------------------------------------------------------
    // Cancel / pause control
    // -----------------------------------------------------------------------

    /// Signal all workers to stop.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    /// Returns `true` if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    /// Pause all workers (they will spin-wait in `wait_if_paused`).
    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    /// Resume paused workers.
    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    /// Returns `true` if the context is currently paused.
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Async spin-wait: yields for 100 ms while paused.
    ///
    /// Call this inside worker loops:
    /// ```ignore
    /// loop {
    ///     ctx.wait_if_paused().await;
    ///     if ctx.is_cancelled() { break; }
    ///     // ... do work ...
    /// }
    /// ```
    pub async fn wait_if_paused(&self) {
        while self.paused.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // -----------------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------------

    /// Increment the attempt counter by one.
    pub fn record_attempt(&self) {
        self.attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the success counter by one.
    pub fn record_success(&self) {
        self.successes.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the error counter by one.
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Total attempts recorded so far.
    pub fn attempts(&self) -> u64 {
        self.attempts.load(Ordering::Relaxed)
    }

    /// Total successes recorded so far.
    pub fn successes(&self) -> u64 {
        self.successes.load(Ordering::Relaxed)
    }

    /// Total errors recorded so far.
    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    /// Wall-clock time elapsed since the context was created.
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Attempts per second since the context was created.
    ///
    /// Returns `0.0` for the first millisecond to avoid division-by-zero.
    pub fn rate_per_second(&self) -> f64 {
        let secs = self.elapsed().as_secs_f64();
        if secs < 0.001 {
            return 0.0;
        }
        self.attempts() as f64 / secs
    }

    // -----------------------------------------------------------------------
    // Credential store access
    // -----------------------------------------------------------------------

    /// Add a found credential to the shared store.
    ///
    /// Returns `false` if an identical entry already exists (deduplication).
    pub fn add_found(&self, cred: FoundCredential) -> bool {
        self.store.write().add(cred)
    }

    /// Number of unique credentials found so far.
    pub fn found_count(&self) -> usize {
        self.store.read().count()
    }

    /// Snapshot of all found credentials at this moment.
    pub fn found_credentials(&self) -> Vec<FoundCredential> {
        self.store.read().all().to_vec()
    }

    // -----------------------------------------------------------------------
    // Worker handle
    // -----------------------------------------------------------------------

    /// Cheap clone of this context for use in a worker task.
    ///
    /// All clones share the same `Arc`-wrapped state, so mutations in one
    /// handle are immediately visible in all others.
    pub fn worker_handle(&self) -> Self {
        Self {
            session_id: self.session_id.clone(),
            cancel: Arc::clone(&self.cancel),
            store: Arc::clone(&self.store),
            attempts: Arc::clone(&self.attempts),
            successes: Arc::clone(&self.successes),
            errors: Arc::clone(&self.errors),
            paused: Arc::clone(&self.paused),
            started_at: self.started_at,
        }
    }
}

impl Default for ZeusContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ZeusContext {
    fn clone(&self) -> Self {
        self.worker_handle()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{credential_store::FoundCredential, Credential};

    fn found(user: &str, pass: &str, target: &str) -> FoundCredential {
        FoundCredential::new(Credential::new(user, pass), target, "ssh", 0)
    }

    #[test]
    fn context_cancel() {
        let ctx = ZeusContext::new();
        assert!(!ctx.is_cancelled());
        ctx.cancel();
        assert!(ctx.is_cancelled());
    }

    #[test]
    fn context_pause_resume() {
        let ctx = ZeusContext::new();
        assert!(!ctx.is_paused());
        ctx.pause();
        assert!(ctx.is_paused());
        ctx.resume();
        assert!(!ctx.is_paused());
    }

    #[test]
    fn context_stats_tracking() {
        let ctx = ZeusContext::new();
        ctx.record_attempt();
        ctx.record_attempt();
        ctx.record_success();
        ctx.record_error();
        assert_eq!(ctx.attempts(), 2);
        assert_eq!(ctx.successes(), 1);
        assert_eq!(ctx.errors(), 1);
    }

    #[test]
    fn context_clone_shares_state() {
        let ctx = ZeusContext::new();
        let clone = ctx.clone();
        clone.record_attempt();
        clone.record_attempt();
        assert_eq!(ctx.attempts(), 2);

        clone.cancel();
        assert!(ctx.is_cancelled());
    }

    #[test]
    fn worker_handle_shares_cancel() {
        let ctx = ZeusContext::new_with_id("test-session");
        let worker = ctx.worker_handle();
        assert_eq!(worker.session_id, "test-session");
        ctx.cancel();
        assert!(worker.is_cancelled());
    }

    #[test]
    fn found_credentials_dedup() {
        let ctx = ZeusContext::new();
        let c = found("admin", "pass", "host:22:ssh");
        assert!(ctx.add_found(c.clone()));
        assert!(!ctx.add_found(c));
        assert_eq!(ctx.found_count(), 1);
    }

    #[test]
    fn found_credentials_shared_across_handles() {
        let ctx = ZeusContext::new();
        let worker = ctx.worker_handle();
        worker.add_found(found("root", "toor", "h:22:ssh"));
        assert_eq!(ctx.found_count(), 1);
    }

    #[tokio::test]
    async fn wait_if_paused_returns_when_resumed() {
        let ctx = ZeusContext::new();
        ctx.pause();

        let worker = ctx.worker_handle();
        // Resume after a short delay on a separate task
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            worker.resume();
        });

        // Should unblock within ~250 ms
        tokio::time::timeout(Duration::from_millis(500), ctx.wait_if_paused())
            .await
            .expect("wait_if_paused should return after resume");
    }
}
