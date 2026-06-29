//! Dispatch strategy — Strategy pattern for credential dispatching.
//!
//! Implement [`DispatchStrategy`] to control how credentials flow through the
//! engine without touching [`Engine`] itself (Open/Closed Principle).
//!
//! The engine depends on `dyn DispatchStrategy`, not a concrete type
//! (Dependency Inversion Principle).

use zeus_core::{AttackConfig, AttackResult, Credential};

// ─────────────────────────────────────────────────────────────────────────────
// Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Controls how a batch of credentials is selected and when to abort early.
///
/// Adding a new dispatch behaviour means adding a new struct — no changes to
/// [`Engine`] are required.
pub trait DispatchStrategy: Send + Sync {
    /// Select the next batch of credentials to dispatch from `credentials`,
    /// starting at `cursor`, up to `concurrency` items.
    fn next_batch(
        &self,
        credentials: &[Credential],
        cursor: usize,
        concurrency: usize,
    ) -> Vec<Credential>;

    /// Return `true` when the session should be cancelled after seeing `result`.
    fn should_stop(&self, result: &AttackResult, config: &AttackConfig) -> bool;
}

// ─────────────────────────────────────────────────────────────────────────────
// SequentialStrategy
// ─────────────────────────────────────────────────────────────────────────────

/// Default strategy: dispatch credentials in order, never stop early.
///
/// Early termination is governed entirely by [`AttackConfig::stop_on_first`];
/// this strategy itself never requests a stop.
pub struct SequentialStrategy;

impl DispatchStrategy for SequentialStrategy {
    fn next_batch(
        &self,
        credentials: &[Credential],
        cursor: usize,
        concurrency: usize,
    ) -> Vec<Credential> {
        let start = cursor.min(credentials.len());
        let end = credentials.len().min(cursor + concurrency);
        credentials[start..end].to_vec()
    }

    fn should_stop(&self, _result: &AttackResult, _config: &AttackConfig) -> bool {
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StopOnFirstStrategy
// ─────────────────────────────────────────────────────────────────────────────

/// Stops the session as soon as any credential succeeds, regardless of
/// [`AttackConfig::stop_on_first`].
pub struct StopOnFirstStrategy;

impl DispatchStrategy for StopOnFirstStrategy {
    fn next_batch(
        &self,
        credentials: &[Credential],
        cursor: usize,
        concurrency: usize,
    ) -> Vec<Credential> {
        let end = credentials.len().min(cursor + concurrency);
        credentials[cursor..end].to_vec()
    }

    fn should_stop(&self, result: &AttackResult, _config: &AttackConfig) -> bool {
        matches!(result, AttackResult::Success { .. })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use zeus_core::{AttackConfigBuilder, Credential};

    fn cred(u: &str, p: &str) -> Credential {
        Credential::new(u, p)
    }

    fn creds(n: usize) -> Vec<Credential> {
        (0..n)
            .map(|i| cred(&format!("u{i}"), &format!("p{i}")))
            .collect()
    }

    fn success() -> AttackResult {
        AttackResult::Success {
            credential: cred("u", "p"),
            elapsed: Duration::from_millis(1),
        }
    }

    fn config() -> AttackConfig {
        AttackConfigBuilder::new().build()
    }

    // ── SequentialStrategy ──────────────────────────────────────────────────

    #[test]
    fn sequential_next_batch_middle() {
        let s = SequentialStrategy;
        let all = creds(10);
        let batch = s.next_batch(&all, 3, 4);
        assert_eq!(batch.len(), 4);
        assert_eq!(batch[0].username, "u3");
        assert_eq!(batch[3].username, "u6");
    }

    #[test]
    fn sequential_next_batch_clamps_at_end() {
        let s = SequentialStrategy;
        let all = creds(5);
        let batch = s.next_batch(&all, 4, 10);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].username, "u4");
    }

    #[test]
    fn sequential_next_batch_empty_when_cursor_past_end() {
        let s = SequentialStrategy;
        let all = creds(3);
        let batch = s.next_batch(&all, 10, 4);
        assert!(batch.is_empty());
    }

    #[test]
    fn sequential_never_stops_on_success() {
        let s = SequentialStrategy;
        assert!(!s.should_stop(&success(), &config()));
    }

    #[test]
    fn sequential_never_stops_on_failure() {
        let s = SequentialStrategy;
        assert!(!s.should_stop(&AttackResult::Failure, &config()));
    }

    // ── StopOnFirstStrategy ─────────────────────────────────────────────────

    #[test]
    fn stop_on_first_stops_on_success() {
        let s = StopOnFirstStrategy;
        assert!(s.should_stop(&success(), &config()));
    }

    #[test]
    fn stop_on_first_does_not_stop_on_failure() {
        let s = StopOnFirstStrategy;
        assert!(!s.should_stop(&AttackResult::Failure, &config()));
    }

    #[test]
    fn stop_on_first_does_not_stop_on_error() {
        let s = StopOnFirstStrategy;
        assert!(!s.should_stop(&AttackResult::Error("oops".into()), &config()));
    }

    #[test]
    fn stop_on_first_batch_same_as_sequential() {
        let seq = SequentialStrategy;
        let sof = StopOnFirstStrategy;
        let all = creds(8);
        assert_eq!(seq.next_batch(&all, 2, 3), sof.next_batch(&all, 2, 3));
    }
}
