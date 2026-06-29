//! Integration tests for zeus-engine public API.
//!
//! Covers: DispatchStrategy implementations, SessionStats, AttackSession.

use std::time::Duration;
use zeus_core::{AttackConfig, AttackResult, Credential};
use zeus_engine::{DispatchStrategy, SequentialStrategy, SessionStats, StopOnFirstStrategy};

// ── helpers ───────────────────────────────────────────────────────────────────

fn cred(user: &str, pass: &str) -> Credential {
    Credential::new(user.to_string(), pass.to_string())
}

fn success_result() -> AttackResult {
    AttackResult::Success {
        credential: cred("admin", "pass"),
        elapsed: Duration::from_millis(10),
    }
}

fn failure_result() -> AttackResult {
    AttackResult::Failure
}

fn default_config() -> AttackConfig {
    AttackConfig::default()
}

// ── SequentialStrategy ────────────────────────────────────────────────────────

#[test]
fn sequential_never_stops_on_success() {
    let strategy = SequentialStrategy;
    assert!(!strategy.should_stop(&success_result(), &default_config()));
}

#[test]
fn sequential_never_stops_on_failure() {
    let strategy = SequentialStrategy;
    assert!(!strategy.should_stop(&failure_result(), &default_config()));
}

#[test]
fn sequential_next_batch_returns_slice() {
    let strategy = SequentialStrategy;
    let all = vec![
        cred("a", "1"),
        cred("b", "2"),
        cred("c", "3"),
        cred("d", "4"),
    ];
    let batch = strategy.next_batch(&all, 0, 2);
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[0].username, "a");
    assert_eq!(batch[1].username, "b");
}

#[test]
fn sequential_next_batch_cursor_advance() {
    let strategy = SequentialStrategy;
    let all = vec![cred("a", "1"), cred("b", "2"), cred("c", "3")];
    let batch = strategy.next_batch(&all, 2, 5);
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].username, "c");
}

// ── StopOnFirstStrategy ───────────────────────────────────────────────────────

#[test]
fn stop_on_first_stops_on_success() {
    let strategy = StopOnFirstStrategy;
    assert!(strategy.should_stop(&success_result(), &default_config()));
}

#[test]
fn stop_on_first_continues_on_failure() {
    let strategy = StopOnFirstStrategy;
    assert!(!strategy.should_stop(&failure_result(), &default_config()));
}

#[test]
fn stop_on_first_continues_on_rate_limit() {
    let strategy = StopOnFirstStrategy;
    assert!(!strategy.should_stop(&AttackResult::RateLimit, &default_config()));
}

#[test]
fn stop_on_first_continues_on_error() {
    let strategy = StopOnFirstStrategy;
    assert!(!strategy.should_stop(&AttackResult::Error("oops".into()), &default_config()));
}

// ── SessionStats ─────────────────────────────────────────────────────────────

#[test]
fn session_stats_default_zeroed() {
    let stats = SessionStats::default();
    assert_eq!(stats.attempts, 0);
    assert_eq!(stats.successes, 0);
    assert_eq!(stats.failures, 0);
    assert_eq!(stats.errors, 0);
    assert_eq!(stats.rate_limits, 0);
}

#[test]
fn session_stats_manual_increment() {
    let mut stats = SessionStats::default();
    stats.attempts += 3;
    stats.successes += 1;
    stats.failures += 2;
    assert_eq!(stats.attempts, 3);
    assert_eq!(stats.successes, 1);
    assert_eq!(stats.failures, 2);
}

// ── AttackResult helpers ──────────────────────────────────────────────────────

#[test]
fn attack_result_is_success() {
    assert!(success_result().is_success());
    assert!(!failure_result().is_success());
    assert!(!AttackResult::RateLimit.is_success());
    assert!(!AttackResult::Timeout.is_success());
    assert!(!AttackResult::Error("x".into()).is_success());
}
