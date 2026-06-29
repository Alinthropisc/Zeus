//! Session lifecycle — State Machine pattern.
//!
//! `AttackSession` models the full lifecycle of an attack:
//!   Pending → Running → Paused ↔ Running → Completed | Cancelled | Failed
//!
//! The original `SessionState` (Memento) and existing tests are preserved.

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use zeus_core::Credential;

// ---------------------------------------------------------------------------
// SessionStats
// ---------------------------------------------------------------------------

/// Running statistics for an attack session.
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    pub attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub errors: u64,
    pub rate_limits: u64,
    pub timeouts: u64,
    pub elapsed: Duration,
    pub rate_per_second: f64,
    pub peak_rps: f64,
}

impl SessionStats {
    /// Recompute `rate_per_second` from current counters and update `peak_rps`.
    pub fn update_rps(&mut self) {
        if self.elapsed.as_secs_f64() > 0.0 {
            self.rate_per_second = self.attempts as f64 / self.elapsed.as_secs_f64();
            if self.rate_per_second > self.peak_rps {
                self.peak_rps = self.rate_per_second;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SessionStatus — state machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum SessionStatus {
    /// Created but not yet started.
    Pending,
    /// Actively running workers.
    Running,
    /// Temporarily paused; can be resumed.
    Paused,
    /// Attack finished normally.
    Completed,
    /// Cancelled by the operator.
    Cancelled,
    /// Failed due to an unrecoverable error.
    Failed(String),
}

// ---------------------------------------------------------------------------
// AttackSession — state machine implementation
// ---------------------------------------------------------------------------

/// Full lifecycle manager for a single attack against one target.
pub struct AttackSession {
    pub id: String,
    pub target: String,
    pub protocol: String,
    pub status: SessionStatus,
    pub stats: SessionStats,
    pub started_at: Option<Instant>,
    pub completed_at: Option<Instant>,
}

impl AttackSession {
    pub fn new(
        id: impl Into<String>,
        target: impl Into<String>,
        protocol: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            target: target.into(),
            protocol: protocol.into(),
            status: SessionStatus::Pending,
            stats: SessionStats::default(),
            started_at: None,
            completed_at: None,
        }
    }

    /// Transition Pending → Running.
    pub fn start(&mut self) {
        self.status = SessionStatus::Running;
        self.started_at = Some(Instant::now());
    }

    /// Transition Running → Paused.
    pub fn pause(&mut self) {
        if self.status == SessionStatus::Running {
            self.status = SessionStatus::Paused;
        }
    }

    /// Transition Paused → Running.
    pub fn resume(&mut self) {
        if self.status == SessionStatus::Paused {
            self.status = SessionStatus::Running;
        }
    }

    /// Transition Running | Paused → Completed.
    pub fn complete(&mut self, stats: SessionStats) {
        self.stats = stats;
        self.status = SessionStatus::Completed;
        self.completed_at = Some(Instant::now());
    }

    /// Transition any non-terminal state → Cancelled.
    pub fn cancel(&mut self) {
        if !self.is_terminal() {
            self.status = SessionStatus::Cancelled;
            self.completed_at = Some(Instant::now());
        }
    }

    /// Transition any non-terminal state → Failed.
    pub fn fail(&mut self, reason: impl Into<String>) {
        if !self.is_terminal() {
            self.status = SessionStatus::Failed(reason.into());
            self.completed_at = Some(Instant::now());
        }
    }

    /// True for Completed, Cancelled, and Failed — no further transitions allowed.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            SessionStatus::Completed | SessionStatus::Cancelled | SessionStatus::Failed(_)
        )
    }

    /// Wall-clock duration from start to completion (or now if still running).
    pub fn duration(&self) -> Option<Duration> {
        let start = self.started_at?;
        let end = self.completed_at.unwrap_or_else(Instant::now);
        Some(end.duration_since(start))
    }
}

// ---------------------------------------------------------------------------
// Legacy types — preserved for backward compatibility
// ---------------------------------------------------------------------------

/// Serialisable snapshot of an attack session for persistence and resume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub id: String,
    pub found: Vec<Credential>,
    pub attempts: u64,
    pub resume_from: Option<u64>,
}

/// Legacy session struct kept for callers that use the old API.
pub struct LegacySession {
    pub id: String,
    pub status: LegacyStatus,
    pub found: Vec<Credential>,
    pub attempts: u64,
    pub started_at: Instant,
    pub elapsed: Option<Duration>,
    pub resume_from: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyStatus {
    Running,
    Finished,
    Aborted,
}

impl LegacySession {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: LegacyStatus::Running,
            found: vec![],
            attempts: 0,
            started_at: Instant::now(),
            elapsed: None,
            resume_from: None,
        }
    }

    pub fn restore(state: SessionState) -> Self {
        Self {
            id: state.id,
            status: LegacyStatus::Running,
            found: state.found,
            attempts: state.attempts,
            started_at: Instant::now(),
            elapsed: None,
            resume_from: state.resume_from,
        }
    }

    pub fn finish(&mut self, found: Vec<Credential>, attempts: u64) {
        self.found = found;
        self.attempts = attempts;
        self.status = LegacyStatus::Finished;
        self.elapsed = Some(self.started_at.elapsed());
    }

    pub fn save_state(&self) -> SessionState {
        SessionState {
            id: self.id.clone(),
            found: self.found.clone(),
            attempts: self.attempts,
            resume_from: Some(self.attempts),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Legacy tests — must keep passing
    // ------------------------------------------------------------------

    #[test]
    fn new_session_is_running() {
        let s = LegacySession::new("test-1");
        assert_eq!(s.status, LegacyStatus::Running);
        assert_eq!(s.id, "test-1");
        assert_eq!(s.attempts, 0);
        assert!(s.found.is_empty());
        assert!(s.resume_from.is_none());
    }

    #[test]
    fn finish_session() {
        let mut s = LegacySession::new("test-2");
        let creds = vec![Credential::new("admin", "pass")];
        s.finish(creds.clone(), 42);
        assert_eq!(s.status, LegacyStatus::Finished);
        assert_eq!(s.attempts, 42);
        assert_eq!(s.found.len(), 1);
        assert!(s.elapsed.is_some());
    }

    #[test]
    fn status_variants_distinct() {
        assert_ne!(LegacyStatus::Running, LegacyStatus::Finished);
        assert_ne!(LegacyStatus::Running, LegacyStatus::Aborted);
    }

    #[test]
    fn aborted_session_has_none_elapsed() {
        let mut s = LegacySession::new("test-abort");
        s.status = LegacyStatus::Aborted;
        assert!(s.elapsed.is_none());
    }

    #[test]
    fn resume_from_preserves_id() {
        let state = SessionState {
            id: "session-xyz".into(),
            found: vec![],
            attempts: 100,
            resume_from: Some(100),
        };
        let s = LegacySession::restore(state);
        assert_eq!(s.id, "session-xyz");
        assert_eq!(s.resume_from, Some(100));
        assert_eq!(s.status, LegacyStatus::Running);
    }

    #[test]
    fn save_state_round_trips() {
        let mut s = LegacySession::new("round-trip");
        s.attempts = 50;
        s.found.push(Credential::new("root", "toor"));

        let state = s.save_state();
        assert_eq!(state.id, "round-trip");
        assert_eq!(state.attempts, 50);
        assert_eq!(state.resume_from, Some(50));
        assert_eq!(state.found.len(), 1);

        let restored = LegacySession::restore(state);
        assert_eq!(restored.id, "round-trip");
        assert_eq!(restored.resume_from, Some(50));
        assert_eq!(restored.found.len(), 1);
    }

    #[test]
    fn save_state_is_serializable() {
        let mut s = LegacySession::new("serde-test");
        s.attempts = 7;
        let state = s.save_state();
        let json = serde_json::to_string(&state).expect("serialization failed");
        let decoded: SessionState = serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(decoded.id, state.id);
        assert_eq!(decoded.attempts, state.attempts);
    }

    // ------------------------------------------------------------------
    // New AttackSession state machine tests
    // ------------------------------------------------------------------

    #[test]
    fn session_state_transitions() {
        let mut s = AttackSession::new("s1", "host:22", "ssh");
        assert_eq!(s.status, SessionStatus::Pending);

        s.start();
        assert_eq!(s.status, SessionStatus::Running);

        s.pause();
        assert_eq!(s.status, SessionStatus::Paused);

        s.resume();
        assert_eq!(s.status, SessionStatus::Running);

        s.complete(SessionStats::default());
        assert_eq!(s.status, SessionStatus::Completed);
    }

    #[test]
    fn session_terminal_states() {
        let mut s = AttackSession::new("s2", "h", "p");
        s.start();
        assert!(!s.is_terminal());

        s.cancel();
        assert!(s.is_terminal());

        // Subsequent transitions are ignored.
        s.fail("oops");
        assert_eq!(s.status, SessionStatus::Cancelled);
    }

    #[test]
    fn session_failed_is_terminal() {
        let mut s = AttackSession::new("s3", "h", "p");
        s.start();
        s.fail("network error");
        assert!(s.is_terminal());
        assert!(matches!(s.status, SessionStatus::Failed(_)));
    }

    #[test]
    fn session_duration() {
        let mut s = AttackSession::new("s4", "h", "p");
        // Not started — no duration.
        assert!(s.duration().is_none());

        s.start();
        // Started but not completed — duration since start.
        assert!(s.duration().is_some());

        s.complete(SessionStats::default());
        let d = s.duration().unwrap();
        // Should be a very small duration (test runs fast).
        assert!(d < Duration::from_secs(5));
    }

    #[test]
    fn stats_rps_calculation() {
        let mut stats = SessionStats {
            attempts: 200,
            elapsed: Duration::from_secs(4),
            ..Default::default()
        };
        stats.update_rps();
        assert!((stats.rate_per_second - 50.0).abs() < 0.01);
        assert!((stats.peak_rps - 50.0).abs() < 0.01);

        // A subsequent lower rate should NOT lower peak.
        stats.attempts = 100;
        stats.elapsed = Duration::from_secs(10);
        stats.update_rps();
        assert!((stats.rate_per_second - 10.0).abs() < 0.01);
        assert!((stats.peak_rps - 50.0).abs() < 0.01);
    }
}
