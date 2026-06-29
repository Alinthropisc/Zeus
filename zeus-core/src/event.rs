use crate::{AttackResult, Credential, Target};
use std::time::{Duration, Instant};

/// Observer pattern — events emitted by the engine.
#[derive(Debug, Clone)]
pub enum ProgressEvent {
    SessionStarted {
        target: Target,
        estimated_total: Option<u64>,
    },
    Attempt {
        credential: Credential,
        result: AttackResult,
        attempts_done: u64,
        started_at: Instant,
    },
    SessionFinished {
        found: Vec<Credential>,
        total_attempts: u64,
        elapsed: Duration,
        /// Per-category counters collected during the session.
        successes: u64,
        failures: u64,
        errors: u64,
        rate_limits: u64,
        timeouts: u64,
        rate_per_second: f64,
    },
    Warning(String),
    Stats {
        attempts_per_sec: f64,
        found: u64,
        remaining: Option<u64>,
    },
}
