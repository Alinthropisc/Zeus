//! Observer pattern — engine event hooks that feed into MetricsRegistry.
//!
//! `MetricsObserver` implements `EngineObserver` and translates each engine
//! event into the appropriate registry increment, keeping the engine itself
//! free of any metrics coupling.

use std::sync::Arc;
use crate::metrics::MetricsRegistry;

// ---------------------------------------------------------------------------
// EngineObserver trait
// ---------------------------------------------------------------------------

/// Observer trait for engine lifecycle events.
///
/// Implement this to plug any behaviour (metrics, logging, alerting …) into
/// the engine without modifying engine internals.
pub trait EngineObserver: Send + Sync {
    fn on_attempt(&self, protocol: &str, target: &str);
    fn on_success(&self, protocol: &str, target: &str, credential: &str);
    fn on_failure(&self, protocol: &str, target: &str);
    fn on_error(&self, protocol: &str, detail: &str);
    fn on_lockout(&self, target: &str);
    fn on_timeout(&self, protocol: &str, target: &str);
}

// ---------------------------------------------------------------------------
// MetricsObserver
// ---------------------------------------------------------------------------

/// Translates engine events into `MetricsRegistry` increments.
#[derive(Debug)]
pub struct MetricsObserver {
    registry: Arc<MetricsRegistry>,
}

impl MetricsObserver {
    pub fn new(registry: Arc<MetricsRegistry>) -> Self {
        Self { registry }
    }
}

impl EngineObserver for MetricsObserver {
    fn on_attempt(&self, protocol: &str, _target: &str) {
        self.registry.inc_attempts();
        self.registry.inc_protocol(protocol);
    }

    fn on_success(&self, _protocol: &str, _target: &str, _credential: &str) {
        self.registry.inc_successes();
    }

    fn on_failure(&self, _protocol: &str, _target: &str) {
        self.registry.inc_failures();
    }

    fn on_error(&self, _protocol: &str, _detail: &str) {
        self.registry.inc_errors();
    }

    fn on_lockout(&self, _target: &str) {
        self.registry.inc_lockouts();
    }

    fn on_timeout(&self, _protocol: &str, _target: &str) {
        self.registry.inc_timeouts();
    }
}

// ---------------------------------------------------------------------------
// CompositeObserver  (fan-out to multiple observers)
// ---------------------------------------------------------------------------

/// Fan-out observer that delegates every event to a list of child observers.
///
/// Build one with [`CompositeObserver::new`] and chain `.add(obs)` calls.
#[derive(Debug, Default)]
pub struct CompositeObserver {
    observers: Vec<Box<dyn EngineObserver>>,
}

impl CompositeObserver {
    pub fn new() -> Self {
        Self { observers: vec![] }
    }

    /// Add an observer and return `self` for chaining.
    pub fn add(mut self, obs: impl EngineObserver + 'static) -> Self {
        self.observers.push(Box::new(obs));
        self
    }
}

impl EngineObserver for CompositeObserver {
    fn on_attempt(&self, p: &str, t: &str) {
        self.observers.iter().for_each(|o| o.on_attempt(p, t));
    }
    fn on_success(&self, p: &str, t: &str, c: &str) {
        self.observers.iter().for_each(|o| o.on_success(p, t, c));
    }
    fn on_failure(&self, p: &str, t: &str) {
        self.observers.iter().for_each(|o| o.on_failure(p, t));
    }
    fn on_error(&self, p: &str, d: &str) {
        self.observers.iter().for_each(|o| o.on_error(p, d));
    }
    fn on_lockout(&self, t: &str) {
        self.observers.iter().for_each(|o| o.on_lockout(t));
    }
    fn on_timeout(&self, p: &str, t: &str) {
        self.observers.iter().for_each(|o| o.on_timeout(p, t));
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn metrics_observer_routes_events_to_registry() {
        let registry = MetricsRegistry::new();
        let obs = MetricsObserver::new(Arc::clone(&registry));

        obs.on_attempt("ssh", "192.168.1.1");
        obs.on_attempt("ssh", "192.168.1.2");
        obs.on_success("ssh", "192.168.1.1", "root:toor");
        obs.on_failure("ftp", "192.168.1.3");
        obs.on_error("ssh", "connection refused");
        obs.on_lockout("192.168.1.1");
        obs.on_timeout("ssh", "192.168.1.4");

        let snap = registry.snapshot();
        assert_eq!(snap.attempts_total, 2);
        assert_eq!(snap.successes_total, 1);
        assert_eq!(snap.failures_total, 1);
        assert_eq!(snap.errors_total, 1);
        assert_eq!(snap.lockouts_detected, 1);
        assert_eq!(snap.timeouts_total, 1);
        assert_eq!(snap.protocol_attempts.get("ssh").copied(), Some(2));
    }

    /// A trivial observer that counts how many times `on_attempt` was called.
    struct CountingObserver(Arc<AtomicU64>);
    impl EngineObserver for CountingObserver {
        fn on_attempt(&self, _: &str, _: &str) { self.0.fetch_add(1, Ordering::Relaxed); }
        fn on_success(&self, _: &str, _: &str, _: &str) {}
        fn on_failure(&self, _: &str, _: &str) {}
        fn on_error(&self, _: &str, _: &str) {}
        fn on_lockout(&self, _: &str) {}
        fn on_timeout(&self, _: &str, _: &str) {}
    }

    #[test]
    fn composite_observer_fans_out_to_all_children() {
        let count_a = Arc::new(AtomicU64::new(0));
        let count_b = Arc::new(AtomicU64::new(0));

        let composite = CompositeObserver::new()
            .add(CountingObserver(Arc::clone(&count_a)))
            .add(CountingObserver(Arc::clone(&count_b)));

        composite.on_attempt("ssh", "host");
        composite.on_attempt("ftp", "host");

        assert_eq!(count_a.load(Ordering::Relaxed), 2);
        assert_eq!(count_b.load(Ordering::Relaxed), 2);
    }
}
