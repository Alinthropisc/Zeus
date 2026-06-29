//! Metrics registry, exporters, and snapshot types for zeus-engine.
//!
//! Patterns:
//!   - Singleton (via Arc): MetricsRegistry is shared across engine threads
//!   - Strategy: MetricsExporter trait with Prometheus, StatsD, and Log implementations

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;
use anyhow::Result;

// ---------------------------------------------------------------------------
// MetricsRegistry
// ---------------------------------------------------------------------------

/// Shared metrics registry. Create one with `MetricsRegistry::new()` and pass
/// the `Arc<MetricsRegistry>` to all engine components.
#[derive(Debug, Default)]
pub struct MetricsRegistry {
    pub attempts_total:    AtomicU64,
    pub successes_total:   AtomicU64,
    pub failures_total:    AtomicU64,
    pub errors_total:      AtomicU64,
    pub lockouts_detected: AtomicU64,
    pub timeouts_total:    AtomicU64,
    pub bytes_sent:        AtomicU64,
    pub bytes_recv:        AtomicU64,
    /// Per-protocol attempt counters.
    protocol_attempts: RwLock<HashMap<String, AtomicU64>>,
}

impl MetricsRegistry {
    /// Create a new registry wrapped in an `Arc`.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn inc_attempts(&self)  { self.attempts_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_successes(&self) { self.successes_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_failures(&self)  { self.failures_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_errors(&self)    { self.errors_total.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_lockouts(&self)  { self.lockouts_detected.fetch_add(1, Ordering::Relaxed); }
    pub fn inc_timeouts(&self)  { self.timeouts_total.fetch_add(1, Ordering::Relaxed); }

    pub fn add_bytes_sent(&self, n: u64) { self.bytes_sent.fetch_add(n, Ordering::Relaxed); }
    pub fn add_bytes_recv(&self, n: u64) { self.bytes_recv.fetch_add(n, Ordering::Relaxed); }

    /// Increment the per-protocol attempt counter for `proto`.
    pub fn inc_protocol(&self, proto: &str) {
        // Fast path: protocol already exists — just bump.
        {
            let read = self.protocol_attempts.read();
            if let Some(counter) = read.get(proto) {
                counter.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // Slow path: insert a new counter (write lock, re-check to avoid TOCTOU).
        let mut write = self.protocol_attempts.write();
        write
            .entry(proto.to_owned())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Read all atomic values into a plain `MetricsSnapshot`.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let attempts  = self.attempts_total.load(Ordering::Relaxed);
        let successes = self.successes_total.load(Ordering::Relaxed);

        let success_rate = if attempts > 0 {
            successes as f64 / attempts as f64
        } else {
            0.0
        };

        let protocol_attempts = {
            let read = self.protocol_attempts.read();
            read.iter()
                .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
                .collect()
        };

        MetricsSnapshot {
            attempts_total:    attempts,
            successes_total:   successes,
            failures_total:    self.failures_total.load(Ordering::Relaxed),
            errors_total:      self.errors_total.load(Ordering::Relaxed),
            lockouts_detected: self.lockouts_detected.load(Ordering::Relaxed),
            timeouts_total:    self.timeouts_total.load(Ordering::Relaxed),
            bytes_sent:        self.bytes_sent.load(Ordering::Relaxed),
            bytes_recv:        self.bytes_recv.load(Ordering::Relaxed),
            protocol_attempts,
            success_rate,
            timestamp: std::time::SystemTime::now(),
        }
    }
}

// ---------------------------------------------------------------------------
// MetricsSnapshot
// ---------------------------------------------------------------------------

/// A point-in-time copy of all metrics — cheap to clone and send across threads.
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub attempts_total:    u64,
    pub successes_total:   u64,
    pub failures_total:    u64,
    pub errors_total:      u64,
    pub lockouts_detected: u64,
    pub timeouts_total:    u64,
    pub bytes_sent:        u64,
    pub bytes_recv:        u64,
    /// Per-protocol attempt counts.
    pub protocol_attempts: HashMap<String, u64>,
    /// `successes / attempts`, or `0.0` when `attempts == 0`.
    pub success_rate:      f64,
    pub timestamp:         std::time::SystemTime,
}

// ---------------------------------------------------------------------------
// MetricsExporter trait (Strategy pattern)
// ---------------------------------------------------------------------------

/// Strategy trait for serialising a `MetricsSnapshot` into a specific wire format.
pub trait MetricsExporter: Send + Sync {
    /// Serialise `snapshot` and return the formatted string.
    fn export(&self, snapshot: &MetricsSnapshot) -> Result<String>;
    /// Human-readable format name for logging/debugging.
    fn format_name(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// PrometheusExporter
// ---------------------------------------------------------------------------

/// Emits Prometheus text exposition format (version 0.0.4).
///
/// Each metric gets a `# HELP` comment, a `# TYPE` line, and a sample line.
#[derive(Debug)]
pub struct PrometheusExporter {
    /// Metric name prefix, e.g. `"zeus"`.
    pub namespace: String,
}

impl PrometheusExporter {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self { namespace: namespace.into() }
    }

    fn counter(&self, out: &mut String, name: &str, help: &str, value: u64) {
        let full = format!("{}_{}", self.namespace, name);
        out.push_str(&format!("# HELP {full} {help}\n"));
        out.push_str(&format!("# TYPE {full} counter\n"));
        out.push_str(&format!("{full} {value}\n"));
    }

    fn gauge(&self, out: &mut String, name: &str, help: &str, value: f64) {
        let full = format!("{}_{}", self.namespace, name);
        out.push_str(&format!("# HELP {full} {help}\n"));
        out.push_str(&format!("# TYPE {full} gauge\n"));
        out.push_str(&format!("{full} {value:.6}\n"));
    }
}

impl MetricsExporter for PrometheusExporter {
    fn format_name(&self) -> &'static str { "prometheus" }

    fn export(&self, snap: &MetricsSnapshot) -> Result<String> {
        let mut out = String::with_capacity(1024);

        self.counter(&mut out, "attempts_total",    "Total probe attempts",              snap.attempts_total);
        self.counter(&mut out, "successes_total",   "Total successful authentications",  snap.successes_total);
        self.counter(&mut out, "failures_total",    "Total failed authentications",      snap.failures_total);
        self.counter(&mut out, "errors_total",      "Total transient/protocol errors",   snap.errors_total);
        self.counter(&mut out, "lockouts_detected", "Total account lockouts detected",   snap.lockouts_detected);
        self.counter(&mut out, "timeouts_total",    "Total connection timeouts",         snap.timeouts_total);
        self.counter(&mut out, "bytes_sent",        "Total bytes sent to targets",       snap.bytes_sent);
        self.counter(&mut out, "bytes_recv",        "Total bytes received from targets", snap.bytes_recv);
        self.gauge(&mut out,   "success_rate",      "Fraction of attempts that succeeded (0-1)", snap.success_rate);

        // Per-protocol counters with a `protocol` label.
        let proto_full = format!("{}_protocol_attempts_total", self.namespace);
        if !snap.protocol_attempts.is_empty() {
            out.push_str(&format!("# HELP {proto_full} Attempts per protocol\n"));
            out.push_str(&format!("# TYPE {proto_full} counter\n"));
            // Sort for deterministic output in tests.
            let mut pairs: Vec<_> = snap.protocol_attempts.iter().collect();
            pairs.sort_by_key(|(k, _)| k.as_str());
            for (proto, count) in pairs {
                out.push_str(&format!("{proto_full}{{protocol=\"{proto}\"}} {count}\n"));
            }
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// StatsdExporter
// ---------------------------------------------------------------------------

/// Emits StatsD line protocol.
///
/// Counters use the `|c` type suffix; gauges use `|g`.
#[derive(Debug)]
pub struct StatsdExporter {
    /// Metric name prefix, e.g. `"zeus.engine"`.
    pub prefix: String,
}

impl StatsdExporter {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self { prefix: prefix.into() }
    }
}

impl MetricsExporter for StatsdExporter {
    fn format_name(&self) -> &'static str { "statsd" }

    fn export(&self, snap: &MetricsSnapshot) -> Result<String> {
        let p = &self.prefix;
        let mut lines = Vec::with_capacity(16);

        lines.push(format!("{p}.attempts_total:{v}|c",    v = snap.attempts_total));
        lines.push(format!("{p}.successes_total:{v}|c",   v = snap.successes_total));
        lines.push(format!("{p}.failures_total:{v}|c",    v = snap.failures_total));
        lines.push(format!("{p}.errors_total:{v}|c",      v = snap.errors_total));
        lines.push(format!("{p}.lockouts_detected:{v}|c", v = snap.lockouts_detected));
        lines.push(format!("{p}.timeouts_total:{v}|c",    v = snap.timeouts_total));
        lines.push(format!("{p}.bytes_sent:{v}|c",        v = snap.bytes_sent));
        lines.push(format!("{p}.bytes_recv:{v}|c",        v = snap.bytes_recv));
        lines.push(format!("{p}.success_rate:{v:.6}|g",   v = snap.success_rate));

        let mut proto_pairs: Vec<_> = snap.protocol_attempts.iter().collect();
        proto_pairs.sort_by_key(|(k, _)| k.as_str());
        for (proto, count) in proto_pairs {
            lines.push(format!("{p}.protocol.{proto}.attempts_total:{count}|c"));
        }

        Ok(lines.join("\n"))
    }
}

// ---------------------------------------------------------------------------
// LogExporter
// ---------------------------------------------------------------------------

/// Emits a human-readable summary table suitable for `--metrics-log` flag output.
#[derive(Debug)]
pub struct LogExporter;

impl MetricsExporter for LogExporter {
    fn format_name(&self) -> &'static str { "log" }

    fn export(&self, snap: &MetricsSnapshot) -> Result<String> {
        let rate_pct = snap.success_rate * 100.0;
        let mut out = format!(
            "Attempts: {a} | Successes: {s} | Failures: {f} | Errors: {e} | \
             Rate: {r:.2}% | Lockouts: {l} | Timeouts: {t} | \
             Bytes sent: {bs} | Bytes recv: {br}",
            a  = snap.attempts_total,
            s  = snap.successes_total,
            f  = snap.failures_total,
            e  = snap.errors_total,
            r  = rate_pct,
            l  = snap.lockouts_detected,
            t  = snap.timeouts_total,
            bs = snap.bytes_sent,
            br = snap.bytes_recv,
        );

        if !snap.protocol_attempts.is_empty() {
            out.push_str(" | Protocols: {");
            let mut pairs: Vec<_> = snap.protocol_attempts.iter().collect();
            pairs.sort_by_key(|(k, _)| k.as_str());
            let proto_str: Vec<String> = pairs
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            out.push_str(&proto_str.join(", "));
            out.push('}');
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_starts_at_zero() {
        let reg = MetricsRegistry::new();
        let snap = reg.snapshot();
        assert_eq!(snap.attempts_total, 0);
        assert_eq!(snap.successes_total, 0);
        assert_eq!(snap.failures_total, 0);
        assert_eq!(snap.errors_total, 0);
        assert_eq!(snap.lockouts_detected, 0);
        assert_eq!(snap.timeouts_total, 0);
        assert_eq!(snap.bytes_sent, 0);
        assert_eq!(snap.bytes_recv, 0);
        assert!(snap.protocol_attempts.is_empty());
    }

    #[test]
    fn inc_attempts_five_times() {
        let reg = MetricsRegistry::new();
        for _ in 0..5 {
            reg.inc_attempts();
        }
        let snap = reg.snapshot();
        assert_eq!(snap.attempts_total, 5);
    }

    #[test]
    fn success_rate_no_div_by_zero_when_attempts_zero() {
        let reg = MetricsRegistry::new();
        let snap = reg.snapshot();
        assert_eq!(snap.success_rate, 0.0, "must not divide by zero");
    }

    #[test]
    fn success_rate_computed_correctly() {
        let reg = MetricsRegistry::new();
        for _ in 0..10 { reg.inc_attempts(); }
        for _ in 0..4  { reg.inc_successes(); }
        let snap = reg.snapshot();
        let expected = 4.0_f64 / 10.0_f64;
        let diff = (snap.success_rate - expected).abs();
        assert!(diff < 1e-9, "success_rate mismatch: {}", snap.success_rate);
    }

    #[test]
    fn inc_protocol_tracks_per_protocol() {
        let reg = MetricsRegistry::new();
        reg.inc_protocol("ssh");
        reg.inc_protocol("ssh");
        reg.inc_protocol("ftp");
        let snap = reg.snapshot();
        assert_eq!(snap.protocol_attempts.get("ssh").copied(), Some(2));
        assert_eq!(snap.protocol_attempts.get("ftp").copied(), Some(1));
    }

    #[test]
    fn prometheus_exporter_contains_help_and_type_lines() {
        let reg = MetricsRegistry::new();
        reg.inc_attempts();
        reg.inc_successes();
        reg.inc_protocol("ssh");

        let snap = reg.snapshot();
        let exp = PrometheusExporter::new("zeus");
        let output = exp.export(&snap).expect("export failed");

        assert!(output.contains("# HELP"), "missing # HELP:\n{output}");
        assert!(output.contains("# TYPE"), "missing # TYPE:\n{output}");
        assert!(output.contains("zeus_attempts_total 1"), "counter value missing:\n{output}");
        assert!(
            output.contains("zeus_protocol_attempts_total{protocol=\"ssh\"} 1"),
            "protocol label missing:\n{output}"
        );
    }

    #[test]
    fn statsd_exporter_contains_counter_and_gauge_suffixes() {
        let reg = MetricsRegistry::new();
        reg.inc_attempts();
        reg.inc_successes();

        let snap = reg.snapshot();
        let exp = StatsdExporter::new("zeus.engine");
        let output = exp.export(&snap).expect("export failed");

        assert!(output.contains("|c"), "missing |c counter suffix:\n{output}");
        assert!(output.contains("|g"), "missing |g gauge suffix:\n{output}");
        assert!(
            output.contains("zeus.engine.attempts_total:1|c"),
            "attempts counter wrong:\n{output}"
        );
        assert!(
            output.contains("zeus.engine.success_rate:"),
            "success_rate gauge missing:\n{output}"
        );
    }

    #[test]
    fn log_exporter_output_is_non_empty() {
        let reg = MetricsRegistry::new();
        reg.inc_attempts();
        let snap = reg.snapshot();
        let exp = LogExporter;
        let output = exp.export(&snap).expect("export failed");
        assert!(!output.is_empty(), "LogExporter output must not be empty");
        assert!(output.contains("Attempts:"), "missing Attempts field:\n{output}");
    }

    #[test]
    fn bytes_accounting() {
        let reg = MetricsRegistry::new();
        reg.add_bytes_sent(1024);
        reg.add_bytes_recv(512);
        let snap = reg.snapshot();
        assert_eq!(snap.bytes_sent, 1024);
        assert_eq!(snap.bytes_recv, 512);
    }
}
