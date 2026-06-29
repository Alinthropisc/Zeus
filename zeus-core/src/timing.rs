//! Timing attack detection — measures response-time deltas to detect user enumeration.
//!
//! Many authentication systems leak whether a username *exists* via response latency:
//! - Valid user + wrong password: the server looks up the user and hashes the password → slower
//! - Invalid user: the server short-circuits and returns immediately → faster
//!
//! A consistent delta > 50 ms is treated as evidence of user enumeration vulnerability.

use std::collections::HashMap;
use std::time::Duration;
use std::collections::VecDeque;

// ── TimingStats ───────────────────────────────────────────────────────────────

/// Rolling window of response-time measurements with summary statistics.
#[derive(Debug, Clone, Default)]
pub struct TimingStats {
    samples: VecDeque<Duration>,
    max_samples: usize,
}

impl TimingStats {
    /// Create a new stats collector that retains at most `max_samples` samples.
    pub fn new(max_samples: usize) -> Self {
        Self {
            samples: VecDeque::new(),
            max_samples,
        }
    }

    /// Record one measurement, evicting the oldest if the window is full.
    pub fn record(&mut self, d: Duration) {
        if self.samples.len() >= self.max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(d);
    }

    /// Arithmetic mean, or `None` when no samples have been recorded.
    pub fn mean(&self) -> Option<Duration> {
        if self.samples.is_empty() {
            return None;
        }
        let sum: Duration = self.samples.iter().sum();
        Some(sum / self.samples.len() as u32)
    }

    /// Median value (lower median for even-length sequences).
    pub fn median(&self) -> Option<Duration> {
        if self.samples.is_empty() {
            return None;
        }
        let mut sorted: Vec<Duration> = self.samples.iter().copied().collect();
        sorted.sort();
        Some(sorted[sorted.len() / 2])
    }

    /// Population standard deviation in milliseconds. Returns 0.0 with fewer than 2 samples.
    pub fn std_dev_ms(&self) -> f64 {
        if self.samples.len() < 2 {
            return 0.0;
        }
        let mean_ms = self.mean().unwrap_or_default().as_secs_f64() * 1000.0;
        let variance = self
            .samples
            .iter()
            .map(|d| {
                let diff = d.as_secs_f64() * 1000.0 - mean_ms;
                diff * diff
            })
            .sum::<f64>()
            / self.samples.len() as f64;
        variance.sqrt()
    }

    /// Minimum observed duration, or `None` if empty.
    pub fn min(&self) -> Option<Duration> {
        self.samples.iter().min().copied()
    }

    /// Maximum observed duration, or `None` if empty.
    pub fn max(&self) -> Option<Duration> {
        self.samples.iter().max().copied()
    }

    /// Number of samples currently held.
    pub fn count(&self) -> usize {
        self.samples.len()
    }

    /// `true` when no samples have been recorded.
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

// ── TimingAnalysis ────────────────────────────────────────────────────────────

/// Outcome of comparing valid-user timings against the invalid-user baseline.
#[derive(Debug, Clone)]
pub struct TimingAnalysis {
    /// The username under analysis.
    pub username: String,
    /// Mean response time (ms) when this username was used with a wrong password.
    pub valid_user_mean_ms: f64,
    /// Mean response time (ms) for requests with a provably non-existent username.
    pub invalid_user_mean_ms: f64,
    /// Absolute delta between the two means (ms).
    pub delta_ms: f64,
    /// `true` when the delta exceeds the configured threshold.
    pub is_vulnerable: bool,
    /// Confidence score in [0.0, 1.0] — ratio of delta to pooled standard deviation,
    /// clamped to 1.0.  Higher is more reliable.
    pub confidence: f64,
    /// Number of valid-user samples used.
    pub samples_valid: usize,
    /// Number of invalid-user baseline samples used.
    pub samples_invalid: usize,
}

impl TimingAnalysis {
    /// Compute an analysis, returning `None` if either stats bucket lacks `min_samples`
    /// measurements or has no mean yet.
    pub fn evaluate(
        valid_stats: &TimingStats,
        invalid_stats: &TimingStats,
        username: impl Into<String>,
        threshold_ms: f64,
        min_samples: usize,
    ) -> Option<Self> {
        let valid_mean = valid_stats.mean()?.as_secs_f64() * 1000.0;
        let invalid_mean = invalid_stats.mean()?.as_secs_f64() * 1000.0;

        if valid_stats.count() < min_samples || invalid_stats.count() < min_samples {
            return None;
        }

        let delta = (valid_mean - invalid_mean).abs();
        let is_vulnerable = delta > threshold_ms;

        // Confidence: signal-to-noise ratio capped at 1.0.
        let pooled_std = (valid_stats.std_dev_ms() + invalid_stats.std_dev_ms()) / 2.0;
        let confidence = if pooled_std > 0.0 {
            (delta / pooled_std).min(1.0)
        } else if is_vulnerable {
            1.0
        } else {
            0.0
        };

        Some(TimingAnalysis {
            username: username.into(),
            valid_user_mean_ms: valid_mean,
            invalid_user_mean_ms: invalid_mean,
            delta_ms: delta,
            is_vulnerable,
            confidence,
            samples_valid: valid_stats.count(),
            samples_invalid: invalid_stats.count(),
        })
    }
}

// ── TimingOracle ──────────────────────────────────────────────────────────────

/// Collects per-username timing measurements and compares them against a
/// known-invalid-user baseline to detect timing-based user enumeration.
pub struct TimingOracle {
    /// Per-username timing samples (user *may* exist).
    valid_user_timings: HashMap<String, TimingStats>,
    /// Baseline: timings for provably non-existent usernames.
    invalid_user_timings: TimingStats,
    /// Minimum number of samples required before an analysis is emitted.
    min_samples: usize,
    /// Delta threshold in milliseconds above which a username is flagged.
    threshold_ms: f64,
    /// Rolling window size per username.
    max_samples_per_user: usize,
}

impl TimingOracle {
    /// Construct a new oracle.
    ///
    /// * `min_samples` — samples required in each bucket before analysis is returned.
    /// * `threshold_ms` — delta threshold; 50.0 ms is a reasonable default.
    pub fn new(min_samples: usize, threshold_ms: f64) -> Self {
        Self {
            valid_user_timings: HashMap::new(),
            invalid_user_timings: TimingStats::new(200),
            min_samples,
            threshold_ms,
            max_samples_per_user: 100,
        }
    }

    /// Record a timing for a candidate username (the user *may* exist).
    pub fn record_attempt(&mut self, username: &str, elapsed: Duration) {
        let max = self.max_samples_per_user;
        let stats = self
            .valid_user_timings
            .entry(username.to_string())
            .or_insert_with(|| TimingStats::new(max));
        stats.record(elapsed);
    }

    /// Record a timing for a known-bogus username — this builds the "does not exist" baseline.
    pub fn record_invalid_baseline(&mut self, elapsed: Duration) {
        self.invalid_user_timings.record(elapsed);
    }

    /// Analyse a single username and return a [`TimingAnalysis`] if enough data exists.
    pub fn analyze(&self, username: &str) -> Option<TimingAnalysis> {
        let valid_stats = self.valid_user_timings.get(username)?;
        TimingAnalysis::evaluate(
            valid_stats,
            &self.invalid_user_timings,
            username,
            self.threshold_ms,
            self.min_samples,
        )
    }

    /// Analyse every tracked username, skipping those with insufficient samples.
    pub fn analyze_all(&self) -> Vec<TimingAnalysis> {
        self.valid_user_timings
            .keys()
            .filter_map(|u| self.analyze(u))
            .collect()
    }

    /// Return usernames whose response-time delta exceeds the vulnerability threshold.
    pub fn vulnerable_usernames(&self) -> Vec<String> {
        self.analyze_all()
            .into_iter()
            .filter(|a| a.is_vulnerable)
            .map(|a| a.username)
            .collect()
    }

    /// Render a human-readable timing report.
    pub fn report(&self) -> String {
        let analyses = self.analyze_all();
        if analyses.is_empty() {
            return "No timing data collected yet.".to_string();
        }

        let mut lines = vec![
            "=== Timing Attack Analysis ===".to_string(),
            format!(
                "Baseline samples (invalid users): {}",
                self.invalid_user_timings.count()
            ),
            format!(
                "Baseline mean: {:.1}ms",
                self.invalid_user_timings
                    .mean()
                    .map(|d| d.as_secs_f64() * 1000.0)
                    .unwrap_or(0.0)
            ),
            String::new(),
        ];

        for a in &analyses {
            let vuln = if a.is_vulnerable { "VULNERABLE" } else { "OK" };
            lines.push(format!(
                "[{}] {} | valid={:.1}ms invalid={:.1}ms delta={:.1}ms confidence={:.0}% samples={}/{}",
                vuln,
                a.username,
                a.valid_user_mean_ms,
                a.invalid_user_mean_ms,
                a.delta_ms,
                a.confidence * 100.0,
                a.samples_valid,
                a.samples_invalid,
            ));
        }

        lines.join("\n")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(millis: u64) -> Duration {
        Duration::from_millis(millis)
    }

    // ── TimingStats ───────────────────────────────────────────────────────────

    #[test]
    fn timing_stats_mean() {
        let mut s = TimingStats::new(10);
        s.record(ms(10));
        s.record(ms(20));
        s.record(ms(30));
        let mean = s.mean().unwrap();
        assert_eq!(mean, ms(20), "mean of 10/20/30 ms should be 20 ms");
    }

    #[test]
    fn timing_stats_median_odd() {
        let mut s = TimingStats::new(10);
        s.record(ms(30));
        s.record(ms(10));
        s.record(ms(20));
        // sorted: [10, 20, 30] — median at index 1 = 20
        let median = s.median().unwrap();
        assert_eq!(median, ms(20));
    }

    #[test]
    fn timing_stats_std_dev() {
        let mut s = TimingStats::new(10);
        // values: 10, 20, 30  — mean = 20, variance = (100+0+100)/3 ≈ 66.67, std ≈ 8.165
        s.record(ms(10));
        s.record(ms(20));
        s.record(ms(30));
        let std = s.std_dev_ms();
        assert!(
            (std - 8.165).abs() < 0.01,
            "std_dev expected ~8.165, got {std:.4}"
        );
    }

    #[test]
    fn timing_stats_min_max() {
        let mut s = TimingStats::new(10);
        s.record(ms(5));
        s.record(ms(50));
        s.record(ms(25));
        assert_eq!(s.min().unwrap(), ms(5));
        assert_eq!(s.max().unwrap(), ms(50));
    }

    #[test]
    fn timing_stats_overflow_max_samples() {
        // Window of 3: the oldest sample must be evicted when a 4th is added.
        let mut s = TimingStats::new(3);
        s.record(ms(1));
        s.record(ms(2));
        s.record(ms(3));
        assert_eq!(s.count(), 3);

        s.record(ms(4)); // evicts ms(1)
        assert_eq!(s.count(), 3, "count must stay at max_samples");

        // Mean of [2, 3, 4] = 3
        assert_eq!(s.mean().unwrap(), ms(3));
        // Minimum must be ms(2), not ms(1) which was evicted
        assert_eq!(s.min().unwrap(), ms(2));
    }

    // ── TimingAnalysis ────────────────────────────────────────────────────────

    #[test]
    fn timing_analysis_vulnerable() {
        let mut valid = TimingStats::new(10);
        let mut invalid = TimingStats::new(10);

        // valid-user responses are ~150 ms
        for _ in 0..5 {
            valid.record(ms(150));
        }
        // invalid-user responses are ~50 ms
        for _ in 0..5 {
            invalid.record(ms(50));
        }

        let analysis = TimingAnalysis::evaluate(&valid, &invalid, "alice", 50.0, 5).unwrap();
        assert!(
            analysis.is_vulnerable,
            "delta of 100 ms should exceed 50 ms threshold"
        );
        assert!((analysis.delta_ms - 100.0).abs() < 0.5);
    }

    #[test]
    fn timing_analysis_not_vulnerable() {
        let mut valid = TimingStats::new(10);
        let mut invalid = TimingStats::new(10);

        for _ in 0..5 {
            valid.record(ms(52));
        }
        for _ in 0..5 {
            invalid.record(ms(50));
        }

        let analysis = TimingAnalysis::evaluate(&valid, &invalid, "bob", 50.0, 5).unwrap();
        assert!(
            !analysis.is_vulnerable,
            "delta of 2 ms should not exceed 50 ms threshold"
        );
    }

    #[test]
    fn timing_analysis_insufficient_samples() {
        let mut valid = TimingStats::new(10);
        let mut invalid = TimingStats::new(10);

        // Only 3 samples, but min_samples = 5
        for _ in 0..3 {
            valid.record(ms(200));
            invalid.record(ms(50));
        }

        let result = TimingAnalysis::evaluate(&valid, &invalid, "carol", 50.0, 5);
        assert!(result.is_none(), "should return None with insufficient samples");
    }

    // ── TimingOracle ──────────────────────────────────────────────────────────

    #[test]
    fn timing_oracle_record_and_analyze() {
        let mut oracle = TimingOracle::new(3, 50.0);

        // Build invalid baseline
        for _ in 0..3 {
            oracle.record_invalid_baseline(ms(30));
        }

        // Record valid-user timings for "dave"
        for _ in 0..3 {
            oracle.record_attempt("dave", ms(200));
        }

        let analysis = oracle.analyze("dave").expect("should have enough samples");
        assert!(analysis.is_vulnerable);
        assert_eq!(analysis.username, "dave");
    }

    #[test]
    fn timing_oracle_vulnerable_usernames() {
        let mut oracle = TimingOracle::new(3, 50.0);

        for _ in 0..3 {
            oracle.record_invalid_baseline(ms(30));
        }
        // "eve" is slow — vulnerable
        for _ in 0..3 {
            oracle.record_attempt("eve", ms(200));
        }
        // "frank" is fast — not vulnerable
        for _ in 0..3 {
            oracle.record_attempt("frank", ms(35));
        }

        let vuln = oracle.vulnerable_usernames();
        assert!(vuln.contains(&"eve".to_string()), "eve should be flagged");
        assert!(!vuln.contains(&"frank".to_string()), "frank should not be flagged");
    }

    #[test]
    fn timing_oracle_report_format() {
        let mut oracle = TimingOracle::new(2, 50.0);

        for _ in 0..2 {
            oracle.record_invalid_baseline(ms(30));
        }
        for _ in 0..2 {
            oracle.record_attempt("grace", ms(150));
        }

        let report = oracle.report();
        assert!(report.contains("Timing Attack Analysis"));
        assert!(report.contains("Baseline samples"));
        assert!(report.contains("grace"));
        assert!(report.contains("VULNERABLE") || report.contains("OK"));
    }

    #[test]
    fn timing_oracle_report_no_data() {
        let oracle = TimingOracle::new(5, 50.0);
        assert_eq!(oracle.report(), "No timing data collected yet.");
    }
}
