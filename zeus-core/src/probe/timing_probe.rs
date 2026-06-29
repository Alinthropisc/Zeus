//! Timing side-channel probes and password-spray support.
//!
//! # TimingProbe
//! Collects per-username response latency samples, then runs statistical
//! analysis to flag usernames whose latency is significantly higher than the
//! "invalid user" baseline — a classic timing oracle for user enumeration.
//!
//! # PasswordSpray
//! Holds a single password and iterates over a user list at a configurable
//! daily cadence using a token bucket, staying below lockout thresholds.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;

// ──────────────────────────────────────────────────────────────────────────────
// Error
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum TimingProbeError {
    #[error("not enough samples for username '{0}' (have {1}, need ≥ {2})")]
    InsufficientSamples(String, usize, usize),
    #[error("spray token bucket exhausted — daily limit reached")]
    SprayRateLimited,
}

// ──────────────────────────────────────────────────────────────────────────────
// TimingFinding
// ──────────────────────────────────────────────────────────────────────────────

/// A timing side-channel finding flagged by [`TimingProbe::analyze`].
#[derive(Debug, Clone)]
pub struct TimingFinding {
    /// The username flagged as potentially valid.
    pub username: String,
    /// Mean latency for this username.
    pub mean_ms: f64,
    /// Standard deviations above the baseline mean.
    pub sigma_above_baseline: f64,
    /// Brief human-readable description.
    pub description: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// TimingProbe
// ──────────────────────────────────────────────────────────────────────────────

/// Collects response-time samples per username and performs statistical
/// analysis to detect timing side-channels.
///
/// Detection criterion: a username whose mean latency exceeds the baseline
/// (average over all *other* samples) by more than `sigma_threshold` standard
/// deviations is flagged as a [`TimingFinding`].
#[derive(Debug, Clone)]
pub struct TimingProbe {
    /// Minimum samples per username before the username is included in analysis.
    pub min_samples: usize,
    /// Number of standard deviations above baseline mean to flag a username.
    pub sigma_threshold: f64,
    samples: Arc<Mutex<HashMap<String, Vec<Duration>>>>,
}

impl TimingProbe {
    /// Create a new probe.
    ///
    /// * `min_samples` — minimum samples before a username participates.
    /// * `sigma_threshold` — flag if `mean > baseline_mean + sigma * baseline_std`.
    pub fn new(min_samples: usize, sigma_threshold: f64) -> Self {
        Self {
            min_samples,
            sigma_threshold,
            samples: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Record one latency observation for `username`.
    ///
    /// Thread-safe; can be called concurrently from multiple tasks.
    pub async fn observe(&self, username: &str, duration: Duration) {
        let mut map = self.samples.lock().await;
        map.entry(username.to_string()).or_default().push(duration);
    }

    /// Run analysis over all collected samples.
    ///
    /// Returns the list of usernames whose mean latency exceeds the global
    /// baseline by more than `sigma_threshold` σ.
    pub async fn analyze(&self) -> Vec<TimingFinding> {
        let map = self.samples.lock().await;

        // Filter to usernames with enough samples.
        let eligible: Vec<(&String, &Vec<Duration>)> = map
            .iter()
            .filter(|(_, v)| v.len() >= self.min_samples)
            .collect();

        if eligible.is_empty() {
            return Vec::new();
        }

        // Compute per-username means (in milliseconds).
        let means: HashMap<&String, f64> = eligible
            .iter()
            .map(|(u, samples)| {
                let mean = samples
                    .iter()
                    .map(|d| d.as_secs_f64() * 1000.0)
                    .sum::<f64>()
                    / samples.len() as f64;
                (*u, mean)
            })
            .collect();

        // Flag usernames using leave-one-out baseline so the outlier
        // does not pull the baseline mean toward itself.
        let mut findings = Vec::new();
        for (username, mean_ms) in &means {
            let others: Vec<f64> = means
                .iter()
                .filter(|(u, _)| *u != username)
                .map(|(_, &m)| m)
                .collect();
            if others.is_empty() {
                continue;
            }
            let baseline_mean = others.iter().sum::<f64>() / others.len() as f64;
            let variance = others
                .iter()
                .map(|&m| (m - baseline_mean).powi(2))
                .sum::<f64>()
                / others.len() as f64;
            let baseline_std = variance.sqrt();
            let sigma_above = if baseline_std > 0.0 {
                (mean_ms - baseline_mean) / baseline_std
            } else if *mean_ms > baseline_mean {
                f64::INFINITY
            } else {
                0.0
            };
            if sigma_above > self.sigma_threshold {
                findings.push(TimingFinding {
                    username: (*username).clone(),
                    mean_ms: *mean_ms,
                    sigma_above_baseline: sigma_above,
                    description: format!(
                        "username '{}' mean latency {:.2} ms is {:.2}σ above baseline {:.2} ms — possible valid user",
                        username, mean_ms, sigma_above, baseline_mean
                    ),
                });
            }
        }

        // Sort descending by sigma so highest-confidence hits appear first.
        findings.sort_by(|a, b| {
            b.sigma_above_baseline
                .partial_cmp(&a.sigma_above_baseline)
                .unwrap()
        });
        findings
    }

    /// Return all raw samples for a specific username.
    pub async fn samples_for(&self, username: &str) -> Vec<Duration> {
        self.samples
            .lock()
            .await
            .get(username)
            .cloned()
            .unwrap_or_default()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// PasswordSpray
// ──────────────────────────────────────────────────────────────────────────────

/// Sprays a single password across a list of usernames at a controlled
/// daily cadence to avoid account lockout.
///
/// Uses a token bucket: one token = permission to attempt one credential pair.
/// Tokens refill at `requests_per_day / 86400` tokens per second.
#[derive(Debug)]
pub struct PasswordSpray {
    /// The single password used for all attempts.
    pub password: String,
    /// Maximum attempts per day.
    pub requests_per_day: u64,
    bucket: Arc<Mutex<SprayBucket>>,
}

#[derive(Debug)]
struct SprayBucket {
    tokens: u64,
    last_refill: std::time::Instant,
}

impl PasswordSpray {
    pub fn new(password: impl Into<String>, requests_per_day: u64) -> Self {
        Self {
            password: password.into(),
            requests_per_day,
            bucket: Arc::new(Mutex::new(SprayBucket {
                tokens: requests_per_day,
                last_refill: std::time::Instant::now(),
            })),
        }
    }

    /// Attempt to consume one token.
    ///
    /// Returns `Ok(())` if a token was available, or
    /// `Err(SprayRateLimited)` when the daily budget is exhausted.
    pub async fn acquire(&self) -> Result<(), TimingProbeError> {
        let mut bucket = self.bucket.lock().await;
        let elapsed = bucket.last_refill.elapsed();
        let day_secs = 86_400_f64;
        let accrued = (elapsed.as_secs_f64() / day_secs * self.requests_per_day as f64) as u64;
        if accrued > 0 {
            bucket.tokens = (bucket.tokens + accrued).min(self.requests_per_day);
            bucket.last_refill = std::time::Instant::now();
        }
        if bucket.tokens == 0 {
            return Err(TimingProbeError::SprayRateLimited);
        }
        bucket.tokens -= 1;
        Ok(())
    }

    /// Return the (password, username) pair to use for the next attempt,
    /// consuming one daily token.
    ///
    /// Returns `None` when `usernames` is empty.
    pub async fn next_attempt<'a>(
        &self,
        usernames: &[&'a str],
        index: usize,
    ) -> Result<Option<(&'a str, &str)>, TimingProbeError> {
        if usernames.is_empty() {
            return Ok(None);
        }
        self.acquire().await?;
        let user = usernames[index % usernames.len()];
        Ok(Some((user, &self.password)))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timing_probe_flags_high_latency_user() {
        let probe = TimingProbe::new(3, 2.0);

        // "alice" has uniformly low latency.
        for _ in 0..5 {
            probe.observe("alice", Duration::from_millis(10)).await;
        }
        // "bob" has uniformly low latency.
        for _ in 0..5 {
            probe.observe("bob", Duration::from_millis(12)).await;
        }
        // "carol" has significantly higher latency.
        for _ in 0..5 {
            probe.observe("carol", Duration::from_millis(200)).await;
        }

        let findings = probe.analyze().await;
        assert!(!findings.is_empty(), "carol should be flagged");
        assert_eq!(findings[0].username, "carol");
        assert!(findings[0].sigma_above_baseline > 2.0);
    }

    #[tokio::test]
    async fn timing_probe_no_findings_when_uniform() {
        let probe = TimingProbe::new(3, 2.0);
        for user in &["alice", "bob", "carol"] {
            for _ in 0..5 {
                probe.observe(user, Duration::from_millis(10)).await;
            }
        }
        let findings = probe.analyze().await;
        assert!(
            findings.is_empty(),
            "uniform latency should produce no findings"
        );
    }

    #[tokio::test]
    async fn timing_probe_respects_min_samples() {
        let probe = TimingProbe::new(5, 2.0);
        // Only 2 samples — below min_samples.
        probe
            .observe("sparse_user", Duration::from_millis(500))
            .await;
        probe
            .observe("sparse_user", Duration::from_millis(500))
            .await;
        let findings = probe.analyze().await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn password_spray_acquires_token() {
        let spray = PasswordSpray::new("Password1", 100);
        assert!(spray.acquire().await.is_ok());
    }

    #[tokio::test]
    async fn password_spray_exhausts_budget() {
        let spray = PasswordSpray::new("Password1", 1);
        spray.acquire().await.unwrap();
        // Second acquire should fail.
        assert!(matches!(
            spray.acquire().await,
            Err(TimingProbeError::SprayRateLimited)
        ));
    }

    #[tokio::test]
    async fn password_spray_next_attempt_cycles_users() {
        let spray = PasswordSpray::new("secret", 1000);
        let users = vec!["alice", "bob"];
        let attempt = spray.next_attempt(&users, 0).await.unwrap();
        assert_eq!(attempt, Some(("alice", "secret")));
        let attempt2 = spray.next_attempt(&users, 1).await.unwrap();
        assert_eq!(attempt2, Some(("bob", "secret")));
    }
}
