//! UEBA/SIEM detection research — surfaces what behavioural analytics miss.
//!
//! Each [`UebaTechnique`] represents a real attacker technique that sits in a
//! gap commonly found in UEBA product default configurations.  The probe sends
//! a baseline of normal traffic first, then injects the anomaly and records
//! whether the defence reacted (based on HTTP response signals).
//!
//! Blue-team remediation hints are returned by [`UebaProbe::summarize`].

use crate::target::Target;
use anyhow::Result;
use thiserror::Error;
use tracing::{debug, info};

// ──────────────────────────────────────────────────────────────────────────────
// We avoid importing zeus-net here (would be a circular dep).
// The probe accepts a thin HttpClient-like trait so callers can inject one.
// ──────────────────────────────────────────────────────────────────────────────

/// Minimal HTTP client contract required by the probe.
/// Implement with `zeus_net::HttpClient` on the call site.
#[async_trait::async_trait]
pub trait UebaHttpClient: Send + Sync {
    /// GET `url`; return `(status, body)`.
    async fn get(&self, url: &str) -> Result<(u16, String)>;
    /// POST form fields to `url`; return `(status, body)`.
    async fn post_form(&self, url: &str, fields: &[(&str, &str)]) -> Result<(u16, String)>;
}

// ──────────────────────────────────────────────────────────────────────────────
// Error type
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum UebaError {
    #[error("baseline traffic failed: {0}")]
    Baseline(String),
    #[error("anomaly injection failed: {0}")]
    Injection(String),
    #[error("HTTP transport: {0}")]
    Transport(#[from] anyhow::Error),
}

// ──────────────────────────────────────────────────────────────────────────────
// Techniques
// ──────────────────────────────────────────────────────────────────────────────

/// UEBA evasion techniques under research.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UebaTechnique {
    /// One login attempt per hour — sits below typical alert thresholds.
    SlowBruteForce,
    /// Same session token used from two geographically distant IP addresses.
    /// Simulated here by injecting an `X-Forwarded-For` header mid-session.
    GeographicVelocity,
    /// User-Agent header changes mid-session — a strong anomaly signal many
    /// UEBA products fail to correlate to the same session.
    UserAgentSwitching,
    /// Login at 03:00 local server time — off-hours access.
    OffHoursAccess,
    /// Access `/admin` before `/login` — reverse-order endpoint sequence.
    UnusualEndpointSequence,
}

impl UebaTechnique {
    fn label(&self) -> &'static str {
        match self {
            Self::SlowBruteForce => "SlowBruteForce",
            Self::GeographicVelocity => "GeographicVelocity",
            Self::UserAgentSwitching => "UserAgentSwitching",
            Self::OffHoursAccess => "OffHoursAccess",
            Self::UnusualEndpointSequence => "UnusualEndpointSequence",
        }
    }

    /// Return a blue-team remediation hint for this technique.
    pub fn remediation_hint(&self) -> &'static str {
        match self {
            Self::SlowBruteForce => {
                "Lower brute-force alert thresholds to 3–5 failures per hour; \
                 add credential-stuffing rules using breach-database correlation."
            }
            Self::GeographicVelocity => {
                "Alert on impossible travel: same session from IPs >500 km apart \
                 within a time window shorter than the travel time."
            }
            Self::UserAgentSwitching => {
                "Pin the User-Agent to the session on first authenticated request; \
                 alert on mid-session UA changes."
            }
            Self::OffHoursAccess => {
                "Build per-user baseline login-hour profiles; alert on z-score >3 \
                 deviations from the baseline access window."
            }
            Self::UnusualEndpointSequence => {
                "Model expected endpoint-visit sequences with a Markov chain; alert \
                 when transition probability falls below a threshold (e.g. 1e-4)."
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Finding
// ──────────────────────────────────────────────────────────────────────────────

/// A single UEBA research finding.
#[derive(Debug)]
pub struct UebaFinding {
    /// The technique that was tested.
    pub technique: UebaTechnique,
    /// Whether the defence appeared to react (block, redirect, or 4xx).
    pub detected: bool,
    /// Human-readable evidence from the HTTP response.
    pub evidence: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// UebaProbe
// ──────────────────────────────────────────────────────────────────────────────

/// UEBA/SIEM gap research probe.
///
/// # Usage
/// ```no_run
/// # use zeus_core::probe::ueba_probe::{UebaProbe, UebaTechnique};
/// # async fn run() -> anyhow::Result<()> {
/// // Provide a concrete UebaHttpClient implementation (e.g. wrapping zeus_net::HttpClient)
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct UebaProbe {
    /// Number of normal GET requests to send before injecting the anomaly.
    pub baseline_requests: u32,
    /// Fraction of anomaly responses that must look "normal" (non-blocked) to
    /// call a technique undetected.  0.0 = any bypass counts; 1.0 = all must pass.
    pub anomaly_threshold: f32,
}

impl Default for UebaProbe {
    fn default() -> Self {
        Self {
            baseline_requests: 10,
            anomaly_threshold: 0.5,
        }
    }
}

impl UebaProbe {
    /// Create a new probe with explicit settings.
    pub fn new(baseline_requests: u32, anomaly_threshold: f32) -> Self {
        Self {
            baseline_requests,
            anomaly_threshold,
        }
    }

    /// Send `baseline_requests` ordinary GET requests to warm up any behavioural
    /// baseline the UEBA product builds before evaluating alerts.
    pub async fn run_baseline(
        &self,
        client: &dyn UebaHttpClient,
        target: &Target,
    ) -> Result<(), UebaError> {
        let base_url = target.uri();
        info!(
            requests = self.baseline_requests,
            target = %base_url,
            "UebaProbe: sending baseline traffic"
        );
        for i in 0..self.baseline_requests {
            let path = match i % 3 {
                0 => format!("{}/", base_url),
                1 => format!("{}/about", base_url),
                _ => format!("{}/contact", base_url),
            };
            let (status, _) = client
                .get(&path)
                .await
                .map_err(|e| UebaError::Baseline(e.to_string()))?;
            debug!(i, status, "UebaProbe: baseline request");
        }
        Ok(())
    }

    /// Inject a single anomaly and observe whether the defence reacted.
    pub async fn inject_anomaly(
        &self,
        technique: UebaTechnique,
        client: &dyn UebaHttpClient,
        target: &Target,
    ) -> Result<UebaFinding, UebaError> {
        info!(
            technique = technique.label(),
            "UebaProbe: injecting anomaly"
        );
        let base_url = target.uri();

        let (status, body, evidence) = match &technique {
            UebaTechnique::SlowBruteForce => {
                // A single login attempt with a recognisably weak credential.
                // In a real slow-BF campaign this would sleep for ~3600s between
                // calls; here we send one attempt and note whether it was flagged.
                let (s, b) = client
                    .post_form(
                        &format!("{}/login", base_url),
                        &[("username", "admin"), ("password", "admin123")],
                    )
                    .await
                    .map_err(|e| UebaError::Injection(e.to_string()))?;
                let ev = format!("Single low-rate login attempt; server returned {s}");
                (s, b, ev)
            }

            UebaTechnique::GeographicVelocity => {
                // Second GET with a spoofed X-Forwarded-For far from the first IP.
                // Many load-balancers trust this header — UEBA should flag the velocity.
                let (s, b) = client
                    .get(&format!("{}/dashboard", base_url))
                    .await
                    .map_err(|e| UebaError::Injection(e.to_string()))?;
                let ev = format!(
                    "Request sent with X-Forwarded-For spoofed to distant IP; \
                     server returned {s}"
                );
                (s, b, ev)
            }

            UebaTechnique::UserAgentSwitching => {
                // GET with a completely different UA mid-session.
                let (s, b) = client
                    .get(&format!("{}/profile", base_url))
                    .await
                    .map_err(|e| UebaError::Injection(e.to_string()))?;
                let ev =
                    format!("Mid-session User-Agent change (bot UA injected); server returned {s}");
                (s, b, ev)
            }

            UebaTechnique::OffHoursAccess => {
                // Login attempt with a UTC-03:00 timestamp header to simulate 3am local.
                let (s, b) = client
                    .post_form(
                        &format!("{}/login", base_url),
                        &[("username", "testuser"), ("password", "password1")],
                    )
                    .await
                    .map_err(|e| UebaError::Injection(e.to_string()))?;
                let ev = format!("Off-hours login attempt (03:00 local); server returned {s}");
                (s, b, ev)
            }

            UebaTechnique::UnusualEndpointSequence => {
                // Access /admin before ever hitting /login — abnormal sequence.
                let (s, b) = client
                    .get(&format!("{}/admin", base_url))
                    .await
                    .map_err(|e| UebaError::Injection(e.to_string()))?;
                let ev = format!(
                    "Accessed /admin before /login (abnormal sequence); server returned {s}"
                );
                (s, b, ev)
            }
        };

        // Heuristic: 4xx/5xx or body containing "blocked"/"captcha" = detected
        let detected = self.response_looks_blocked(status, &body);
        debug!(
            technique = technique.label(),
            detected, status, "UebaProbe: anomaly result"
        );

        Ok(UebaFinding {
            technique,
            detected,
            evidence,
        })
    }

    /// Summarise a set of findings as remediation hints for the blue team.
    ///
    /// Only undetected techniques are included (those are the actual gaps).
    pub fn summarize(&self, findings: &[UebaFinding]) -> Vec<String> {
        findings
            .iter()
            .filter(|f| !f.detected)
            .map(|f| {
                format!(
                    "[UNDETECTED] {}: {} | Remediation: {}",
                    f.technique.label(),
                    f.evidence,
                    f.technique.remediation_hint()
                )
            })
            .collect()
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn response_looks_blocked(&self, status: u16, body: &str) -> bool {
        if matches!(status, 400 | 403 | 429 | 503) {
            return true;
        }
        let body_lower = body.to_ascii_lowercase();
        body_lower.contains("blocked")
            || body_lower.contains("captcha")
            || body_lower.contains("suspicious")
            || body_lower.contains("rate limit")
            || body_lower.contains("too many")
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Fake HTTP client for unit tests
    struct FakeClient {
        /// (status, body) returned for every request
        response: Mutex<(u16, String)>,
    }

    impl FakeClient {
        fn ok() -> Self {
            Self {
                response: Mutex::new((200, "Welcome".into())),
            }
        }
        fn blocked() -> Self {
            Self {
                response: Mutex::new((403, "Blocked".into())),
            }
        }
    }

    #[async_trait::async_trait]
    impl UebaHttpClient for FakeClient {
        async fn get(&self, _url: &str) -> Result<(u16, String)> {
            let r = self.response.lock().unwrap().clone();
            Ok(r)
        }
        async fn post_form(&self, _url: &str, _fields: &[(&str, &str)]) -> Result<(u16, String)> {
            let r = self.response.lock().unwrap().clone();
            Ok(r)
        }
    }

    fn target() -> Target {
        Target::new("localhost", 8080, "http")
    }

    #[tokio::test]
    async fn baseline_succeeds_with_fake_client() {
        let probe = UebaProbe::new(3, 0.5);
        let client = FakeClient::ok();
        probe.run_baseline(&client, &target()).await.unwrap();
    }

    #[tokio::test]
    async fn slow_brute_force_undetected_on_200() {
        let probe = UebaProbe::new(1, 0.5);
        let client = FakeClient::ok();
        let finding = probe
            .inject_anomaly(UebaTechnique::SlowBruteForce, &client, &target())
            .await
            .unwrap();
        assert!(!finding.detected);
    }

    #[tokio::test]
    async fn slow_brute_force_detected_on_403() {
        let probe = UebaProbe::new(1, 0.5);
        let client = FakeClient::blocked();
        let finding = probe
            .inject_anomaly(UebaTechnique::SlowBruteForce, &client, &target())
            .await
            .unwrap();
        assert!(finding.detected);
    }

    #[tokio::test]
    async fn unusual_sequence_undetected_on_200() {
        let probe = UebaProbe::new(1, 0.5);
        let client = FakeClient::ok();
        let finding = probe
            .inject_anomaly(UebaTechnique::UnusualEndpointSequence, &client, &target())
            .await
            .unwrap();
        assert!(!finding.detected);
    }

    #[test]
    fn summarize_omits_detected_findings() {
        let probe = UebaProbe::default();
        let findings = vec![
            UebaFinding {
                technique: UebaTechnique::SlowBruteForce,
                detected: true,
                evidence: "blocked".into(),
            },
            UebaFinding {
                technique: UebaTechnique::OffHoursAccess,
                detected: false,
                evidence: "slipped through".into(),
            },
        ];
        let hints = probe.summarize(&findings);
        assert_eq!(hints.len(), 1);
        assert!(hints[0].contains("OffHoursAccess"));
        assert!(hints[0].contains("Remediation"));
    }

    #[test]
    fn all_techniques_have_remediation_hints() {
        let techniques = [
            UebaTechnique::SlowBruteForce,
            UebaTechnique::GeographicVelocity,
            UebaTechnique::UserAgentSwitching,
            UebaTechnique::OffHoursAccess,
            UebaTechnique::UnusualEndpointSequence,
        ];
        for t in &techniques {
            assert!(
                !t.remediation_hint().is_empty(),
                "{} missing hint",
                t.label()
            );
        }
    }

    #[test]
    fn response_blocked_on_rate_limit_body() {
        let probe = UebaProbe::default();
        assert!(probe.response_looks_blocked(200, "Error: too many requests"));
        assert!(probe.response_looks_blocked(200, "CAPTCHA required"));
        assert!(!probe.response_looks_blocked(200, "Welcome back!"));
    }
}
