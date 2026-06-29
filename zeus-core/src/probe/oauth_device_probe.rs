//! OAuth 2.0 Device Authorization Grant abuse probes — Phase 7.
//!
//! Fluent Builder pattern: [`OAuthDeviceFlowBuilder`] constructs an
//! [`OAuthDeviceProbe`] step by step.

use anyhow::{Result, anyhow};
use thiserror::Error;

use crate::probe::jwt_probe::Severity;

// ──────────────────────────────────────────────────────────────────────────────
// Error
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DeviceProbeError {
    #[error("device flow configuration invalid: {0}")]
    Config(String),
    #[error("HTTP error: {0}")]
    Http(String),
}

// ──────────────────────────────────────────────────────────────────────────────
// DeviceFlowIssue
// ──────────────────────────────────────────────────────────────────────────────

/// A specific weakness found in a Device Authorization Grant implementation.
#[derive(Debug, Clone)]
pub enum DeviceFlowIssue {
    /// Polled the token endpoint repeatedly with no throttle response.
    NoRateLimitOnPoll,
    /// Device code remained valid (or returned a token) after first use.
    DeviceCodeReuse,
    /// Device code expiry exceeds the 15-minute SHOULD limit (RFC 8628 §3.4).
    LongExpiry { seconds: u64 },
    /// Token was issued without any indication the user confirmed the code.
    NoUserConfirmation,
    /// Device flow does not enforce PKCE.
    PkceNotEnforced,
}

impl std::fmt::Display for DeviceFlowIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRateLimitOnPoll => write!(f, "no rate-limit on token poll"),
            Self::DeviceCodeReuse => write!(f, "device code reusable after first use"),
            Self::LongExpiry { seconds } => write!(f, "device code expiry {seconds}s (>900s)"),
            Self::NoUserConfirmation => write!(f, "token issued without user confirmation"),
            Self::PkceNotEnforced => write!(f, "PKCE not enforced in device flow"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// DeviceFlowFinding
// ──────────────────────────────────────────────────────────────────────────────

/// A finding produced by one of the device-flow probe methods.
#[derive(Debug, Clone)]
pub struct DeviceFlowFinding {
    pub issue: DeviceFlowIssue,
    pub evidence: String,
    pub severity: Severity,
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal async HTTP abstraction
// ──────────────────────────────────────────────────────────────────────────────

/// Callers wrap their HTTP client to implement this trait.
#[async_trait::async_trait]
pub trait DeviceHttpClient: Send + Sync {
    /// POST form-encoded `params` to `url`.
    /// Returns `(status_code, response_body_json_string)`.
    async fn post_form(&self, url: &str, params: &[(&str, &str)]) -> Result<(u16, String)>;
}

// ──────────────────────────────────────────────────────────────────────────────
// OAuthDeviceFlowBuilder  (Fluent Builder)
// ──────────────────────────────────────────────────────────────────────────────

/// Fluent builder for [`OAuthDeviceProbe`].
///
/// ```rust,ignore
/// let probe = OAuthDeviceFlowBuilder::new("my-client-id")
///     .device_endpoint("https://auth.example.com/device/code")
///     .token_endpoint("https://auth.example.com/token")
///     .poll_interval_ms(500)
///     .max_polls(120)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct OAuthDeviceFlowBuilder {
    client_id: String,
    device_endpoint: String,
    token_endpoint: String,
    poll_interval_ms: u64,
    max_polls: u32,
}

impl OAuthDeviceFlowBuilder {
    pub fn new(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            device_endpoint: String::new(),
            token_endpoint: String::new(),
            poll_interval_ms: 5_000,
            max_polls: 100,
        }
    }

    pub fn device_endpoint(mut self, url: impl Into<String>) -> Self {
        self.device_endpoint = url.into();
        self
    }

    pub fn token_endpoint(mut self, url: impl Into<String>) -> Self {
        self.token_endpoint = url.into();
        self
    }

    pub fn poll_interval_ms(mut self, ms: u64) -> Self {
        self.poll_interval_ms = ms;
        self
    }

    pub fn max_polls(mut self, n: u32) -> Self {
        self.max_polls = n;
        self
    }

    pub fn build(self) -> Result<OAuthDeviceProbe> {
        if self.device_endpoint.is_empty() {
            return Err(anyhow!(DeviceProbeError::Config(
                "device_endpoint is required".into()
            )));
        }
        if self.token_endpoint.is_empty() {
            return Err(anyhow!(DeviceProbeError::Config(
                "token_endpoint is required".into()
            )));
        }
        Ok(OAuthDeviceProbe {
            client_id: self.client_id,
            device_endpoint: self.device_endpoint,
            token_endpoint: self.token_endpoint,
            poll_interval_ms: self.poll_interval_ms,
            max_polls: self.max_polls,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// OAuthDeviceProbe
// ──────────────────────────────────────────────────────────────────────────────

/// Probes a Device Authorization Grant endpoint for RFC 8628 weaknesses.
#[derive(Debug, Clone)]
pub struct OAuthDeviceProbe {
    pub client_id: String,
    pub device_endpoint: String,
    pub token_endpoint: String,
    /// Milliseconds to wait between poll attempts.
    pub poll_interval_ms: u64,
    /// Maximum number of poll attempts before giving up.
    pub max_polls: u32,
}

impl OAuthDeviceProbe {
    /// Convenience constructor — delegates to [`OAuthDeviceFlowBuilder`].
    pub fn builder(client_id: impl Into<String>) -> OAuthDeviceFlowBuilder {
        OAuthDeviceFlowBuilder::new(client_id)
    }

    // ── Probe: rate-limit on polling ─────────────────────────────────────────

    /// Poll the token endpoint `max_polls` times in rapid succession.
    ///
    /// If the server never returns HTTP 429 (or a `slow_down` error), it is
    /// not enforcing rate-limits as required by RFC 8628 §3.5.
    pub async fn probe_rate_limit(
        &self,
        client: &dyn DeviceHttpClient,
        device_code: &str,
    ) -> Result<DeviceFlowFinding> {
        let mut throttled = false;
        let mut attempts = 0u32;

        for _ in 0..self.max_polls {
            let (status, body) = client
                .post_form(
                    &self.token_endpoint,
                    &[
                        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                        ("device_code", device_code),
                        ("client_id", &self.client_id),
                    ],
                )
                .await
                .unwrap_or((0, String::new()));

            attempts += 1;

            if status == 429 || body.contains("slow_down") || body.contains("rate") {
                throttled = true;
                break;
            }
        }

        if throttled {
            Ok(DeviceFlowFinding {
                issue: DeviceFlowIssue::NoRateLimitOnPoll,
                evidence: format!(
                    "server throttled after {attempts} attempts — rate-limiting present"
                ),
                severity: Severity::Low,
            })
        } else {
            Ok(DeviceFlowFinding {
                issue: DeviceFlowIssue::NoRateLimitOnPoll,
                evidence: format!(
                    "polled {attempts} times without any 429 or slow_down — no rate-limit detected"
                ),
                severity: Severity::High,
            })
        }
    }

    // ── Probe: device code reuse ─────────────────────────────────────────────

    /// After a device code has been exchanged for a token, try to exchange it
    /// again.  If the server returns another token (or `authorization_pending`
    /// rather than `expired_token`), the code is reusable.
    pub async fn probe_code_reuse(
        &self,
        client: &dyn DeviceHttpClient,
        device_code: &str,
    ) -> Result<DeviceFlowFinding> {
        let (status, body) = client
            .post_form(
                &self.token_endpoint,
                &[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", device_code),
                    ("client_id", &self.client_id),
                ],
            )
            .await
            .map_err(|e| anyhow!("HTTP error: {e}"))?;

        // RFC 8628: after first use the server MUST return `expired_token`.
        let reused = status == 200
            || body.contains("access_token")
            || body.contains("authorization_pending");

        if reused {
            Ok(DeviceFlowFinding {
                issue: DeviceFlowIssue::DeviceCodeReuse,
                evidence: format!(
                    "server returned status {status} on second exchange — code reusable"
                ),
                severity: Severity::High,
            })
        } else {
            Ok(DeviceFlowFinding {
                issue: DeviceFlowIssue::DeviceCodeReuse,
                evidence: format!("server returned status {status} — code correctly invalidated"),
                severity: Severity::Low,
            })
        }
    }

    // ── Probe: device code expiry ────────────────────────────────────────────

    /// Request a device code and check the `expires_in` field.  Values greater
    /// than 900 seconds (15 minutes) exceed the RFC 8628 SHOULD limit.
    pub async fn probe_expiry(&self, client: &dyn DeviceHttpClient) -> Result<DeviceFlowFinding> {
        let (status, body) = client
            .post_form(
                &self.device_endpoint,
                &[("client_id", &self.client_id), ("scope", "openid")],
            )
            .await
            .map_err(|e| anyhow!("HTTP error: {e}"))?;

        if status != 200 {
            return Err(anyhow!("device endpoint returned {status}"));
        }

        // Parse expires_in from JSON body (simple scan — no external dep).
        let expires_in = parse_u64_field(&body, "expires_in");

        match expires_in {
            Some(secs) if secs > 900 => Ok(DeviceFlowFinding {
                issue: DeviceFlowIssue::LongExpiry { seconds: secs },
                evidence: format!("expires_in={secs}s exceeds RFC 8628 SHOULD limit of 900s"),
                severity: Severity::Medium,
            }),
            Some(secs) => Ok(DeviceFlowFinding {
                issue: DeviceFlowIssue::LongExpiry { seconds: secs },
                evidence: format!("expires_in={secs}s is within acceptable range"),
                severity: Severity::Low,
            }),
            None => Ok(DeviceFlowFinding {
                issue: DeviceFlowIssue::LongExpiry { seconds: 0 },
                evidence: "expires_in field not found in device authorization response".into(),
                severity: Severity::Medium,
            }),
        }
    }

    // ── run_all ──────────────────────────────────────────────────────────────

    /// Run all device-flow probes.  Requires a fresh device code (obtained
    /// by calling the device endpoint before invoking this method).
    pub async fn run_all(
        &self,
        client: &dyn DeviceHttpClient,
        device_code: &str,
    ) -> Result<Vec<DeviceFlowFinding>> {
        let mut findings = Vec::new();

        match self.probe_rate_limit(client, device_code).await {
            Ok(f) => findings.push(f),
            Err(e) => tracing::warn!(error = %e, "probe_rate_limit failed"),
        }
        match self.probe_code_reuse(client, device_code).await {
            Ok(f) => findings.push(f),
            Err(e) => tracing::warn!(error = %e, "probe_code_reuse failed"),
        }
        match self.probe_expiry(client).await {
            Ok(f) => findings.push(f),
            Err(e) => tracing::warn!(error = %e, "probe_expiry failed"),
        }

        Ok(findings)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Scan a JSON string for `"field": <number>` and return the number.
fn parse_u64_field(json: &str, field: &str) -> Option<u64> {
    let needle = format!("\"{field}\"");
    let pos = json.find(&needle)?;
    let after = &json[pos + needle.len()..];
    let colon = after.find(':')? + 1;
    let value_str = after[colon..].trim_start();
    // Read digits.
    let digits: String = value_str
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_requires_device_endpoint() {
        let result = OAuthDeviceFlowBuilder::new("client")
            .token_endpoint("https://auth.example.com/token")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_requires_token_endpoint() {
        let result = OAuthDeviceFlowBuilder::new("client")
            .device_endpoint("https://auth.example.com/device/code")
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_happy_path() {
        let probe = OAuthDeviceFlowBuilder::new("my-client")
            .device_endpoint("https://auth.example.com/device/code")
            .token_endpoint("https://auth.example.com/token")
            .poll_interval_ms(200)
            .max_polls(50)
            .build()
            .unwrap();
        assert_eq!(probe.client_id, "my-client");
        assert_eq!(probe.max_polls, 50);
        assert_eq!(probe.poll_interval_ms, 200);
    }

    #[test]
    fn parse_u64_field_finds_expires_in() {
        let json = r#"{"device_code":"abc","user_code":"XYZ","expires_in":1800,"interval":5}"#;
        assert_eq!(parse_u64_field(json, "expires_in"), Some(1800));
    }

    #[test]
    fn parse_u64_field_missing_returns_none() {
        assert_eq!(parse_u64_field("{}", "expires_in"), None);
    }

    #[test]
    fn device_flow_issue_display() {
        assert!(
            DeviceFlowIssue::LongExpiry { seconds: 3600 }
                .to_string()
                .contains("3600")
        );
        assert!(
            DeviceFlowIssue::NoRateLimitOnPoll
                .to_string()
                .contains("rate")
        );
    }
}
