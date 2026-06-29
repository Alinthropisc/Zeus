//! OAuth 2.0 misconfiguration probes.
//!
//! Each probe method returns a [`ProbeResult`] describing its finding and
//! severity.  Probes are intentionally stateless and synchronous; callers
//! supply the HTTP response data already collected so that the probe logic
//! remains testable without live network access.

use thiserror::Error;

// ──────────────────────────────────────────────────────────────────────────────
// Severity
// ──────────────────────────────────────────────────────────────────────────────

/// CVSS-inspired severity for a reported finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ProbeResult
// ──────────────────────────────────────────────────────────────────────────────

/// Result returned by each OAuth probe method.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    /// Short finding title.
    pub finding: String,
    /// Finding severity.
    pub severity: Severity,
    /// Optional remediation advice.
    pub remediation: Option<String>,
}

impl ProbeResult {
    pub fn new(finding: impl Into<String>, severity: Severity) -> Self {
        Self {
            finding: finding.into(),
            severity,
            remediation: None,
        }
    }

    pub fn with_remediation(mut self, advice: impl Into<String>) -> Self {
        self.remediation = Some(advice.into());
        self
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Error
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum OAuthProbeError {
    #[error("probe configuration invalid: {0}")]
    Config(String),
    #[error("probe inconclusive — insufficient data")]
    Inconclusive,
}

// ──────────────────────────────────────────────────────────────────────────────
// OAuthMisconfigProbe
// ──────────────────────────────────────────────────────────────────────────────

/// Analyses collected OAuth response artefacts for known misconfigurations.
///
/// Instantiate with the authorization server's metadata / observed responses,
/// then call individual probe methods or [`probe_all`].
#[derive(Debug, Clone)]
pub struct OAuthMisconfigProbe {
    /// The registered redirect URIs for the client (from server metadata).
    pub registered_redirect_uris: Vec<String>,
    /// Whether the authorization server advertises PKCE support.
    pub pkce_supported: bool,
    /// Whether the server enforces PKCE (i.e., rejects requests without code_challenge).
    pub pkce_enforced: bool,
    /// `state` value the server echoed back in the last authorization response.
    /// `None` if the server omitted the `state` parameter entirely.
    pub echoed_state: Option<String>,
    /// `state` value originally sent in the authorization request.
    pub sent_state: Option<String>,
}

impl OAuthMisconfigProbe {
    pub fn new() -> Self {
        Self {
            registered_redirect_uris: Vec::new(),
            pkce_supported: false,
            pkce_enforced: false,
            echoed_state: None,
            sent_state: None,
        }
    }

    // ── Builder helpers ───────────────────────────────────────────────────────

    pub fn with_redirect_uris(mut self, uris: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.registered_redirect_uris = uris.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_pkce(mut self, supported: bool, enforced: bool) -> Self {
        self.pkce_supported = supported;
        self.pkce_enforced = enforced;
        self
    }

    pub fn with_state(
        mut self,
        sent: impl Into<String>,
        echoed: Option<impl Into<String>>,
    ) -> Self {
        self.sent_state = Some(sent.into());
        self.echoed_state = echoed.map(Into::into);
        self
    }

    // ── Probe methods ─────────────────────────────────────────────────────────

    /// Check whether the server allows open redirects via a lax `redirect_uri`
    /// validation.
    ///
    /// Heuristics:
    /// - No registered URIs configured → server likely accepts arbitrary URIs.
    /// - Registered URIs include wildcards or path-only patterns.
    pub fn probe_open_redirect(&self) -> Result<ProbeResult, OAuthProbeError> {
        if self.registered_redirect_uris.is_empty() {
            return Ok(ProbeResult::new(
                "Open Redirect: no redirect_uri restrictions registered — server may accept arbitrary URIs",
                Severity::Critical,
            )
            .with_remediation(
                "Register an explicit allowlist of redirect URIs and enforce exact-match validation.",
            ));
        }

        // Check for suspicious patterns: wildcards, localhost-only, HTTP (non-TLS).
        let mut findings: Vec<String> = Vec::new();

        for uri in &self.registered_redirect_uris {
            if uri.contains('*') {
                findings.push(format!("wildcard pattern in redirect URI: '{uri}'"));
            }
            if uri.starts_with("http://")
                && !uri.contains("localhost")
                && !uri.contains("127.0.0.1")
            {
                findings.push(format!(
                    "non-TLS redirect URI for non-localhost destination: '{uri}'"
                ));
            }
        }

        if findings.is_empty() {
            Ok(ProbeResult::new(
                "Open Redirect: redirect_uri registration appears correct",
                Severity::Low,
            ))
        } else {
            Ok(ProbeResult::new(
                format!(
                    "Open Redirect: suspicious redirect_uri patterns — {}",
                    findings.join("; ")
                ),
                Severity::High,
            )
            .with_remediation(
                "Remove wildcards and enforce HTTPS for all non-localhost redirect URIs.",
            ))
        }
    }

    /// Check whether the server allows PKCE downgrade — i.e., accepts
    /// authorization requests without `code_challenge` even though PKCE is
    /// advertised.
    pub fn probe_pkce_downgrade(&self) -> Result<ProbeResult, OAuthProbeError> {
        if self.pkce_supported && !self.pkce_enforced {
            return Ok(ProbeResult::new(
                "PKCE Downgrade: server advertises PKCE support but does not enforce it — authorization code interception is possible",
                Severity::High,
            )
            .with_remediation(
                "Configure the authorization server to reject /authorize requests that omit code_challenge.",
            ));
        }

        if !self.pkce_supported {
            return Ok(ProbeResult::new(
                "PKCE Not Supported: server does not advertise PKCE — public clients are vulnerable to authorization code interception",
                Severity::Medium,
            )
            .with_remediation(
                "Upgrade the authorization server to support RFC 7636 PKCE, especially for public clients.",
            ));
        }

        Ok(ProbeResult::new(
            "PKCE: server supports and enforces PKCE — no downgrade vulnerability detected",
            Severity::Low,
        ))
    }

    /// Check whether the server properly validates the `state` parameter,
    /// protecting against CSRF.
    pub fn probe_state_bypass(&self) -> Result<ProbeResult, OAuthProbeError> {
        match (&self.sent_state, &self.echoed_state) {
            (None, _) => {
                // No state was sent — either the client doesn't use state or
                // we have incomplete data.
                Ok(ProbeResult::new(
                    "State Bypass: no 'state' parameter was included in the authorization request — CSRF protection absent",
                    Severity::High,
                )
                .with_remediation(
                    "Include a cryptographically random 'state' parameter in every authorization request and validate it on callback.",
                ))
            }
            (Some(_), None) => {
                // State was sent but the server did not echo it back.
                Ok(ProbeResult::new(
                    "State Bypass: server did not echo the 'state' parameter in the callback — CSRF validation cannot be performed",
                    Severity::High,
                )
                .with_remediation(
                    "Ensure the authorization server passes 'state' through to the redirect URI.",
                ))
            }
            (Some(sent), Some(echoed)) if sent != echoed => {
                Ok(ProbeResult::new(
                    format!(
                        "State Bypass: echoed state '{echoed}' does not match sent state '{sent}' — possible CSRF or session-fixation attack"
                    ),
                    Severity::Critical,
                )
                .with_remediation(
                    "Validate that the echoed 'state' exactly matches the value sent; abort the flow on mismatch.",
                ))
            }
            (Some(_), Some(_)) => {
                // State matches — no finding.
                Ok(ProbeResult::new(
                    "State Bypass: 'state' parameter round-trips correctly — CSRF baseline satisfied",
                    Severity::Low,
                ))
            }
        }
    }

    /// Run all probes and return their results.
    pub fn probe_all(&self) -> Vec<Result<ProbeResult, OAuthProbeError>> {
        vec![
            self.probe_open_redirect(),
            self.probe_pkce_downgrade(),
            self.probe_state_bypass(),
        ]
    }
}

impl Default for OAuthMisconfigProbe {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_redirect_no_uris_is_critical() {
        let probe = OAuthMisconfigProbe::new();
        let result = probe.probe_open_redirect().unwrap();
        assert_eq!(result.severity, Severity::Critical);
    }

    #[test]
    fn open_redirect_wildcard_is_high() {
        let probe = OAuthMisconfigProbe::new().with_redirect_uris(["https://example.com/*"]);
        let result = probe.probe_open_redirect().unwrap();
        assert_eq!(result.severity, Severity::High);
        assert!(result.finding.contains("wildcard"));
    }

    #[test]
    fn open_redirect_good_uris_is_low() {
        let probe =
            OAuthMisconfigProbe::new().with_redirect_uris(["https://app.example.com/callback"]);
        let result = probe.probe_open_redirect().unwrap();
        assert_eq!(result.severity, Severity::Low);
    }

    #[test]
    fn pkce_supported_not_enforced_is_high() {
        let probe = OAuthMisconfigProbe::new().with_pkce(true, false);
        let result = probe.probe_pkce_downgrade().unwrap();
        assert_eq!(result.severity, Severity::High);
    }

    #[test]
    fn pkce_not_supported_is_medium() {
        let probe = OAuthMisconfigProbe::new().with_pkce(false, false);
        let result = probe.probe_pkce_downgrade().unwrap();
        assert_eq!(result.severity, Severity::Medium);
    }

    #[test]
    fn pkce_enforced_is_low() {
        let probe = OAuthMisconfigProbe::new().with_pkce(true, true);
        let result = probe.probe_pkce_downgrade().unwrap();
        assert_eq!(result.severity, Severity::Low);
    }

    #[test]
    fn state_missing_is_high() {
        let probe = OAuthMisconfigProbe::new();
        let result = probe.probe_state_bypass().unwrap();
        assert_eq!(result.severity, Severity::High);
    }

    #[test]
    fn state_mismatch_is_critical() {
        let probe = OAuthMisconfigProbe::new().with_state("abc123", Some("xyz789"));
        let result = probe.probe_state_bypass().unwrap();
        assert_eq!(result.severity, Severity::Critical);
    }

    #[test]
    fn state_match_is_low() {
        let probe = OAuthMisconfigProbe::new().with_state("abc123", Some("abc123"));
        let result = probe.probe_state_bypass().unwrap();
        assert_eq!(result.severity, Severity::Low);
    }

    #[test]
    fn probe_all_returns_three_results() {
        let probe = OAuthMisconfigProbe::new();
        let results = probe.probe_all();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }
}
