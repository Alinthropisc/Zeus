//! WAF/IDS fingerprinting and honeypot/captcha detection.
//!
//! Design:
//! - [`WafSignature`] + [`WafPattern`] describe per-vendor detection rules.
//! - [`WafDetectorChain`] (Chain of Responsibility) tries each detector in order.
//! - [`HoneypotDetector`] flags tarpit / always-same-response conditions.
//! - [`CaptchaDetector`] checks for known CAPTCHA provider markers.

use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

// ──────────────────────────────────────────────────────────────────────────────
// Error
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum WafError {
    #[error("detection pipeline failed: {0}")]
    Pipeline(String),
}

// ──────────────────────────────────────────────────────────────────────────────
// ResponseSnapshot — input to all detectors
// ──────────────────────────────────────────────────────────────────────────────

/// A minimal snapshot of an HTTP response used for detection.
#[derive(Debug, Clone)]
pub struct ResponseSnapshot {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    /// Round-trip time observed for this response.
    pub rtt: Duration,
}

impl ResponseSnapshot {
    pub fn new(
        status_code: u16,
        headers: impl IntoIterator<Item = (String, String)>,
        body: impl Into<String>,
        rtt: Duration,
    ) -> Self {
        Self {
            status_code,
            headers: headers.into_iter().collect(),
            body: body.into(),
            rtt,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        // Case-insensitive lookup.
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// WafPattern + WafSignature
// ──────────────────────────────────────────────────────────────────────────────

/// A single matching rule within a [`WafSignature`].
#[derive(Debug, Clone)]
pub enum WafPattern {
    /// Response header `name` must contain `value` (case-insensitive value match).
    ResponseHeader(&'static str, &'static str),
    /// HTTP status code must equal this value.
    StatusCode(u16),
    /// Response body must contain this string (case-insensitive).
    BodyContains(&'static str),
}

impl WafPattern {
    /// Returns `true` if this pattern matches `resp`.
    pub fn matches(&self, resp: &ResponseSnapshot) -> bool {
        match self {
            Self::ResponseHeader(name, value) => resp
                .header(name)
                .map(|v| v.to_ascii_lowercase().contains(&value.to_ascii_lowercase()))
                .unwrap_or(false),
            Self::StatusCode(code) => resp.status_code == *code,
            Self::BodyContains(needle) => resp
                .body
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase()),
        }
    }
}

/// A named set of patterns that identify a specific WAF vendor.
///
/// Matching strategy: ANY pattern match → WAF detected (OR semantics).
/// Change to all-patterns-must-match if stricter AND semantics are required.
#[derive(Debug, Clone)]
pub struct WafSignature {
    pub name: &'static str,
    pub patterns: Vec<WafPattern>,
}

impl WafSignature {
    pub fn new(name: &'static str, patterns: Vec<WafPattern>) -> Self {
        Self { name, patterns }
    }

    /// Returns `true` if at least one pattern matches.
    pub fn matches(&self, resp: &ResponseSnapshot) -> bool {
        self.patterns.iter().any(|p| p.matches(resp))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Built-in signatures
// ──────────────────────────────────────────────────────────────────────────────

/// Build the default library of WAF signatures.
pub fn builtin_signatures() -> Vec<WafSignature> {
    vec![
        WafSignature::new(
            "Cloudflare",
            vec![
                WafPattern::ResponseHeader("server", "cloudflare"),
                WafPattern::ResponseHeader("cf-ray", ""),
                WafPattern::BodyContains("Attention Required! | Cloudflare"),
                WafPattern::BodyContains("cf-error-details"),
                WafPattern::StatusCode(403),
            ],
        ),
        WafSignature::new(
            "ModSecurity",
            vec![
                WafPattern::ResponseHeader("server", "mod_security"),
                WafPattern::BodyContains("Mod_Security"),
                WafPattern::BodyContains("ModSecurity"),
                WafPattern::StatusCode(406),
                WafPattern::StatusCode(501),
            ],
        ),
        WafSignature::new(
            "Imperva (Incapsula)",
            vec![
                WafPattern::ResponseHeader("x-iinfo", ""),
                WafPattern::ResponseHeader("x-cdn", "Imperva"),
                WafPattern::BodyContains("incapsula incident id"),
                WafPattern::BodyContains("/_Incapsula_Resource"),
            ],
        ),
        WafSignature::new(
            "F5 BIG-IP ASM",
            vec![
                WafPattern::ResponseHeader("x-cnection", "close"),
                WafPattern::ResponseHeader("set-cookie", "TS0"),
                WafPattern::BodyContains("The requested URL was rejected"),
                WafPattern::BodyContains("f5"),
            ],
        ),
        WafSignature::new(
            "Akamai",
            vec![
                WafPattern::ResponseHeader("server", "AkamaiGHost"),
                WafPattern::ResponseHeader("x-akamai-transformed", ""),
                WafPattern::ResponseHeader("x-check-cacheable", ""),
                WafPattern::BodyContains("Access Denied - Akamai Reference"),
                WafPattern::StatusCode(403),
            ],
        ),
    ]
}

// ──────────────────────────────────────────────────────────────────────────────
// WafDetector trait + chain
// ──────────────────────────────────────────────────────────────────────────────

/// Detection result from a single detector.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub detected: bool,
    /// Name of the detector / WAF vendor, if detected.
    pub name: Option<String>,
    /// Human-readable explanation.
    pub reason: Option<String>,
}

impl DetectionResult {
    pub fn hit(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            detected: true,
            name: Some(name.into()),
            reason: Some(reason.into()),
        }
    }

    pub fn miss() -> Self {
        Self { detected: false, name: None, reason: None }
    }
}

/// Chain of Responsibility: each detector returns `Some(DetectionResult)` on a
/// match or `None` to pass to the next link.
pub trait WafDetector: Send + Sync + std::fmt::Debug {
    fn detect(&self, resp: &ResponseSnapshot) -> Option<DetectionResult>;
}

/// Iterates detectors in order; returns the first positive detection.
#[derive(Debug, Default)]
pub struct WafDetectorChain {
    detectors: Vec<Box<dyn WafDetector>>,
}

impl WafDetectorChain {
    pub fn new() -> Self { Self::default() }

    pub fn add(mut self, detector: impl WafDetector + 'static) -> Self {
        self.detectors.push(Box::new(detector));
        self
    }

    /// Run the chain and return the first match, or a "not detected" result.
    pub fn run(&self, resp: &ResponseSnapshot) -> DetectionResult {
        for detector in &self.detectors {
            if let Some(result) = detector.detect(resp) {
                return result;
            }
        }
        DetectionResult::miss()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SignatureDetector — wraps Vec<WafSignature>
// ──────────────────────────────────────────────────────────────────────────────

/// Detects a WAF by matching built-in or custom signatures.
#[derive(Debug)]
pub struct SignatureDetector {
    pub signatures: Vec<WafSignature>,
}

impl SignatureDetector {
    pub fn with_builtins() -> Self {
        Self { signatures: builtin_signatures() }
    }
}

impl WafDetector for SignatureDetector {
    fn detect(&self, resp: &ResponseSnapshot) -> Option<DetectionResult> {
        for sig in &self.signatures {
            if sig.matches(resp) {
                return Some(DetectionResult::hit(
                    sig.name,
                    format!("matched WAF signature '{}'", sig.name),
                ));
            }
        }
        None
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// HoneypotDetector
// ──────────────────────────────────────────────────────────────────────────────

/// Detects honeypot / tarpit behaviours:
/// - Response RTT < 1 ms (unusually fast — spoofed response).
/// - Known tarpit / LaBrea patterns in headers or body.
/// - Response body identical across all probes (always-same-response).
#[derive(Debug, Default)]
pub struct HoneypotDetector {
    /// If set, a response body exactly equal to this triggers detection.
    pub known_static_body: Option<String>,
}

impl HoneypotDetector {
    pub fn new() -> Self { Self::default() }

    pub fn with_static_body(mut self, body: impl Into<String>) -> Self {
        self.known_static_body = Some(body.into());
        self
    }
}

impl WafDetector for HoneypotDetector {
    fn detect(&self, resp: &ResponseSnapshot) -> Option<DetectionResult> {
        // Unusually fast response (< 1 ms) is suspicious.
        if resp.rtt < Duration::from_millis(1) {
            return Some(DetectionResult::hit(
                "Honeypot",
                format!("response RTT {:?} < 1 ms — possible spoofed/tarpit response", resp.rtt),
            ));
        }

        // Known tarpit fingerprints.
        let tarpit_markers = ["labrea", "honeyd", "dionaea", "kippo", "cowrie"];
        let body_lower = resp.body.to_ascii_lowercase();
        for marker in tarpit_markers {
            if body_lower.contains(marker) {
                return Some(DetectionResult::hit(
                    "Honeypot",
                    format!("body contains tarpit marker '{marker}'"),
                ));
            }
        }

        // Always-same-response body.
        if let Some(ref static_body) = self.known_static_body {
            if &resp.body == static_body {
                return Some(DetectionResult::hit(
                    "Honeypot",
                    "response body identical to known static honeypot body",
                ));
            }
        }

        None
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// CaptchaDetector
// ──────────────────────────────────────────────────────────────────────────────

/// Detects CAPTCHA challenge pages from common providers.
#[derive(Debug, Default)]
pub struct CaptchaDetector;

impl CaptchaDetector {
    pub fn new() -> Self { Self }

    const MARKERS: &'static [&'static str] = &[
        "hcaptcha",
        "recaptcha",
        "cf-turnstile",
        "geetest",
        "arkose",
        "funcaptcha",
        "data-sitekey",
    ];
}

impl WafDetector for CaptchaDetector {
    fn detect(&self, resp: &ResponseSnapshot) -> Option<DetectionResult> {
        let body_lower = resp.body.to_ascii_lowercase();
        for marker in Self::MARKERS {
            if body_lower.contains(marker) {
                return Some(DetectionResult::hit(
                    "CAPTCHA",
                    format!("CAPTCHA provider marker '{marker}' found in response body"),
                ));
            }
        }
        None
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Convenience builder
// ──────────────────────────────────────────────────────────────────────────────

/// Build a fully-loaded default detector chain.
pub fn default_detector_chain() -> WafDetectorChain {
    WafDetectorChain::new()
        .add(SignatureDetector::with_builtins())
        .add(HoneypotDetector::new())
        .add(CaptchaDetector::new())
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_resp(
        status: u16,
        headers: &[(&str, &str)],
        body: &str,
        rtt_ms: u64,
    ) -> ResponseSnapshot {
        ResponseSnapshot::new(
            status,
            headers.iter().map(|(k, v)| (k.to_string(), v.to_string())),
            body,
            Duration::from_millis(rtt_ms),
        )
    }

    #[test]
    fn cloudflare_detected_by_server_header() {
        let resp = make_resp(403, &[("server", "cloudflare"), ("cf-ray", "abc123")], "", 100);
        let chain = default_detector_chain();
        let result = chain.run(&resp);
        assert!(result.detected);
        assert!(result.name.unwrap().contains("Cloudflare"));
    }

    #[test]
    fn honeypot_detected_by_sub_ms_rtt() {
        let resp = make_resp(200, &[], "hello", 0);
        let detector = HoneypotDetector::new();
        let result = detector.detect(&resp);
        assert!(result.is_some());
    }

    #[test]
    fn captcha_detected_by_hcaptcha() {
        let resp = make_resp(200, &[], "please complete hcaptcha challenge", 200);
        let detector = CaptchaDetector::new();
        let result = detector.detect(&resp);
        assert!(result.is_some());
    }

    #[test]
    fn captcha_detected_by_cf_turnstile() {
        let resp = make_resp(200, &[], "cf-turnstile widget loaded", 150);
        let chain = default_detector_chain();
        let result = chain.run(&resp);
        assert!(result.detected);
        assert_eq!(result.name.unwrap(), "CAPTCHA");
    }

    #[test]
    fn no_detection_on_clean_response() {
        let resp = make_resp(200, &[("server", "nginx")], "Welcome!", 80);
        let chain = default_detector_chain();
        let result = chain.run(&resp);
        assert!(!result.detected);
    }

    #[test]
    fn modsecurity_detected_by_body() {
        let resp = make_resp(406, &[], "This page has been blocked by ModSecurity", 120);
        let chain = default_detector_chain();
        let result = chain.run(&resp);
        assert!(result.detected);
    }

    #[test]
    fn waf_pattern_status_code_matches() {
        let resp = make_resp(406, &[], "", 100);
        let pattern = WafPattern::StatusCode(406);
        assert!(pattern.matches(&resp));
    }
}
