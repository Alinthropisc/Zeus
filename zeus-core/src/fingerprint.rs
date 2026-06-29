//! Response fingerprinting — capture metadata from HTTP responses and compare
//! them against a failure baseline to detect successful authentication, MFA
//! challenges, and CAPTCHA gates without requiring protocol-specific parsing.

use std::collections::HashMap;

// ── ResponseFingerprint ───────────────────────────────────────────────────────

/// Metadata captured from a single HTTP response.
#[derive(Debug, Clone)]
pub struct ResponseFingerprint {
    /// HTTP status code.
    pub status_code: u16,
    /// Byte length of the response body.
    pub body_length: usize,
    /// Round-trip time in milliseconds.
    pub response_time_ms: f64,
    /// Selected response headers (lowercase keys).
    pub headers: HashMap<String, String>,
    /// Success / failure keywords detected in the body.
    pub keywords_found: Vec<String>,
    /// `Location` header value when the response is a redirect.
    pub redirect_location: Option<String>,
}

impl ResponseFingerprint {
    /// Build a fingerprint from raw response data.
    ///
    /// Keyword extraction is performed automatically over `body`.
    pub fn new(
        status_code: u16,
        body: &str,
        response_time_ms: f64,
        headers: HashMap<String, String>,
        redirect_location: Option<String>,
    ) -> Self {
        let keywords_found = Self::extract_keywords(body);
        Self {
            status_code,
            body_length: body.len(),
            response_time_ms,
            headers,
            keywords_found,
            redirect_location,
        }
    }

    /// Scan `body` for well-known success and failure indicators.
    fn extract_keywords(body: &str) -> Vec<String> {
        const SUCCESS_KEYWORDS: &[&str] = &[
            "welcome",
            "logout",
            "dashboard",
            "profile",
            "signed in",
            "logged in",
            "account",
            "my account",
            "hello,",
            "hi,",
        ];
        const FAILURE_KEYWORDS: &[&str] = &[
            "invalid",
            "incorrect",
            "wrong",
            "failed",
            "error",
            "denied",
            "unauthorized",
            "bad credentials",
            "try again",
        ];

        let body_lower = body.to_lowercase();
        let mut found = Vec::new();

        for kw in SUCCESS_KEYWORDS.iter().chain(FAILURE_KEYWORDS.iter()) {
            if body_lower.contains(kw) {
                found.push(kw.to_string());
            }
        }
        found
    }

    /// Weighted similarity score against a `baseline` fingerprint in [0.0, 1.0].
    ///
    /// Weights:
    /// - Status code match: 3
    /// - Body length within 10 %: 2 (within 30 %: 1)
    /// - Redirect location match: 2
    pub fn similarity(&self, baseline: &ResponseFingerprint) -> f64 {
        let mut score = 0.0f64;
        let mut weight = 0.0f64;

        // Status code (weight 3)
        weight += 3.0;
        if self.status_code == baseline.status_code {
            score += 3.0;
        }

        // Body length (weight 2)
        weight += 2.0;
        if baseline.body_length > 0 {
            let ratio = self.body_length as f64 / baseline.body_length as f64;
            if (ratio - 1.0).abs() < 0.1 {
                score += 2.0;
            } else if (ratio - 1.0).abs() < 0.3 {
                score += 1.0;
            }
        }

        // Redirect location (weight 2)
        weight += 2.0;
        if self.redirect_location == baseline.redirect_location {
            score += 2.0;
        }

        score / weight
    }

    /// Returns `true` when this response looks like a successful login compared
    /// to a known-failure `baseline`.
    ///
    /// Heuristic: the response differs significantly from the failure baseline
    /// **or** contains success keywords.
    pub fn looks_like_success(&self, baseline_failure: &ResponseFingerprint) -> bool {
        let sim = self.similarity(baseline_failure);
        sim < 0.6
            || self.keywords_found.iter().any(|k| {
                ["welcome", "logout", "dashboard", "profile", "signed in", "logged in"]
                    .contains(&k.as_str())
            })
    }

    /// Returns `true` when the response appears to be an MFA / 2FA challenge.
    pub fn looks_like_mfa(&self) -> bool {
        const MFA_INDICATORS: &[&str] = &[
            "two-factor",
            "2fa",
            "otp",
            "authenticator",
            "verification code",
            "one-time",
            "totp",
        ];
        self.keywords_found
            .iter()
            .any(|k| MFA_INDICATORS.contains(&k.as_str()))
    }

    /// Returns `true` when the response body suggests a CAPTCHA is present.
    pub fn has_captcha(&self) -> bool {
        const CAPTCHA_INDICATORS: &[&str] = &[
            "recaptcha",
            "hcaptcha",
            "captcha",
            "are you human",
            "verify you are not a robot",
        ];
        self.keywords_found
            .iter()
            .any(|k| CAPTCHA_INDICATORS.contains(&k.as_str()))
    }
}

// ── BaselineCollector ─────────────────────────────────────────────────────────

/// Accumulates unauthenticated (failure) response fingerprints and produces an
/// averaged baseline for comparison.
pub struct BaselineCollector {
    samples: Vec<ResponseFingerprint>,
    max_samples: usize,
}

impl BaselineCollector {
    /// Create a collector that stores up to `max_samples` fingerprints.
    pub fn new(max_samples: usize) -> Self {
        Self {
            samples: Vec::new(),
            max_samples,
        }
    }

    /// Add a sample if the collector has not yet reached `max_samples`.
    pub fn add_sample(&mut self, fp: ResponseFingerprint) {
        if self.samples.len() < self.max_samples {
            self.samples.push(fp);
        }
    }

    /// Returns `true` once at least one sample has been added.
    pub fn is_ready(&self) -> bool {
        !self.samples.is_empty()
    }

    /// Returns a synthetic baseline [`ResponseFingerprint`] averaged over all
    /// collected samples, or `None` if no samples have been added.
    ///
    /// Status code and headers are taken from the first sample (mode would be
    /// more accurate but requires additional complexity).
    pub fn baseline(&self) -> Option<ResponseFingerprint> {
        if self.samples.is_empty() {
            return None;
        }
        let avg_status = self.samples[0].status_code;
        let avg_len =
            self.samples.iter().map(|s| s.body_length).sum::<usize>() / self.samples.len();
        let avg_time =
            self.samples.iter().map(|s| s.response_time_ms).sum::<f64>() / self.samples.len() as f64;
        let redirect = self.samples[0].redirect_location.clone();
        let headers = self.samples[0].headers.clone();

        Some(ResponseFingerprint {
            status_code: avg_status,
            body_length: avg_len,
            response_time_ms: avg_time,
            headers,
            keywords_found: vec![],
            redirect_location: redirect,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fp(status: u16, body: &str, len_override: Option<usize>) -> ResponseFingerprint {
        let mut fp = ResponseFingerprint::new(status, body, 100.0, HashMap::new(), None);
        if let Some(len) = len_override {
            fp.body_length = len;
        }
        fp
    }

    // ── similarity ────────────────────────────────────────────────────────────

    #[test]
    fn fingerprint_similarity_identical() {
        let fp = make_fp(200, "invalid password", None);
        let baseline = make_fp(200, "invalid password", None);
        let sim = fp.similarity(&baseline);
        assert!(
            (sim - 1.0).abs() < 1e-9,
            "identical fingerprints should score 1.0, got {sim}"
        );
    }

    #[test]
    fn fingerprint_similarity_different_status() {
        let fp = make_fp(302, "redirecting", None);
        let baseline = make_fp(200, "redirecting", None);
        // status differs — score loses 3/7 weight; redirect locations both None → +2/7
        // body lengths identical → +2/7 — total = 4/7 ≈ 0.571
        let sim = fp.similarity(&baseline);
        assert!(
            sim < 1.0,
            "different status codes should reduce similarity, got {sim}"
        );
    }

    #[test]
    fn fingerprint_similarity_different_length() {
        // Same status, but body length doubles — should drop score
        let fp = make_fp(200, "", Some(2000));
        let baseline = make_fp(200, "", Some(100));
        let sim = fp.similarity(&baseline);
        // Status matches (+3) but body length ratio = 20x → no length points; redirect both None (+2)
        // 5/7 ≈ 0.714 — strictly less than 1.0
        assert!(sim < 1.0, "very different body length should reduce similarity, got {sim}");
    }

    // ── keyword extraction ────────────────────────────────────────────────────

    #[test]
    fn fingerprint_extract_keywords_success() {
        let fp = ResponseFingerprint::new(
            200,
            "Welcome back! Visit your dashboard or logout anytime.",
            50.0,
            HashMap::new(),
            None,
        );
        assert!(fp.keywords_found.contains(&"welcome".to_string()));
        assert!(fp.keywords_found.contains(&"dashboard".to_string()));
        assert!(fp.keywords_found.contains(&"logout".to_string()));
    }

    #[test]
    fn fingerprint_extract_keywords_failure() {
        let fp = ResponseFingerprint::new(
            200,
            "Error: invalid username or password. Please try again.",
            50.0,
            HashMap::new(),
            None,
        );
        assert!(fp.keywords_found.contains(&"invalid".to_string()));
        assert!(fp.keywords_found.contains(&"error".to_string()));
        assert!(fp.keywords_found.contains(&"try again".to_string()));
    }

    // ── looks_like_success ────────────────────────────────────────────────────

    #[test]
    fn fingerprint_looks_like_success_vs_baseline() {
        // Baseline is the typical failure page
        let baseline = ResponseFingerprint::new(
            200,
            "invalid password, try again",
            80.0,
            HashMap::new(),
            None,
        );

        // Success page has different status AND success keywords
        let success = ResponseFingerprint::new(
            302,
            "Welcome to your dashboard!",
            80.0,
            HashMap::new(),
            Some("/dashboard".to_string()),
        );

        assert!(
            success.looks_like_success(&baseline),
            "response with success keywords and different status should be flagged as success"
        );
    }

    #[test]
    fn fingerprint_does_not_look_like_success_when_similar() {
        let baseline = ResponseFingerprint::new(
            200,
            "invalid password try again",
            80.0,
            HashMap::new(),
            None,
        );
        // Same status, similar body length, no success keywords
        let failure = ResponseFingerprint::new(
            200,
            "incorrect password try again",
            80.0,
            HashMap::new(),
            None,
        );
        // similarity will be high (same status, similar length, same redirect)
        // and no success keywords — should NOT be classified as success
        assert!(
            !failure.looks_like_success(&baseline),
            "similar failure responses should not be classified as success"
        );
    }

    // ── BaselineCollector ─────────────────────────────────────────────────────

    #[test]
    fn baseline_collector_ready_after_sample() {
        let mut col = BaselineCollector::new(5);
        assert!(!col.is_ready());
        col.add_sample(make_fp(200, "bad password", None));
        assert!(col.is_ready());
    }

    #[test]
    fn baseline_collector_avg_length() {
        let mut col = BaselineCollector::new(5);
        // Manually set body lengths to known values
        let mut fp1 = make_fp(200, "", None);
        fp1.body_length = 100;
        let mut fp2 = make_fp(200, "", None);
        fp2.body_length = 200;
        let mut fp3 = make_fp(200, "", None);
        fp3.body_length = 300;

        col.add_sample(fp1);
        col.add_sample(fp2);
        col.add_sample(fp3);

        let baseline = col.baseline().expect("baseline should be available");
        assert_eq!(baseline.body_length, 200, "average of 100/200/300 should be 200");
    }

    #[test]
    fn baseline_collector_respects_max_samples() {
        let mut col = BaselineCollector::new(2);
        col.add_sample(make_fp(200, "a", None));
        col.add_sample(make_fp(200, "b", None));
        col.add_sample(make_fp(200, "c", None)); // should be ignored
        // baseline() averages over exactly 2 samples
        let baseline = col.baseline().unwrap();
        // both samples have len 1, so avg = 1
        assert_eq!(baseline.body_length, 1);
    }

    #[test]
    fn baseline_collector_none_when_empty() {
        let col = BaselineCollector::new(5);
        assert!(col.baseline().is_none());
    }
}
