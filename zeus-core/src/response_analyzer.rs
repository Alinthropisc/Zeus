use std::collections::HashMap;

/// Extended attack result with rich context.
#[derive(Debug, Clone)]
pub enum EnrichedResult {
    /// Clear success — credential works.
    Success { confidence: f64, evidence: Vec<String> },
    /// Clear failure.
    Failure,
    /// Password correct but MFA required — still a valuable finding!
    MfaRequired { mfa_type: MfaType },
    /// CAPTCHA triggered — bot protection detected.
    CaptchaDetected { captcha_type: CaptchaType },
    /// Account locked out.
    AccountLocked { lockout_duration_hint: Option<String> },
    /// Rate limited by server.
    RateLimited { retry_after_secs: Option<u64> },
    /// WAF blocked the request.
    WafBlocked { waf_vendor: Option<String> },
    /// Unknown — needs manual review.
    Unknown { status_code: u16, body_snippet: String },
}

#[derive(Debug, Clone)]
pub enum MfaType {
    /// Time-based OTP (Google Authenticator style).
    Totp,
    /// SMS one-time code.
    Sms,
    /// Email verification code.
    Email,
    /// Push notification (Duo, etc.).
    Push,
    /// MFA detected but type unknown.
    Unknown,
}

#[derive(Debug, Clone)]
pub enum CaptchaType {
    ReCaptchaV2,
    ReCaptchaV3,
    HCaptcha,
    /// Cloudflare Turnstile.
    Turnstile,
    Generic,
}

/// Rules for analyzing HTTP responses from login endpoints.
pub struct ResponseAnalyzer {
    /// Baseline body length for unauthenticated requests (set during warmup).
    baseline_failure_length: Option<usize>,
    /// Baseline status for failures.
    baseline_failure_status: Option<u16>,
    /// Custom success keywords (from target config).
    success_keywords: Vec<String>,
    /// Custom failure keywords.
    failure_keywords: Vec<String>,
    /// Whether to detect MFA challenges.
    detect_mfa: bool,
    /// Whether to detect CAPTCHA challenges.
    detect_captcha: bool,
}

impl Default for ResponseAnalyzer {
    fn default() -> Self {
        Self {
            baseline_failure_length: None,
            baseline_failure_status: None,
            success_keywords: vec![
                "welcome".into(),
                "logout".into(),
                "dashboard".into(),
                "sign out".into(),
                "logged in".into(),
                "my account".into(),
                "profile".into(),
                "hello,".into(),
            ],
            failure_keywords: vec![
                "invalid".into(),
                "incorrect".into(),
                "wrong password".into(),
                "bad credentials".into(),
                "authentication failed".into(),
                "login failed".into(),
                "access denied".into(),
                "try again".into(),
                "error".into(),
            ],
            detect_mfa: true,
            detect_captcha: true,
        }
    }
}

impl ResponseAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Extend the default success keyword list with additional entries.
    pub fn with_success_keywords(mut self, keywords: Vec<String>) -> Self {
        self.success_keywords.extend(keywords);
        self
    }

    /// Extend the default failure keyword list with additional entries.
    pub fn with_failure_keywords(mut self, keywords: Vec<String>) -> Self {
        self.failure_keywords.extend(keywords);
        self
    }

    /// Record a baseline from a known-failure response (call before the attack starts).
    pub fn set_failure_baseline(&mut self, status: u16, body_len: usize) {
        self.baseline_failure_status = Some(status);
        self.baseline_failure_length = Some(body_len);
    }

    /// Analyze a single HTTP response and return an [`EnrichedResult`].
    ///
    /// Evaluation order (first match wins):
    /// 1. WAF block
    /// 2. Rate limit (HTTP 429)
    /// 3. Account lockout
    /// 4. CAPTCHA
    /// 5. MFA challenge
    /// 6. Success signals
    /// 7. Explicit failure keywords
    /// 8. Status-code / baseline fallback
    pub fn analyze(
        &self,
        status: u16,
        body: &str,
        headers: &HashMap<String, String>,
        redirect_url: Option<&str>,
    ) -> EnrichedResult {
        let body_lower = body.to_lowercase();

        // 1. WAF detection.
        if let Some(waf) = self.detect_waf(status, headers, &body_lower) {
            return EnrichedResult::WafBlocked { waf_vendor: Some(waf) };
        }

        // 2. Rate limiting.
        if status == 429 {
            let retry_after = headers
                .get("retry-after")
                .or_else(|| headers.get("x-ratelimit-reset"))
                .and_then(|v| v.parse::<u64>().ok());
            return EnrichedResult::RateLimited { retry_after_secs: retry_after };
        }

        // 3. Account lockout.
        if let Some(hint) = self.detect_lockout(status, &body_lower, headers) {
            return EnrichedResult::AccountLocked { lockout_duration_hint: hint };
        }

        // 4. CAPTCHA detection.
        if self.detect_captcha {
            if let Some(cap_type) = self.detect_captcha_type(&body_lower, headers) {
                return EnrichedResult::CaptchaDetected { captcha_type: cap_type };
            }
        }

        // 5. MFA detection.
        if self.detect_mfa {
            if let Some(mfa) = self.detect_mfa_type(&body_lower, status, redirect_url) {
                return EnrichedResult::MfaRequired { mfa_type: mfa };
            }
        }

        // 6. Success detection.
        if let Some((confidence, evidence)) =
            self.detect_success(status, body, &body_lower, redirect_url)
        {
            return EnrichedResult::Success { confidence, evidence };
        }

        // 7. Explicit failure keywords.
        if self
            .failure_keywords
            .iter()
            .any(|k| body_lower.contains(k.as_str()))
        {
            return EnrichedResult::Failure;
        }

        // 8. Status-code / baseline fallback.
        match status {
            200 => {
                if let (Some(base_len), Some(base_status)) =
                    (self.baseline_failure_length, self.baseline_failure_status)
                {
                    if base_status == 200 {
                        let len_diff = (body.len() as i64 - base_len as i64).abs();
                        if len_diff > 200 {
                            return EnrichedResult::Success {
                                confidence: 0.6,
                                evidence: vec![format!("body length diff: {} bytes", len_diff)],
                            };
                        }
                    }
                }
                EnrichedResult::Failure
            }
            301 | 302 | 303 | 307 | 308 => {
                let loc = redirect_url.unwrap_or("");
                if loc.contains("dashboard")
                    || loc.contains("home")
                    || loc.contains("account")
                    || loc.contains("profile")
                    || loc.contains("welcome")
                {
                    EnrichedResult::Success {
                        confidence: 0.85,
                        evidence: vec![format!("redirect to {}", loc)],
                    }
                } else if loc.contains("login") || loc.contains("signin") {
                    EnrichedResult::Failure
                } else {
                    EnrichedResult::Unknown {
                        status_code: status,
                        body_snippet: loc.chars().take(100).collect(),
                    }
                }
            }
            401 | 403 => EnrichedResult::Failure,
            _ => EnrichedResult::Unknown {
                status_code: status,
                body_snippet: body.chars().take(200).collect(),
            },
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn detect_waf(
        &self,
        status: u16,
        headers: &HashMap<String, String>,
        body_lower: &str,
    ) -> Option<String> {
        // Cloudflare
        if headers.contains_key("cf-ray")
            || headers
                .get("server")
                .map(|s| s.to_lowercase().contains("cloudflare"))
                .unwrap_or(false)
        {
            if status == 403 || status == 503 {
                return Some("Cloudflare".into());
            }
        }
        // AWS WAF
        if headers.get("x-amzn-requestid").is_some() && status == 403 {
            return Some("AWS WAF".into());
        }
        // F5 BIG-IP ASM
        if headers.get("x-cnection").is_some()
            || body_lower.contains("the requested url was rejected")
        {
            return Some("F5 BIG-IP ASM".into());
        }
        // ModSecurity
        if body_lower.contains("mod_security")
            || (body_lower.contains("not acceptable") && status == 406)
        {
            return Some("ModSecurity".into());
        }
        // Imperva / Incapsula
        if headers.get("x-iinfo").is_some() || body_lower.contains("incapsula") {
            return Some("Imperva/Incapsula".into());
        }
        // Akamai
        if headers.get("x-akamai-transformed").is_some() {
            return Some("Akamai".into());
        }
        None
    }

    /// Returns `Some(hint)` when a lockout is detected.
    /// The inner `Option<String>` carries a human-readable duration hint.
    fn detect_lockout(
        &self,
        status: u16,
        body_lower: &str,
        headers: &HashMap<String, String>,
    ) -> Option<Option<String>> {
        const LOCKOUT_PATTERNS: &[&str] = &[
            "account locked",
            "account has been locked",
            "too many failed",
            "account disabled",
            "account suspended",
            "locked out",
            "temporarily blocked",
            "security lockout",
        ];

        if LOCKOUT_PATTERNS.iter().any(|p| body_lower.contains(p)) {
            let hint = if body_lower.contains("30 minute") {
                Some("30 minutes".into())
            } else if body_lower.contains("15 minute") {
                Some("15 minutes".into())
            } else if body_lower.contains("1 hour") {
                Some("1 hour".into())
            } else {
                headers
                    .get("retry-after")
                    .map(|v| format!("{} seconds", v))
            };
            return Some(hint);
        }

        // HTTP 423 Locked
        if status == 423 {
            return Some(None);
        }

        None
    }

    fn detect_captcha_type(
        &self,
        body_lower: &str,
        _headers: &HashMap<String, String>,
    ) -> Option<CaptchaType> {
        if body_lower.contains("hcaptcha.com") || body_lower.contains("h-captcha") {
            return Some(CaptchaType::HCaptcha);
        }
        if body_lower.contains("challenges.cloudflare.com") || body_lower.contains("cf-turnstile")
        {
            return Some(CaptchaType::Turnstile);
        }
        if body_lower.contains("recaptcha/api.js") || body_lower.contains("g-recaptcha") {
            if body_lower.contains("v3") || body_lower.contains("grecaptcha.execute") {
                return Some(CaptchaType::ReCaptchaV3);
            }
            return Some(CaptchaType::ReCaptchaV2);
        }
        if body_lower.contains("captcha") || body_lower.contains("are you human") {
            return Some(CaptchaType::Generic);
        }
        None
    }

    fn detect_mfa_type(
        &self,
        body_lower: &str,
        _status: u16,
        redirect: Option<&str>,
    ) -> Option<MfaType> {
        if body_lower.contains("authenticator")
            || body_lower.contains("totp")
            || body_lower.contains("google authenticator")
            || body_lower.contains("6-digit")
        {
            return Some(MfaType::Totp);
        }
        if body_lower.contains("sms")
            && (body_lower.contains("code") || body_lower.contains("sent"))
        {
            return Some(MfaType::Sms);
        }
        if body_lower.contains("check your email") && body_lower.contains("code") {
            return Some(MfaType::Email);
        }
        if body_lower.contains("push notification")
            || (body_lower.contains("duo") && body_lower.contains("approve"))
        {
            return Some(MfaType::Push);
        }
        if body_lower.contains("two-factor")
            || body_lower.contains("2fa")
            || body_lower.contains("verification code")
            || body_lower.contains("one-time")
        {
            return Some(MfaType::Unknown);
        }
        // Redirect to /2fa or /mfa path.
        if let Some(url) = redirect {
            let url_lower = url.to_lowercase();
            if url_lower.contains("/2fa")
                || url_lower.contains("/mfa")
                || url_lower.contains("/totp")
                || url_lower.contains("/verify")
            {
                return Some(MfaType::Unknown);
            }
        }
        None
    }

    fn detect_success(
        &self,
        _status: u16,
        _body: &str,
        body_lower: &str,
        redirect: Option<&str>,
    ) -> Option<(f64, Vec<String>)> {
        let mut evidence = Vec::new();
        let mut confidence = 0.0f64;

        for kw in &self.success_keywords {
            if body_lower.contains(kw.as_str()) {
                evidence.push(format!("keyword '{}'", kw));
                confidence += 0.3;
            }
        }

        if let Some(url) = redirect {
            let url_lower = url.to_lowercase();
            if url_lower.contains("dashboard") || url_lower.contains("home") {
                evidence.push(format!("redirect to {}", url));
                confidence += 0.5;
            }
        }

        if confidence > 0.3 {
            Some((confidence.min(1.0), evidence))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // --- WAF ---

    #[test]
    fn analyzer_detects_cloudflare_waf() {
        let a = ResponseAnalyzer::new();
        let h = headers(&[("cf-ray", "abc123")]);
        let r = a.analyze(403, "", &h, None);
        assert!(matches!(
            r,
            EnrichedResult::WafBlocked { waf_vendor: Some(ref v) } if v == "Cloudflare"
        ));
    }

    // --- Rate limiting ---

    #[test]
    fn analyzer_detects_rate_limit() {
        let a = ResponseAnalyzer::new();
        let r = a.analyze(429, "", &headers(&[]), None);
        assert!(matches!(r, EnrichedResult::RateLimited { retry_after_secs: None }));
    }

    #[test]
    fn analyzer_detects_retry_after() {
        let a = ResponseAnalyzer::new();
        let h = headers(&[("retry-after", "60")]);
        let r = a.analyze(429, "", &h, None);
        assert!(matches!(
            r,
            EnrichedResult::RateLimited { retry_after_secs: Some(60) }
        ));
    }

    // --- CAPTCHA ---

    #[test]
    fn analyzer_detects_captcha_recaptcha_v2() {
        let a = ResponseAnalyzer::new();
        let body = r#"<script src="https://www.google.com/recaptcha/api.js"></script><div class="g-recaptcha"></div>"#;
        let r = a.analyze(200, body, &headers(&[]), None);
        assert!(matches!(
            r,
            EnrichedResult::CaptchaDetected { captcha_type: CaptchaType::ReCaptchaV2 }
        ));
    }

    #[test]
    fn analyzer_detects_captcha_hcaptcha() {
        let a = ResponseAnalyzer::new();
        let body = r#"<script src="https://js.hcaptcha.com/1/api.js"></script>"#;
        let r = a.analyze(200, body, &headers(&[]), None);
        assert!(matches!(
            r,
            EnrichedResult::CaptchaDetected { captcha_type: CaptchaType::HCaptcha }
        ));
    }

    #[test]
    fn analyzer_detects_captcha_turnstile() {
        let a = ResponseAnalyzer::new();
        let body = r#"<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>"#;
        let r = a.analyze(200, body, &headers(&[]), None);
        assert!(matches!(
            r,
            EnrichedResult::CaptchaDetected { captcha_type: CaptchaType::Turnstile }
        ));
    }

    // --- MFA ---

    #[test]
    fn analyzer_detects_mfa_totp() {
        let a = ResponseAnalyzer::new();
        let body = "Please enter the 6-digit code from your authenticator app.";
        let r = a.analyze(200, body, &headers(&[]), None);
        assert!(matches!(
            r,
            EnrichedResult::MfaRequired { mfa_type: MfaType::Totp }
        ));
    }

    #[test]
    fn analyzer_detects_mfa_sms() {
        let a = ResponseAnalyzer::new();
        let body = "We sent an SMS code to your phone number.";
        let r = a.analyze(200, body, &headers(&[]), None);
        assert!(matches!(
            r,
            EnrichedResult::MfaRequired { mfa_type: MfaType::Sms }
        ));
    }

    #[test]
    fn analyzer_detects_mfa_redirect() {
        let a = ResponseAnalyzer::new();
        let r = a.analyze(302, "", &headers(&[]), Some("/2fa/verify"));
        assert!(matches!(r, EnrichedResult::MfaRequired { .. }));
    }

    // --- Success ---

    #[test]
    fn analyzer_detects_success_keyword() {
        let a = ResponseAnalyzer::new();
        // "welcome" + "logout" = two keywords → confidence 0.6, above the 0.3 threshold
        let body = "Welcome back! You are now logged in. <a href='/logout'>logout</a>";
        let r = a.analyze(200, body, &headers(&[]), None);
        assert!(matches!(r, EnrichedResult::Success { .. }));
    }

    #[test]
    fn analyzer_detects_success_redirect_dashboard() {
        let a = ResponseAnalyzer::new();
        let r = a.analyze(302, "", &headers(&[]), Some("/dashboard"));
        assert!(matches!(r, EnrichedResult::Success { confidence, .. } if confidence > 0.8));
    }

    // --- Lockout ---

    #[test]
    fn analyzer_detects_lockout() {
        let a = ResponseAnalyzer::new();
        let body = "Your account has been locked due to too many failed attempts.";
        let r = a.analyze(200, body, &headers(&[]), None);
        assert!(matches!(r, EnrichedResult::AccountLocked { .. }));
    }

    #[test]
    fn analyzer_detects_lockout_hint() {
        let a = ResponseAnalyzer::new();
        let body = "Account locked. Please try again after 30 minute cooldown.";
        let r = a.analyze(200, body, &headers(&[]), None);
        assert!(matches!(
            r,
            EnrichedResult::AccountLocked { lockout_duration_hint: Some(ref h) } if h == "30 minutes"
        ));
    }

    // --- Failure ---

    #[test]
    fn analyzer_failure_explicit_keyword() {
        let a = ResponseAnalyzer::new();
        let body = "Invalid username or password.";
        let r = a.analyze(200, body, &headers(&[]), None);
        assert!(matches!(r, EnrichedResult::Failure));
    }

    #[test]
    fn analyzer_failure_redirect_login() {
        let a = ResponseAnalyzer::new();
        let r = a.analyze(302, "", &headers(&[]), Some("/login?err=1"));
        assert!(matches!(r, EnrichedResult::Failure));
    }

    // --- Baseline body-length diff ---

    #[test]
    fn analyzer_baseline_body_length_diff() {
        let mut a = ResponseAnalyzer::new();
        // Baseline: 200 with a short body (simulates the failed-login page).
        a.set_failure_baseline(200, 50);

        // A significantly longer body should be flagged as a probable success.
        let long_body = "X".repeat(300);
        let r = a.analyze(200, &long_body, &headers(&[]), None);
        assert!(
            matches!(r, EnrichedResult::Success { confidence, .. } if (confidence - 0.6).abs() < f64::EPSILON),
            "expected Success with confidence 0.6"
        );
    }
}
