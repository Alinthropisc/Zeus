//! Thin HTTP wrapper over `reqwest` for web-form and HTTP Basic brute-force.
//!
//! Provides a [`HttpClientBuilder`] (Builder pattern) for flexible client
//! construction, plus helpers for HEAD requests, custom headers, Digest auth,
//! NTLM probing, CSRF extraction, and HTML form field parsing.

use anyhow::{anyhow, Result};
use md5::{Digest as Md5Digest, Md5};
use std::collections::HashMap;
use std::time::Duration;
use tracing::debug;

// ──────────────────────────────────────────────────────────────────────────────
// HttpClientBuilder  (Builder pattern)
// ──────────────────────────────────────────────────────────────────────────────

/// Builder for [`HttpClient`].
///
/// ```rust
/// use std::time::Duration;
/// use zeus_services::net::http_client::HttpClient;
///
/// let client = HttpClient::builder("https://example.com")
///     .timeout(Duration::from_secs(5))
///     .user_agent("CustomBot/2.0")
///     .build()
///     .unwrap();
/// ```
pub struct HttpClientBuilder {
    base_url: String,
    timeout: Duration,
    proxy: Option<String>,
    headers: HashMap<String, String>,
    user_agent: String,
    follow_redirects: bool,
    max_redirects: usize,
    cookie_store: bool,
    danger_accept_invalid_certs: bool,
}

impl HttpClientBuilder {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            timeout: Duration::from_secs(10),
            proxy: None,
            headers: HashMap::new(),
            user_agent: "Mozilla/5.0 (compatible; Zeus/1.0)".into(),
            follow_redirects: true,
            max_redirects: 5,
            cookie_store: true,
            danger_accept_invalid_certs: false,
        }
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }

    pub fn proxy(mut self, url: impl Into<String>) -> Self {
        self.proxy = Some(url.into());
        self
    }

    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers.extend(headers);
        self
    }

    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }

    pub fn no_follow_redirects(mut self) -> Self {
        self.follow_redirects = false;
        self
    }

    pub fn max_redirects(mut self, n: usize) -> Self {
        self.max_redirects = n;
        self
    }

    pub fn no_cookies(mut self) -> Self {
        self.cookie_store = false;
        self
    }

    /// Allow self-signed / invalid TLS certificates.
    ///
    /// **Use only for internal/test targets.**
    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.danger_accept_invalid_certs = true;
        self
    }

    pub fn build(self) -> Result<HttpClient> {
        let mut builder = reqwest::Client::builder()
            .timeout(self.timeout)
            .use_rustls_tls()
            .cookie_store(self.cookie_store)
            .danger_accept_invalid_certs(self.danger_accept_invalid_certs)
            .user_agent(&self.user_agent);

        if self.follow_redirects {
            builder = builder.redirect(reqwest::redirect::Policy::limited(self.max_redirects));
        } else {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }

        if let Some(proxy_url) = self.proxy {
            let proxy = reqwest::Proxy::all(&proxy_url)
                .map_err(|e| anyhow!("invalid proxy URL `{proxy_url}`: {e}"))?;
            builder = builder.proxy(proxy);
        }

        // Build default headers
        let mut default_headers = reqwest::header::HeaderMap::new();
        for (k, v) in &self.headers {
            let name = reqwest::header::HeaderName::from_bytes(k.as_bytes())
                .map_err(|e| anyhow!("invalid header name `{k}`: {e}"))?;
            let value = reqwest::header::HeaderValue::from_str(v)
                .map_err(|e| anyhow!("invalid header value for `{k}`: {e}"))?;
            default_headers.insert(name, value);
        }
        builder = builder.default_headers(default_headers);

        let inner = builder
            .build()
            .map_err(|e| anyhow!("failed to build HTTP client: {e}"))?;

        Ok(HttpClient { inner, base_url: self.base_url })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// HttpClient
// ──────────────────────────────────────────────────────────────────────────────

/// Thin wrapper over [`reqwest::Client`] for web-form brute-force attacks.
///
/// All methods return `(status_code, body)` so that the caller can apply
/// whatever success/failure heuristic is appropriate for the target.
pub struct HttpClient {
    pub(crate) inner: reqwest::Client,
    base_url: String,
}

impl HttpClient {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Entry-point for the Builder pattern.
    pub fn builder(base_url: impl Into<String>) -> HttpClientBuilder {
        HttpClientBuilder::new(base_url)
    }

    /// Build a client with the given base URL and per-request timeout.
    ///
    /// Uses `rustls` for TLS (no system trust store needed).
    pub fn new(base_url: impl Into<String>, timeout: Duration) -> Result<Self> {
        HttpClientBuilder::new(base_url).timeout(timeout).build()
    }

    /// Build a client that routes all traffic through `proxy_url`.
    ///
    /// `proxy_url` can be an HTTP or SOCKS5 URL, e.g. `"socks5://127.0.0.1:1080"`.
    pub fn with_proxy(
        base_url: impl Into<String>,
        proxy_url: &str,
        timeout: Duration,
    ) -> Result<Self> {
        HttpClientBuilder::new(base_url)
            .timeout(timeout)
            .proxy(proxy_url)
            .build()
    }

    // ── Existing request helpers ──────────────────────────────────────────────

    /// POST URL-encoded form fields to `path`.
    ///
    /// Returns `(status_code, body_text)`.
    pub async fn post_form(
        &self,
        path: &str,
        fields: &[(&str, &str)],
    ) -> Result<(u16, String)> {
        let url = self.url(path);
        debug!("POST form -> {url}");
        let resp = self.inner.post(&url).form(fields).send().await
            .map_err(|e| anyhow!("POST form to {url}: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        debug!("POST form <- {status} ({} bytes)", body.len());
        Ok((status, body))
    }

    /// GET with HTTP Basic authentication credentials.
    ///
    /// Returns `(status_code, body_text)`.
    pub async fn get_basic_auth(
        &self,
        path: &str,
        user: &str,
        pass: &str,
    ) -> Result<(u16, String)> {
        let url = self.url(path);
        debug!("GET basic-auth -> {url} (user={user})");
        let resp = self.inner.get(&url)
            .basic_auth(user, Some(pass))
            .send()
            .await
            .map_err(|e| anyhow!("GET basic-auth to {url}: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        debug!("GET basic-auth <- {status} ({} bytes)", body.len());
        Ok((status, body))
    }

    /// POST a JSON body to `path`.
    ///
    /// Returns `(status_code, body_text)`.
    pub async fn post_json(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<(u16, String)> {
        let url = self.url(path);
        debug!("POST json -> {url}");
        let resp = self.inner.post(&url).json(&body).send().await
            .map_err(|e| anyhow!("POST json to {url}: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        debug!("POST json <- {status} ({} bytes)", text.len());
        Ok((status, text))
    }

    // ── New: HEAD requests ────────────────────────────────────────────────────

    /// Send a HEAD request; return only the HTTP status code (no body).
    pub async fn head(&self, path: &str) -> Result<u16> {
        let url = self.url(path);
        debug!("HEAD -> {url}");
        let resp = self.inner.head(&url).send().await
            .map_err(|e| anyhow!("HEAD to {url}: {e}"))?;
        let status = resp.status().as_u16();
        debug!("HEAD <- {status}");
        Ok(status)
    }

    /// Send a HEAD request with HTTP Basic auth; return only the status code.
    pub async fn head_basic_auth(&self, path: &str, user: &str, pass: &str) -> Result<u16> {
        let url = self.url(path);
        debug!("HEAD basic-auth -> {url} (user={user})");
        let resp = self.inner.head(&url)
            .basic_auth(user, Some(pass))
            .send()
            .await
            .map_err(|e| anyhow!("HEAD basic-auth to {url}: {e}"))?;
        let status = resp.status().as_u16();
        debug!("HEAD basic-auth <- {status}");
        Ok(status)
    }

    // ── New: requests with extra headers (Decorator pattern) ─────────────────

    /// GET with additional per-request headers injected on top of client defaults.
    pub async fn get_with_headers(
        &self,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> Result<(u16, String)> {
        let url = self.url(path);
        debug!("GET (extra headers) -> {url}");
        let mut req = self.inner.get(&url);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let resp = req.send().await
            .map_err(|e| anyhow!("GET with headers to {url}: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        Ok((status, body))
    }

    /// POST form with additional per-request headers.
    pub async fn post_form_with_headers(
        &self,
        path: &str,
        fields: &[(&str, &str)],
        headers: &HashMap<String, String>,
    ) -> Result<(u16, String)> {
        let url = self.url(path);
        debug!("POST form (extra headers) -> {url}");
        let mut req = self.inner.post(&url).form(fields);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let resp = req.send().await
            .map_err(|e| anyhow!("POST form with headers to {url}: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        Ok((status, body))
    }

    // ── New: Digest Authentication ────────────────────────────────────────────

    /// Attempt HTTP Digest authentication.
    ///
    /// Sends an unauthenticated GET first, parses the `WWW-Authenticate: Digest`
    /// challenge, computes MD5 hashes per RFC 2617, then re-sends with the
    /// `Authorization` header.
    pub async fn get_digest_auth(
        &self,
        path: &str,
        user: &str,
        pass: &str,
    ) -> Result<(u16, String)> {
        let url = self.url(path);
        debug!("GET digest-auth -> {url} (user={user})");

        // Step 1: unauthenticated GET to receive the 401 challenge
        let challenge = self.inner.get(&url).send().await
            .map_err(|e| anyhow!("GET digest challenge to {url}: {e}"))?;

        if challenge.status() != 401 {
            let status = challenge.status().as_u16();
            let body = challenge.text().await.unwrap_or_default();
            return Ok((status, body));
        }

        let www_auth = challenge
            .headers()
            .get("WWW-Authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();

        let realm  = extract_param(&www_auth, "realm").unwrap_or_default();
        let nonce  = extract_param(&www_auth, "nonce").unwrap_or_default();
        let _qop   = extract_param(&www_auth, "qop").unwrap_or_default();

        // Compute Digest per RFC 2617 §3.2.2
        let ha1 = md5_hex(&format!("{}:{}:{}", user, realm, pass));
        let ha2 = md5_hex(&format!("GET:{}", path));
        let nc     = "00000001";
        let cnonce = "zeus1234";
        let response_hash = md5_hex(&format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2));

        let auth_header = format!(
            r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", qop=auth, nc={}, cnonce="{}", response="{}""#,
            user, realm, nonce, path, nc, cnonce, response_hash
        );

        debug!("GET digest-auth (step 2) -> {url}");
        let resp = self.inner.get(&url)
            .header("Authorization", auth_header)
            .send()
            .await
            .map_err(|e| anyhow!("GET digest-auth (step 2) to {url}: {e}"))?;

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        debug!("GET digest-auth <- {status} ({} bytes)", body.len());
        Ok((status, body))
    }

    // ── New: NTLM probe ───────────────────────────────────────────────────────

    /// Return `true` if the server advertises NTLM authentication.
    ///
    /// Sends a HEAD request and inspects the `WWW-Authenticate` response header.
    pub async fn probe_ntlm(&self, path: &str) -> Result<bool> {
        let url = self.url(path);
        debug!("NTLM probe -> {url}");
        let resp = self.inner.head(&url).send().await
            .map_err(|e| anyhow!("NTLM probe to {url}: {e}"))?;

        let has_ntlm = resp
            .headers()
            .get_all("WWW-Authenticate")
            .iter()
            .any(|v| {
                v.to_str()
                    .map(|s| s.to_ascii_uppercase().contains("NTLM"))
                    .unwrap_or(false)
            });

        debug!("NTLM probe <- ntlm={has_ntlm}");
        Ok(has_ntlm)
    }

    // ── New: URL existence check ──────────────────────────────────────────────

    /// Return `true` if a GET to `path` returns one of the `success_codes`.
    pub async fn url_exists(&self, path: &str, success_codes: &[u16]) -> Result<bool> {
        let status = self.head(path).await?;
        Ok(success_codes.contains(&status))
    }

    // ── New: HTML helpers (pure / no network) ────────────────────────────────

    /// Extract all `<input>` field names and values from an HTML body.
    ///
    /// Useful for discovering form field names before a brute-force POST.
    pub fn extract_form_fields(html: &str) -> HashMap<String, String> {
        let mut fields = HashMap::new();
        let mut remaining = html;
        while let Some(pos) = remaining.find("<input") {
            remaining = &remaining[pos..];
            let tag_end = remaining.find('>').unwrap_or(remaining.len());
            let tag = &remaining[..tag_end];

            if let Some(name) = extract_attr(tag, "name") {
                let value = extract_attr(tag, "value").unwrap_or_default();
                fields.insert(name, value);
            }
            // Advance past the current `<input` to avoid infinite loop
            remaining = &remaining[1..];
        }
        fields
    }

    /// Extract a CSRF token from common HTML patterns.
    ///
    /// Looks for `<input name="_token">`, `<meta name="csrf-token">`, etc.
    pub fn extract_csrf_token(html: &str) -> Option<String> {
        for pattern in &[
            r#"name="_token" value=""#,
            r#"name="csrf_token" value=""#,
            r#"name="_csrf" value=""#,
            r#"csrf-token" content=""#,
            r#"name="authenticity_token" value=""#,
        ] {
            if let Some(start) = html.find(pattern) {
                let after = &html[start + pattern.len()..];
                if let Some(end) = after.find('"') {
                    return Some(after[..end].to_string());
                }
            }
        }
        None
    }

    // ── Body analysis helpers ─────────────────────────────────────────────────

    /// Return `true` if `body` contains **any** of the `fail_strings`.
    pub fn is_failure(&self, body: &str, fail_strings: &[&str]) -> bool {
        fail_strings.iter().any(|s| body.contains(s))
    }

    /// Return `true` if `body` contains **any** of the `success_strings`.
    pub fn is_success(&self, body: &str, success_strings: &[&str]) -> bool {
        success_strings.iter().any(|s| body.contains(s))
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    fn url(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("{}{}", self.base_url.trim_end_matches('/'), path)
        } else {
            format!("{}/{}", self.base_url.trim_end_matches('/'), path)
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Private helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Compute the lowercase hex MD5 digest of `input`.
fn md5_hex(input: &str) -> String {
    let mut h = Md5::new();
    h.update(input.as_bytes());
    format!("{:x}", h.finalize())
}

/// Extract a named parameter from a `WWW-Authenticate` style header value.
///
/// Handles both quoted (`key="value"`) and unquoted (`key=value`) forms.
fn extract_param(header: &str, name: &str) -> Option<String> {
    let pattern = format!("{}=", name);
    let start = header.find(&pattern)? + pattern.len();
    let rest = &header[start..];
    if rest.starts_with('"') {
        let end = rest[1..].find('"')? + 1;
        Some(rest[1..end].to_string())
    } else {
        let end = rest
            .find(|c: char| c == ',' || c == ' ')
            .unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

/// Extract an HTML attribute value from a tag fragment.
fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    // Try quoted form first: attr="value"
    let quoted_pattern = format!(r#"{}=""#, attr);
    if let Some(start) = tag.find(&quoted_pattern) {
        let rest = &tag[start + quoted_pattern.len()..];
        let end = rest.find('"').unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    }
    // Try single-quoted form: attr='value'
    let sq_pattern = format!("{}='", attr);
    if let Some(start) = tag.find(&sq_pattern) {
        let rest = &tag[start + sq_pattern.len()..];
        let end = rest.find('\'').unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    }
    None
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests (pure logic — no network)
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> HttpClient {
        HttpClient::new("http://localhost:8080", Duration::from_secs(5)).unwrap()
    }

    // ── URL joining ───────────────────────────────────────────────────────────

    #[test]
    fn url_joining_with_leading_slash() {
        let c = client();
        assert_eq!(c.url("/login"), "http://localhost:8080/login");
    }

    #[test]
    fn url_joining_without_leading_slash() {
        let c = client();
        assert_eq!(c.url("login"), "http://localhost:8080/login");
    }

    #[test]
    fn url_trailing_slash_on_base() {
        let c = HttpClient::new("http://localhost:8080/", Duration::from_secs(5)).unwrap();
        assert_eq!(c.url("/api/login"), "http://localhost:8080/api/login");
    }

    // ── Body analysis ─────────────────────────────────────────────────────────

    #[test]
    fn is_failure_detects_any_match() {
        let c = client();
        assert!(c.is_failure("Invalid password, try again", &["Invalid password", "error"]));
        assert!(!c.is_failure("Welcome back!", &["Invalid password", "error"]));
    }

    #[test]
    fn is_success_detects_any_match() {
        let c = client();
        assert!(c.is_success("Welcome, admin!", &["Welcome", "Dashboard"]));
        assert!(!c.is_success("Login failed.", &["Welcome", "Dashboard"]));
    }

    #[test]
    fn is_failure_empty_patterns() {
        let c = client();
        assert!(!c.is_failure("anything", &[]));
    }

    #[test]
    fn is_success_empty_patterns() {
        let c = client();
        assert!(!c.is_success("anything", &[]));
    }

    // ── Builder ───────────────────────────────────────────────────────────────

    #[test]
    fn builder_defaults_succeed() {
        let c = HttpClient::builder("http://localhost:9090")
            .timeout(Duration::from_secs(3))
            .user_agent("TestBot/1.0")
            .build();
        assert!(c.is_ok());
    }

    #[test]
    fn builder_no_cookies_succeeds() {
        let c = HttpClient::builder("http://localhost:9090")
            .no_cookies()
            .no_follow_redirects()
            .build();
        assert!(c.is_ok());
    }

    #[test]
    fn builder_with_headers_succeeds() {
        let mut hdrs = HashMap::new();
        hdrs.insert("X-Custom".into(), "zeus".into());
        let c = HttpClient::builder("http://localhost:9090")
            .headers(hdrs)
            .header("X-Another", "value")
            .build();
        assert!(c.is_ok());
    }

    #[test]
    fn builder_danger_accept_invalid_certs() {
        let c = HttpClient::builder("https://localhost:9443")
            .danger_accept_invalid_certs()
            .build();
        assert!(c.is_ok());
    }

    // ── Digest auth helpers ───────────────────────────────────────────────────

    #[test]
    fn extract_param_quoted() {
        let header = r#"Digest realm="example.com", nonce="abc123", qop="auth""#;
        assert_eq!(extract_param(header, "realm"), Some("example.com".into()));
        assert_eq!(extract_param(header, "nonce"), Some("abc123".into()));
        assert_eq!(extract_param(header, "qop"),   Some("auth".into()));
    }

    #[test]
    fn extract_param_missing_returns_none() {
        let header = r#"Digest realm="x""#;
        assert_eq!(extract_param(header, "nonce"), None);
    }

    #[test]
    fn md5_hex_known_value() {
        // echo -n "hello" | md5sum  →  5d41402abc4b2a76b9719d911017c592
        assert_eq!(md5_hex("hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    // ── HTML helpers ──────────────────────────────────────────────────────────

    #[test]
    fn extract_form_fields_basic() {
        let html = r#"<form>
            <input name="username" value="">
            <input name="password" value="">
            <input type="hidden" name="_token" value="abc123">
        </form>"#;
        let fields = HttpClient::extract_form_fields(html);
        assert!(fields.contains_key("username"));
        assert!(fields.contains_key("password"));
        assert!(fields.contains_key("_token"));
        assert_eq!(fields["_token"], "abc123");
    }

    #[test]
    fn extract_form_fields_empty_html() {
        let fields = HttpClient::extract_form_fields("<html><body></body></html>");
        assert!(fields.is_empty());
    }

    #[test]
    fn extract_csrf_token_input_token() {
        let html = r#"<input type="hidden" name="_token" value="xyz789" />"#;
        assert_eq!(HttpClient::extract_csrf_token(html), Some("xyz789".into()));
    }

    #[test]
    fn extract_csrf_token_meta_tag() {
        let html = r#"<meta name="csrf-token" content="meta_tok_42">"#;
        assert_eq!(HttpClient::extract_csrf_token(html), Some("meta_tok_42".into()));
    }

    #[test]
    fn extract_csrf_token_none_when_absent() {
        let html = "<html><body><form></form></body></html>";
        assert_eq!(HttpClient::extract_csrf_token(html), None);
    }

    #[test]
    fn extract_attr_quoted() {
        let tag = r#"<input name="user" value="alice">"#;
        assert_eq!(extract_attr(tag, "name"),  Some("user".into()));
        assert_eq!(extract_attr(tag, "value"), Some("alice".into()));
    }

    #[test]
    fn extract_attr_missing() {
        let tag = r#"<input type="text">"#;
        assert_eq!(extract_attr(tag, "name"), None);
    }
}
