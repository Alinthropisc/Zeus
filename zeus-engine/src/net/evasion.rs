//! Traffic evasion strategies — Strategy pattern.
//!
//! Each evasion technique is an independent [`EvasionStrategy`] implementation.
//! Strategies are composable: build a `Vec<Box<dyn EvasionStrategy>>` and apply
//! them in sequence against a [`RequestContext`].

use async_trait::async_trait;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Mutex;

// ──────────────────────────────────────────────────────────────────────────────
// Error
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum EvasionError {
    #[error("rate-limit token bucket exhausted")]
    RateLimited,
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("TLS config error: {0}")]
    TlsConfig(String),
}

// ──────────────────────────────────────────────────────────────────────────────
// RequestContext
// ──────────────────────────────────────────────────────────────────────────────

/// Mutable context passed through an evasion pipeline.
///
/// Strategies mutate headers, the URL, and optionally the body before the
/// request is dispatched.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Destination URL (strategies may rewrite or encode path segments).
    pub url: String,
    /// HTTP headers (key → value).
    pub headers: Vec<(String, String)>,
    /// Optional request body.
    pub body: Option<Vec<u8>>,
    /// TLS cipher-suite hint (opaque string used by TLS strategies).
    pub tls_profile_hint: Option<String>,
}

impl RequestContext {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            headers: Vec::new(),
            body: None,
            tls_profile_hint: None,
        }
    }

    /// Append or overwrite a header.
    pub fn set_header(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        // Replace if already present.
        if let Some(h) = self.headers.iter_mut().find(|(k, _)| k == &key) {
            h.1 = value.into();
        } else {
            self.headers.push((key, value.into()));
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// EvasionStrategy trait
// ──────────────────────────────────────────────────────────────────────────────

/// Core strategy interface — each evasion technique implements this.
#[async_trait]
pub trait EvasionStrategy: Send + Sync + std::fmt::Debug {
    /// Apply this technique to `req`, mutating it in place.
    async fn apply(&self, req: &mut RequestContext) -> Result<(), EvasionError>;
}

// ──────────────────────────────────────────────────────────────────────────────
// 2.1a — TlsFingerprintRotator
// ──────────────────────────────────────────────────────────────────────────────

/// Known TLS "profiles" — each maps to a different cipher-suite / extension
/// ordering that produces a distinct JA3/JA4 fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsProfile {
    /// Mimics Chrome 120.
    Chrome120,
    /// Mimics Firefox 121.
    Firefox121,
    /// Mimics Safari 17.
    Safari17,
    /// Mimics curl/libcurl.
    Curl,
    /// Randomised order — least predictable.
    Random,
}

impl TlsProfile {
    /// Returns a human-readable hint that downstream TLS configuration code
    /// can use to select the appropriate `rustls::ClientConfig`.
    pub fn hint(&self) -> &'static str {
        match self {
            Self::Chrome120 => "chrome120",
            Self::Firefox121 => "firefox121",
            Self::Safari17 => "safari17",
            Self::Curl => "curl",
            Self::Random => "random",
        }
    }

    const ALL: &'static [Self] = &[
        Self::Chrome120,
        Self::Firefox121,
        Self::Safari17,
        Self::Curl,
        Self::Random,
    ];
}

/// Cycles through [`TlsProfile`] variants on every request, randomising the
/// JA3/JA4 fingerprint observed by the server.
#[derive(Debug)]
pub struct TlsFingerprintRotator {
    /// Index into `TlsProfile::ALL`, wrapped atomically.
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl TlsFingerprintRotator {
    pub fn new() -> Self {
        Self {
            counter: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    fn next_profile(&self) -> TlsProfile {
        let idx = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % TlsProfile::ALL.len();
        TlsProfile::ALL[idx]
    }
}

impl Default for TlsFingerprintRotator {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl EvasionStrategy for TlsFingerprintRotator {
    async fn apply(&self, req: &mut RequestContext) -> Result<(), EvasionError> {
        let profile = self.next_profile();
        req.tls_profile_hint = Some(profile.hint().to_string());
        // Inject User-Agent consistent with the chosen profile.
        let ua = match profile {
            TlsProfile::Chrome120 => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
            TlsProfile::Firefox121 => "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            TlsProfile::Safari17 => "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
            TlsProfile::Curl => "curl/8.5.0",
            TlsProfile::Random => "Mozilla/5.0 (compatible; ZeusResearch/1.0)",
        };
        req.set_header("User-Agent", ua);
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 2.1b — SlowRateEvasion (per-session token bucket, req/day granularity)
// ──────────────────────────────────────────────────────────────────────────────

/// Token-bucket evasion — limits total requests per day rather than per second
/// so that low-and-slow attacks stay below daily detection thresholds.
#[derive(Debug)]
pub struct SlowRateEvasion {
    /// Maximum requests allowed per 24-hour window.
    pub requests_per_day: u64,
    inner: Arc<Mutex<SlowRateBucket>>,
}

#[derive(Debug)]
struct SlowRateBucket {
    tokens: u64,
    last_refill: Instant,
}

impl SlowRateEvasion {
    pub fn new(requests_per_day: u64) -> Self {
        Self {
            requests_per_day,
            inner: Arc::new(Mutex::new(SlowRateBucket {
                tokens: requests_per_day,
                last_refill: Instant::now(),
            })),
        }
    }

    /// Refill tokens proportionally to elapsed time since the last refill.
    async fn refill_and_consume(&self) -> Result<(), EvasionError> {
        let mut bucket = self.inner.lock().await;
        let elapsed = bucket.last_refill.elapsed();
        let day = Duration::from_secs(86_400);
        // Tokens accrued since last refill (fractional days → tokens).
        let accrued = (elapsed.as_secs_f64() / day.as_secs_f64()
            * self.requests_per_day as f64) as u64;
        if accrued > 0 {
            bucket.tokens = (bucket.tokens + accrued).min(self.requests_per_day);
            bucket.last_refill = Instant::now();
        }
        if bucket.tokens == 0 {
            return Err(EvasionError::RateLimited);
        }
        bucket.tokens -= 1;
        Ok(())
    }
}

#[async_trait]
impl EvasionStrategy for SlowRateEvasion {
    async fn apply(&self, req: &mut RequestContext) -> Result<(), EvasionError> {
        self.refill_and_consume().await?;
        // Tag the request so downstream telemetry knows rate-limiting is active.
        req.set_header("X-Zeus-RatePolicy", "slow-rate");
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 2.1c — EncodingEvasion
// ──────────────────────────────────────────────────────────────────────────────

/// URL encoding variants used to bypass WAF/IDS signature matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingVariant {
    /// Standard `%xx` URL encoding of non-safe characters.
    UrlEncoded,
    /// Double-encode: `%25xx` — the WAF decodes once and sees `%xx`.
    DoubleEncoded,
    /// Replace ASCII characters with their Unicode fullwidth equivalents
    /// (U+FF01..U+FF5E for `!`..`~`).
    UnicodeNormalized,
    /// No encoding — send the raw value.
    Raw,
}

/// Applies an encoding variant to the path component of the request URL.
#[derive(Debug)]
pub struct EncodingEvasion {
    pub variant: EncodingVariant,
}

impl EncodingEvasion {
    pub fn new(variant: EncodingVariant) -> Self { Self { variant } }

    fn encode_path(path: &str, variant: EncodingVariant) -> String {
        match variant {
            EncodingVariant::Raw => path.to_string(),
            EncodingVariant::UrlEncoded => {
                path.chars()
                    .map(|c| {
                        if c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '~') {
                            c.to_string()
                        } else {
                            format!("%{:02X}", c as u32)
                        }
                    })
                    .collect()
            }
            EncodingVariant::DoubleEncoded => {
                // First URL-encode, then encode the '%' itself as %25.
                let once = Self::encode_path(path, EncodingVariant::UrlEncoded);
                once.replace('%', "%25")
            }
            EncodingVariant::UnicodeNormalized => {
                path.chars()
                    .map(|c| {
                        let cp = c as u32;
                        // ASCII printable range 0x21..=0x7E → fullwidth block.
                        if (0x21..=0x7E).contains(&cp) {
                            char::from_u32(cp + 0xFF00 - 0x20)
                                .map(|fc| fc.to_string())
                                .unwrap_or_else(|| c.to_string())
                        } else {
                            c.to_string()
                        }
                    })
                    .collect()
            }
        }
    }
}

#[async_trait]
impl EvasionStrategy for EncodingEvasion {
    async fn apply(&self, req: &mut RequestContext) -> Result<(), EvasionError> {
        // Split URL into scheme+host and path+query, encode only the path part.
        if let Some(path_start) = req.url.find("://").and_then(|i| req.url[i + 3..].find('/').map(|j| i + 3 + j)) {
            let (prefix, path) = req.url.split_at(path_start);
            req.url = format!("{}{}", prefix, Self::encode_path(path, self.variant));
        }
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Builder for evasion pipeline
// ──────────────────────────────────────────────────────────────────────────────

/// Builder for composing multiple [`EvasionStrategy`] implementations into a
/// pipeline that is applied left-to-right.
#[derive(Debug, Default)]
pub struct EvasionPipelineBuilder {
    strategies: Vec<Box<dyn EvasionStrategy>>,
}

impl EvasionPipelineBuilder {
    pub fn new() -> Self { Self::default() }

    pub fn add(mut self, strategy: impl EvasionStrategy + 'static) -> Self {
        self.strategies.push(Box::new(strategy));
        self
    }

    pub fn build(self) -> EvasionPipeline {
        EvasionPipeline { strategies: self.strategies }
    }
}

/// An ordered pipeline of evasion strategies applied sequentially.
#[derive(Debug)]
pub struct EvasionPipeline {
    strategies: Vec<Box<dyn EvasionStrategy>>,
}

impl EvasionPipeline {
    pub async fn apply_all(&self, req: &mut RequestContext) -> Result<(), EvasionError> {
        for strategy in &self.strategies {
            strategy.apply(req).await?;
        }
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tls_rotator_cycles_profiles() {
        let rotator = TlsFingerprintRotator::new();
        let mut req = RequestContext::new("https://example.com/");
        rotator.apply(&mut req).await.unwrap();
        let first_hint = req.tls_profile_hint.clone();
        rotator.apply(&mut req).await.unwrap();
        let second_hint = req.tls_profile_hint.clone();
        // Different profiles on consecutive calls.
        assert_ne!(first_hint, second_hint);
    }

    #[tokio::test]
    async fn slow_rate_allows_first_request() {
        let evasion = SlowRateEvasion::new(100);
        let mut req = RequestContext::new("https://example.com/");
        assert!(evasion.apply(&mut req).await.is_ok());
    }

    #[tokio::test]
    async fn slow_rate_exhausts_tokens() {
        let evasion = SlowRateEvasion::new(1);
        // Drain the single token.
        {
            let mut b = evasion.inner.lock().await;
            b.tokens = 0;
        }
        let mut req = RequestContext::new("https://example.com/");
        assert!(matches!(evasion.apply(&mut req).await, Err(EvasionError::RateLimited)));
    }

    #[tokio::test]
    async fn url_encoding_encodes_special_chars() {
        let strat = EncodingEvasion::new(EncodingVariant::UrlEncoded);
        let mut req = RequestContext::new("https://example.com/path?q=<script>");
        strat.apply(&mut req).await.unwrap();
        assert!(!req.url.contains('<'));
    }

    #[tokio::test]
    async fn double_encoding_has_percent25() {
        let strat = EncodingEvasion::new(EncodingVariant::DoubleEncoded);
        let mut req = RequestContext::new("https://example.com/path?q=<x>");
        strat.apply(&mut req).await.unwrap();
        assert!(req.url.contains("%25"));
    }

    #[tokio::test]
    async fn raw_encoding_leaves_url_unchanged() {
        let strat = EncodingEvasion::new(EncodingVariant::Raw);
        let original = "https://example.com/path?q=hello";
        let mut req = RequestContext::new(original);
        strat.apply(&mut req).await.unwrap();
        assert_eq!(req.url, original);
    }

    #[tokio::test]
    async fn pipeline_applies_all_strategies() {
        let pipeline = EvasionPipelineBuilder::new()
            .add(TlsFingerprintRotator::new())
            .add(EncodingEvasion::new(EncodingVariant::Raw))
            .build();

        let mut req = RequestContext::new("https://example.com/test");
        pipeline.apply_all(&mut req).await.unwrap();
        // TLS hint set by first strategy.
        assert!(req.tls_profile_hint.is_some());
    }
}
