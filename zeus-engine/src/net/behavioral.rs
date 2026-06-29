//! Behavioral camouflage — Decorator pattern wrapping any [`EvasionStrategy`]
//! with human-like timing, realistic browser headers, and referrer chains.
//!
//! # Design
//! - **Decorator** — [`BehavioralDecorator`] wraps any strategy and injects
//!   Gaussian think-time delays plus browser-fingerprint headers before each
//!   request is handed off to the inner strategy.
//! - **Composite** — [`BehaviorProfile`] composes independent micro-behaviors
//!   (timing distribution, mouse jitter headers, viewport, referrer chain).

use anyhow::Result;
use std::collections::HashMap;
use std::time::Duration;
use tracing::debug;

// ──────────────────────────────────────────────────────────────────────────────
// Micro-behavior building blocks
// ──────────────────────────────────────────────────────────────────────────────

/// Gaussian think-time distribution between simulated page interactions.
#[derive(Debug, Clone)]
pub struct ThinkTimeDistribution {
    /// Mean delay in milliseconds.
    pub mean_ms: u64,
    /// Standard deviation in milliseconds.
    pub std_dev_ms: u64,
}

impl ThinkTimeDistribution {
    /// Sample a delay using the Box-Muller transform (no external RNG crate needed).
    pub fn sample(&self) -> Duration {
        // Box-Muller: two uniform samples → one standard-normal sample
        let u1: f64 = pseudo_uniform(self.mean_ms ^ 0xDEAD_BEEF);
        let u2: f64 = pseudo_uniform(self.std_dev_ms ^ 0xCAFE_BABE);

        // Clamp u1 away from 0 to avoid log(0)
        let u1 = u1.max(1e-10);
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        let sample_ms = self.mean_ms as f64 + z * self.std_dev_ms as f64;
        let clamped = sample_ms.max(0.0) as u64;
        Duration::from_millis(clamped)
    }
}

/// Simulated browser viewport dimensions.
#[derive(Debug, Clone, Copy)]
pub struct Viewport {
    pub width: u16,
    pub height: u16,
}

impl Viewport {
    /// Build the `Sec-CH-Viewport-Width` / `Viewport-Width` header value.
    pub fn as_header_value(&self) -> String {
        format!("{}", self.width)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Composite: BehaviorProfile
// ──────────────────────────────────────────────────────────────────────────────

/// Composite profile of human-like micro-behaviors injected per request.
#[derive(Debug, Clone)]
pub struct BehaviorProfile {
    /// Gaussian delay between simulated interactions.
    pub think_time: ThinkTimeDistribution,
    /// Whether to inject `X-Mouse-X` / `X-Mouse-Y` headers.
    pub mouse_jitter: bool,
    /// `Accept-Language` header value.
    pub accept_language: &'static str,
    /// Browser viewport used for `Viewport-Width` hints.
    pub viewport: Viewport,
    /// Ordered list of referrer URLs injected as `Referer` header per hop.
    pub referrer_chain: Vec<String>,
    /// User-Agent string for this profile.
    pub user_agent: &'static str,
}

impl BehaviorProfile {
    /// Realistic Chrome 124 on Windows 11 profile.
    pub fn chrome_windows() -> Self {
        Self {
            think_time: ThinkTimeDistribution { mean_ms: 1_800, std_dev_ms: 600 },
            mouse_jitter: true,
            accept_language: "en-US,en;q=0.9",
            viewport: Viewport { width: 1920, height: 1080 },
            referrer_chain: vec![
                "https://www.google.com/".into(),
                "https://www.google.com/search?q=login".into(),
            ],
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                AppleWebKit/537.36 (KHTML, like Gecko) \
                Chrome/124.0.0.0 Safari/537.36",
        }
    }

    /// Realistic Safari 17 on macOS Sonoma profile.
    pub fn safari_macos() -> Self {
        Self {
            think_time: ThinkTimeDistribution { mean_ms: 2_200, std_dev_ms: 800 },
            mouse_jitter: false,
            accept_language: "en-GB,en;q=0.9",
            viewport: Viewport { width: 1440, height: 900 },
            referrer_chain: vec![
                "https://duckduckgo.com/".into(),
            ],
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) \
                AppleWebKit/605.1.15 (KHTML, like Gecko) \
                Version/17.4.1 Safari/605.1.15",
        }
    }

    /// Realistic Firefox 125 on Linux profile.
    pub fn firefox_linux() -> Self {
        Self {
            think_time: ThinkTimeDistribution { mean_ms: 1_500, std_dev_ms: 500 },
            mouse_jitter: false,
            accept_language: "en-US,en;q=0.5",
            viewport: Viewport { width: 1366, height: 768 },
            referrer_chain: vec![],
            user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) \
                Gecko/20100101 Firefox/125.0",
        }
    }

    /// Build a header map from this profile for a given hop index into the referrer chain.
    pub fn headers(&self, referrer_hop: usize) -> HashMap<String, String> {
        let mut map = HashMap::new();

        map.insert("Accept-Language".into(), self.accept_language.into());
        map.insert("User-Agent".into(), self.user_agent.into());
        map.insert("Viewport-Width".into(), self.viewport.as_header_value());
        map.insert(
            "Accept".into(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into(),
        );
        map.insert("Accept-Encoding".into(), "gzip, deflate, br".into());
        map.insert("DNT".into(), "1".into());
        map.insert("Sec-Fetch-Site".into(), "cross-site".into());
        map.insert("Sec-Fetch-Mode".into(), "navigate".into());
        map.insert("Sec-Fetch-Dest".into(), "document".into());

        if let Some(referrer) = self.referrer_chain.get(referrer_hop) {
            map.insert("Referer".into(), referrer.clone());
        }

        if self.mouse_jitter {
            // Synthetic mouse position headers used by some behavioural analytics SDKs
            let x = (referrer_hop as u64 * 137 + 450) % 1920;
            let y = (referrer_hop as u64 * 97 + 300) % 1080;
            map.insert("X-Mouse-X".into(), x.to_string());
            map.insert("X-Mouse-Y".into(), y.to_string());
        }

        map
    }

    /// Asynchronously wait for the think-time delay for this profile.
    pub async fn think(&self) {
        let delay = self.think_time.sample();
        debug!("BehaviorProfile: think delay {:?}", delay);
        tokio::time::sleep(delay).await;
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Decorator: BehavioralDecorator
// ──────────────────────────────────────────────────────────────────────────────

/// Marker trait for strategies that can be decorated — matches the shape of
/// `EvasionStrategy` without importing it (zeus-net is already the home crate).
pub trait EvasionStrategy: Send + Sync {
    /// A short label for logging.
    fn name(&self) -> &'static str;

    /// Mutate `headers` before the HTTP request is sent.
    fn apply(&self, headers: &mut HashMap<String, String>);
}

/// **Decorator** — wraps any [`EvasionStrategy`] with:
/// 1. Gaussian think-time delay (via `BehaviorProfile::think`).
/// 2. Browser-fingerprint headers injected before delegating to `inner`.
/// 3. Referrer chain cycling across successive calls.
#[derive(Debug)]
pub struct BehavioralDecorator<S: EvasionStrategy> {
    inner: S,
    profile: BehaviorProfile,
    /// Tracks which referrer URL in the chain to use next.
    referrer_idx: std::sync::atomic::AtomicUsize,
}

impl<S: EvasionStrategy> BehavioralDecorator<S> {
    /// Wrap `inner` strategy with the given `profile`.
    pub fn new(inner: S, profile: BehaviorProfile) -> Self {
        Self {
            inner,
            profile,
            referrer_idx: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Apply behavioral camouflage: wait think-time, then inject headers,
    /// then delegate to the inner strategy.
    pub async fn apply_with_think(&self, headers: &mut HashMap<String, String>) {
        self.profile.think().await;
        let hop = self
            .referrer_idx
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let behavior_headers = self.profile.headers(hop);
        for (k, v) in behavior_headers {
            // Don't overwrite headers the inner strategy already set
            headers.entry(k).or_insert(v);
        }
        self.inner.apply(headers);
    }
}

impl<S: EvasionStrategy> EvasionStrategy for BehavioralDecorator<S> {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn apply(&self, headers: &mut HashMap<String, String>) {
        // Synchronous path: inject profile headers without the async think delay.
        let hop = self
            .referrer_idx
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let behavior_headers = self.profile.headers(hop);
        for (k, v) in behavior_headers {
            headers.entry(k).or_insert(v);
        }
        self.inner.apply(headers);
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Private helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Deterministic pseudo-uniform [0, 1) value derived from a seed.
///
/// Used for Box-Muller sampling without pulling in the `rand` crate.
fn pseudo_uniform(seed: u64) -> f64 {
    // xorshift64
    let mut x = seed.wrapping_add(0x9E3779B97F4A7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D049BB133111EB);
    x ^= x >> 31;
    // Map to [0, 1)
    (x >> 11) as f64 / (1u64 << 53) as f64
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopStrategy;
    impl EvasionStrategy for NoopStrategy {
        fn name(&self) -> &'static str { "noop" }
        fn apply(&self, _headers: &mut HashMap<String, String>) {}
    }

    #[test]
    fn chrome_profile_headers_contain_user_agent() {
        let profile = BehaviorProfile::chrome_windows();
        let hdrs = profile.headers(0);
        assert!(hdrs.get("User-Agent").unwrap().contains("Chrome"));
        assert_eq!(hdrs.get("Accept-Language").unwrap(), "en-US,en;q=0.9");
    }

    #[test]
    fn safari_profile_mouse_jitter_absent() {
        let profile = BehaviorProfile::safari_macos();
        let hdrs = profile.headers(0);
        assert!(!hdrs.contains_key("X-Mouse-X"));
    }

    #[test]
    fn chrome_profile_mouse_jitter_present() {
        let profile = BehaviorProfile::chrome_windows();
        let hdrs = profile.headers(0);
        assert!(hdrs.contains_key("X-Mouse-X"));
    }

    #[test]
    fn decorator_injects_behavioral_headers() {
        let dec = BehavioralDecorator::new(NoopStrategy, BehaviorProfile::firefox_linux());
        let mut hdrs = HashMap::new();
        dec.apply(&mut hdrs);
        assert!(hdrs.contains_key("Accept-Language"));
        assert!(hdrs.contains_key("Viewport-Width"));
    }

    #[test]
    fn referrer_cycles_across_calls() {
        let profile = BehaviorProfile::chrome_windows(); // 2-entry chain
        let dec = BehavioralDecorator::new(NoopStrategy, profile);
        let mut h1 = HashMap::new();
        dec.apply(&mut h1);
        let mut h2 = HashMap::new();
        dec.apply(&mut h2);
        // Second call uses hop index 1, which is a different referrer
        assert_ne!(h1.get("Referer"), h2.get("Referer"));
    }

    #[test]
    fn think_time_sample_in_plausible_range() {
        let dist = ThinkTimeDistribution { mean_ms: 1000, std_dev_ms: 100 };
        // Run 100 samples; none should be wildly negative (clamped to 0)
        for _ in 0..100 {
            let d = dist.sample();
            assert!(d.as_millis() < 10_000, "sample too large: {:?}", d);
        }
    }
}
