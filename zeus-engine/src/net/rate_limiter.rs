//! Token-bucket rate limiter with burst support, per-host limiting, and stats.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;

// ──────────────────────────────────────────────────────────────────────────────
// RateLimiter
// ──────────────────────────────────────────────────────────────────────────────

/// Token-bucket rate limiter for throttling brute-force attempts.
///
/// Supports:
/// - Burst capacity (`with_burst`)
/// - Adaptive rate control (`slow_down` / `speed_up`)
/// - Acquisition statistics (`total_acquired`, `total_waited_ms`)
pub struct RateLimiter {
    inner: Arc<AsyncMutex<RateLimiterInner>>,
}

struct RateLimiterInner {
    tokens: f64,
    /// Current bucket capacity (== burst size).
    max_tokens: f64,
    /// Original max — ceiling for `speed_up`.
    original_rate: f64,
    refill_rate: f64,
    last_refill: Instant,
    #[allow(dead_code)]
    burst_size: f64,
    /// Total successful `acquire` calls.
    total_acquired: u64,
    /// Total milliseconds spent waiting across all `acquire` calls.
    total_waited_ms: u64,
}

impl RateLimiterInner {
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }
}

impl RateLimiter {
    /// Create a limiter with `rps` refill rate and a burst equal to one second
    /// of requests (i.e. `burst_size = rps`).
    pub fn new(requests_per_second: f64) -> Self {
        Self::with_burst(requests_per_second, requests_per_second)
    }

    /// Create a limiter with `rps` refill rate and an explicit `burst_size`.
    ///
    /// `burst_size` is the maximum number of tokens that can accumulate.
    pub fn with_burst(requests_per_second: f64, burst_size: f64) -> Self {
        assert!(requests_per_second > 0.0, "rate must be > 0");
        assert!(burst_size > 0.0, "burst_size must be > 0");
        Self {
            inner: Arc::new(AsyncMutex::new(RateLimiterInner {
                tokens: burst_size,
                max_tokens: burst_size,
                original_rate: requests_per_second,
                refill_rate: requests_per_second,
                last_refill: Instant::now(),
                burst_size,
                total_acquired: 0,
                total_waited_ms: 0,
            })),
        }
    }

    /// Effectively unlimited — never blocks in practice.
    pub fn new_unlimited() -> Self {
        let cap = 1_000_000_000.0_f64;
        Self {
            inner: Arc::new(AsyncMutex::new(RateLimiterInner {
                tokens: cap,
                max_tokens: cap,
                original_rate: cap,
                refill_rate: cap,
                last_refill: Instant::now(),
                burst_size: cap,
                total_acquired: 0,
                total_waited_ms: 0,
            })),
        }
    }

    /// Convenience constructor from an integer rate.
    pub fn from_rate(rate: u64) -> Self {
        Self::new(rate as f64)
    }

    /// Wait until one token is available, then consume it.
    pub async fn acquire(&self) {
        self.acquire_many(1).await;
    }

    /// Wait until `n` tokens are available, then consume them all atomically.
    pub async fn acquire_many(&self, n: u64) {
        let needed = n as f64;
        let mut total_wait = Duration::ZERO;
        loop {
            let wait = {
                let mut inner = self.inner.lock().await;
                inner.refill();
                if inner.tokens >= needed {
                    inner.tokens -= needed;
                    inner.total_acquired += n;
                    inner.total_waited_ms += total_wait.as_millis() as u64;
                    None
                } else {
                    let deficit = needed - inner.tokens;
                    let secs = deficit / inner.refill_rate;
                    Some(Duration::from_secs_f64(secs))
                }
            };
            match wait {
                None => return,
                Some(d) => {
                    total_wait += d;
                    tokio::time::sleep(d).await;
                }
            }
        }
    }

    /// Non-blocking try: consume one token if available.
    pub async fn try_acquire(&self) -> bool {
        let mut inner = self.inner.lock().await;
        inner.refill();
        if inner.tokens >= 1.0 {
            inner.tokens -= 1.0;
            inner.total_acquired += 1;
            true
        } else {
            false
        }
    }

    /// Adaptive: halve the refill rate (floor: 0.01 req/s).
    pub async fn slow_down(&self) {
        let mut inner = self.inner.lock().await;
        inner.refill();
        inner.refill_rate = (inner.refill_rate / 2.0).max(0.01);
        inner.max_tokens = inner.refill_rate;
        inner.tokens = inner.tokens.min(inner.max_tokens);
    }

    /// Adaptive: double the refill rate (ceiling: original rate).
    pub async fn speed_up(&self) {
        let mut inner = self.inner.lock().await;
        inner.refill();
        inner.refill_rate = (inner.refill_rate * 2.0).min(inner.original_rate);
        inner.max_tokens = inner.refill_rate;
    }

    /// Current refill rate (requests per second).
    pub async fn current_rate(&self) -> f64 {
        self.inner.lock().await.refill_rate
    }

    /// Total number of tokens successfully acquired since construction.
    pub async fn total_acquired(&self) -> u64 {
        self.inner.lock().await.total_acquired
    }

    /// Total milliseconds spent waiting across all `acquire` calls.
    pub async fn total_waited_ms(&self) -> u64 {
        self.inner.lock().await.total_waited_ms
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// GlobalRateLimiter
// ──────────────────────────────────────────────────────────────────────────────

/// Per-host rate limiter backed by a map of [`RateLimiter`]s.
///
/// Hosts without an explicit limit use `default_rps`.
pub struct GlobalRateLimiter {
    default_rps: f64,
    per_host: Arc<Mutex<HashMap<String, RateLimiter>>>,
}

impl GlobalRateLimiter {
    pub fn new(default_rps: f64) -> Self {
        Self {
            default_rps,
            per_host: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// No per-host throttling (effectively unlimited).
    pub fn unlimited() -> Self {
        Self::new(f64::MAX / 2.0)
    }

    /// Override the rate limit for a specific host.
    pub fn set_host_limit(&self, host: impl Into<String>, rps: f64) {
        let mut map = self.per_host.lock();
        map.insert(host.into(), RateLimiter::new(rps));
    }

    /// Acquire one token for `host`, blocking until one is available.
    ///
    /// Uses the host-specific limit if set, otherwise falls back to the
    /// default rate.
    pub async fn acquire(&self, host: &str) {
        // Pull the Arc-clone out of the lock to avoid holding it across await.
        let limiter_arc: Option<Arc<AsyncMutex<RateLimiterInner>>> = {
            let map = self.per_host.lock();
            map.get(host).map(|rl| Arc::clone(&rl.inner))
        };

        if let Some(inner_arc) = limiter_arc {
            // Reuse existing per-host limiter
            let needed = 1.0_f64;
            loop {
                let wait = {
                    let mut inner = inner_arc.lock().await;
                    inner.refill();
                    if inner.tokens >= needed {
                        inner.tokens -= needed;
                        inner.total_acquired += 1;
                        None
                    } else {
                        let deficit = needed - inner.tokens;
                        let secs = deficit / inner.refill_rate;
                        Some(Duration::from_secs_f64(secs))
                    }
                };
                match wait {
                    None => return,
                    Some(d) => tokio::time::sleep(d).await,
                }
            }
        } else {
            // No host-specific limit — create a temporary limiter or use default
            // For simplicity with unlimited/very-high default, just create inline.
            let rps = self.default_rps;
            if rps >= 1_000_000_000.0 {
                // Effectively unlimited — skip sleeping
                return;
            }
            // Insert a new limiter for this host and acquire from it
            let new_rl = RateLimiter::new(rps);
            let inner_arc = Arc::clone(&new_rl.inner);
            {
                let mut map = self.per_host.lock();
                // Another task may have inserted in the meantime — use entry API
                map.entry(host.to_string()).or_insert(new_rl);
            }
            // Acquire from the (possibly newly inserted) limiter
            let map = self.per_host.lock();
            if let Some(rl) = map.get(host) {
                let arc = Arc::clone(&rl.inner);
                drop(map);
                let needed = 1.0_f64;
                loop {
                    let wait = {
                        let mut inner = arc.lock().await;
                        inner.refill();
                        if inner.tokens >= needed {
                            inner.tokens -= needed;
                            inner.total_acquired += 1;
                            None
                        } else {
                            let deficit = needed - inner.tokens;
                            let secs = deficit / inner.refill_rate;
                            Some(Duration::from_secs_f64(secs))
                        }
                    };
                    match wait {
                        None => return,
                        Some(d) => tokio::time::sleep(d).await,
                    }
                }
            } else {
                drop(map);
                // Fallback: acquire from the temporary limiter we created
                let needed = 1.0_f64;
                loop {
                    let wait = {
                        let mut inner = inner_arc.lock().await;
                        inner.refill();
                        if inner.tokens >= needed {
                            inner.tokens -= needed;
                            inner.total_acquired += 1;
                            None
                        } else {
                            let deficit = needed - inner.tokens;
                            let secs = deficit / inner.refill_rate;
                            Some(Duration::from_secs_f64(secs))
                        }
                    };
                    match wait {
                        None => return,
                        Some(d) => tokio::time::sleep(d).await,
                    }
                }
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Existing tests (preserved) ────────────────────────────────────────────

    #[tokio::test]
    async fn acquire_does_not_deadlock() {
        let rl = RateLimiter::new(1000.0);
        for _ in 0..5 {
            rl.acquire().await;
        }
    }

    #[tokio::test]
    async fn try_acquire_returns_false_when_empty() {
        let rl = RateLimiter::new(1000.0);
        for _ in 0..1000 {
            rl.acquire().await;
        }
        let _ = rl.try_acquire().await;
    }

    #[tokio::test]
    async fn slow_down_halves_rate() {
        let rl = RateLimiter::new(100.0);
        rl.slow_down().await;
        let rate = rl.current_rate().await;
        assert!((rate - 50.0).abs() < 0.01, "expected ~50, got {rate}");
    }

    #[tokio::test]
    async fn speed_up_capped_at_original() {
        let rl = RateLimiter::new(10.0);
        rl.slow_down().await;
        rl.speed_up().await;
        rl.speed_up().await;
        let rate = rl.current_rate().await;
        assert!((rate - 10.0).abs() < 0.01, "expected 10.0, got {rate}");
    }

    #[test]
    fn from_rate_constructor() {
        let _rl = RateLimiter::from_rate(50);
    }

    #[test]
    #[should_panic(expected = "rate must be > 0")]
    fn zero_rate_panics() {
        let _rl = RateLimiter::new(0.0);
    }

    #[tokio::test]
    async fn new_unlimited_never_blocks() {
        let rl = RateLimiter::new_unlimited();
        for _ in 0..100_000 {
            rl.acquire().await;
        }
    }

    #[tokio::test]
    async fn new_unlimited_try_acquire_succeeds() {
        let rl = RateLimiter::new_unlimited();
        assert!(rl.try_acquire().await);
    }

    // ── New tests ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn rate_limiter_burst() {
        // burst_size of 5 means 5 tokens available immediately
        let rl = RateLimiter::with_burst(1.0, 5.0);
        // All 5 should succeed instantly without waiting
        for _ in 0..5 {
            assert!(rl.try_acquire().await);
        }
        // 6th should fail (bucket empty, refill rate is 1/s)
        assert!(!rl.try_acquire().await);
    }

    #[tokio::test]
    async fn rate_limiter_stats() {
        let rl = RateLimiter::new(10_000.0);
        for _ in 0..10 {
            rl.acquire().await;
        }
        assert_eq!(rl.total_acquired().await, 10);
        // With a very high rate there should be zero wait time
        assert_eq!(rl.total_waited_ms().await, 0);
    }

    #[tokio::test]
    async fn global_rate_limiter_per_host() {
        let g = GlobalRateLimiter::new(100.0);
        g.set_host_limit("slow.example.com", 1.0);
        g.set_host_limit("fast.example.com", 10_000.0);

        // fast host should not block
        for _ in 0..5 {
            g.acquire("fast.example.com").await;
        }
        // slow host has 1 token at construction — first acquire should succeed
        g.acquire("slow.example.com").await;
    }

    #[tokio::test]
    async fn unlimited_never_waits() {
        let g = GlobalRateLimiter::unlimited();
        for _ in 0..1000 {
            g.acquire("any.host").await;
        }
    }
}
