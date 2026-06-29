use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use std::collections::VecDeque;

/// Signals from the server that change our strategy
#[derive(Debug, Clone)]
pub enum ServerSignal {
    RateLimited { retry_after: Option<Duration> },
    AccountLocked { username: String },
    WafDetected { vendor: String },
    CaptchaRequired,
    MfaRequired { username: String },
    NormalResponse,
}

/// Adaptive throttling state
#[derive(Debug)]
struct ThrottleState {
    current_rps: f64,
    min_rps: f64,
    max_rps: f64,
    /// Consecutive rate-limit hits
    consecutive_limits: u32,
    /// Last rate-limit time
    last_limit: Option<Instant>,
    /// Recent response times
    response_times: VecDeque<Duration>,
}

impl ThrottleState {
    fn new(target_rps: f64) -> Self {
        Self {
            current_rps: target_rps,
            min_rps: 0.1,
            max_rps: target_rps * 2.0,
            consecutive_limits: 0,
            last_limit: None,
            response_times: VecDeque::with_capacity(50),
        }
    }

    /// Back off due to rate limiting
    fn backoff(&mut self) -> Duration {
        self.consecutive_limits += 1;
        self.last_limit = Some(Instant::now());
        // Exponential backoff: halve RPS each time, cap at min
        self.current_rps = (self.current_rps / 2.0).max(self.min_rps);
        // Wait time: 1s * 2^consecutive_limits, max 60s
        let wait_secs = (1.0 * 2f64.powi(self.consecutive_limits as i32)).min(60.0);
        Duration::from_secs_f64(wait_secs)
    }

    /// Server accepted normally — gradually increase RPS
    fn on_success(&mut self) {
        if self.consecutive_limits > 0 {
            self.consecutive_limits = self.consecutive_limits.saturating_sub(1);
        }
        // Slowly ramp back up (10% increase per normal response after backoff)
        if self.current_rps < self.max_rps {
            self.current_rps = (self.current_rps * 1.1).min(self.max_rps);
        }
    }

    fn record_response_time(&mut self, d: Duration) {
        if self.response_times.len() >= 50 {
            self.response_times.pop_front();
        }
        self.response_times.push_back(d);
    }

    fn avg_response_time_ms(&self) -> f64 {
        if self.response_times.is_empty() { return 0.0; }
        self.response_times.iter().map(|d| d.as_secs_f64() * 1000.0).sum::<f64>()
            / self.response_times.len() as f64
    }
}

/// Statistics collected by AdaptiveController
#[derive(Debug, Clone, Default)]
pub struct AdaptiveStats {
    pub total_signals: u64,
    pub rate_limit_events: u64,
    pub lockout_events: u64,
    pub waf_events: u64,
    pub captcha_events: u64,
    pub mfa_events: u64,
    pub current_rps: f64,
    pub avg_response_time_ms: f64,
    /// Usernames known to be locked
    pub locked_usernames: Vec<String>,
    /// WAF vendors detected
    pub waf_vendors: Vec<String>,
}

pub struct AdaptiveController {
    throttle: Arc<RwLock<ThrottleState>>,
    stats: Arc<RwLock<AdaptiveStats>>,
    paused: Arc<AtomicBool>,
}

impl AdaptiveController {
    pub fn new(target_rps: f64) -> Self {
        Self {
            throttle: Arc::new(RwLock::new(ThrottleState::new(target_rps))),
            stats: Arc::new(RwLock::new(AdaptiveStats::default())),
            paused: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Process a signal from the server, returns optional wait duration
    pub async fn process_signal(&self, signal: ServerSignal) -> Option<Duration> {
        let mut stats = self.stats.write();
        stats.total_signals += 1;

        match signal {
            ServerSignal::RateLimited { retry_after } => {
                stats.rate_limit_events += 1;
                let mut throttle = self.throttle.write();
                let backoff = throttle.backoff();
                drop(throttle);
                drop(stats);

                let wait = retry_after.unwrap_or(backoff);
                tracing::warn!("Rate limited — waiting {:.1}s, RPS reduced", wait.as_secs_f64());
                tokio::time::sleep(wait).await;
                Some(wait)
            }
            ServerSignal::AccountLocked { username } => {
                stats.lockout_events += 1;
                if !stats.locked_usernames.contains(&username) {
                    stats.locked_usernames.push(username.clone());
                }
                tracing::warn!("Account locked: {}", username);
                None
            }
            ServerSignal::WafDetected { vendor } => {
                stats.waf_events += 1;
                if !stats.waf_vendors.contains(&vendor) {
                    stats.waf_vendors.push(vendor.clone());
                    tracing::warn!("WAF detected: {}", vendor);
                }
                // Slow way down when WAF is detected
                let mut throttle = self.throttle.write();
                throttle.current_rps = (throttle.current_rps * 0.25).max(throttle.min_rps);
                drop(throttle);
                None
            }
            ServerSignal::CaptchaRequired => {
                stats.captcha_events += 1;
                tracing::warn!("CAPTCHA detected — bot protection active");
                None
            }
            ServerSignal::MfaRequired { username } => {
                stats.mfa_events += 1;
                tracing::info!("MFA required for {} — password may be correct!", username);
                None
            }
            ServerSignal::NormalResponse => {
                let mut throttle = self.throttle.write();
                throttle.on_success();
                None
            }
        }
    }

    pub fn record_response_time(&self, d: Duration) {
        let mut throttle = self.throttle.write();
        throttle.record_response_time(d);
        let avg = throttle.avg_response_time_ms();
        drop(throttle);
        self.stats.write().avg_response_time_ms = avg;
    }

    pub fn current_rps(&self) -> f64 {
        let t = self.throttle.read();
        let rps = t.current_rps;
        drop(t);
        self.stats.write().current_rps = rps;
        rps
    }

    pub fn stats(&self) -> AdaptiveStats {
        self.stats.read().clone()
    }

    pub fn is_locked(&self, username: &str) -> bool {
        self.stats.read().locked_usernames.contains(&username.to_string())
    }

    /// Worker interval based on current RPS
    pub fn worker_interval(&self) -> Duration {
        let rps = self.current_rps();
        if rps <= 0.0 {
            Duration::from_secs(10)
        } else {
            Duration::from_secs_f64(1.0 / rps)
        }
    }

    /// Pause all workers
    pub fn pause(&self) { self.paused.store(true, Ordering::Relaxed); }
    pub fn resume(&self) { self.paused.store(false, Ordering::Relaxed); }
    pub fn is_paused(&self) -> bool { self.paused.load(Ordering::Relaxed) }
}

impl Clone for AdaptiveController {
    fn clone(&self) -> Self {
        Self {
            throttle: Arc::clone(&self.throttle),
            stats: Arc::clone(&self.stats),
            paused: Arc::clone(&self.paused),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn adaptive_rate_limit_reduces_rps() {
        let ctrl = AdaptiveController::new(10.0);
        let initial_rps = ctrl.current_rps();
        // Use a tiny retry_after so the test doesn't block
        ctrl.process_signal(ServerSignal::RateLimited {
            retry_after: Some(Duration::from_millis(1)),
        }).await;
        assert!(ctrl.current_rps() < initial_rps, "RPS should decrease after rate limit");
    }

    #[tokio::test]
    async fn adaptive_waf_reduces_rps_more() {
        let ctrl = AdaptiveController::new(10.0);
        let initial_rps = ctrl.current_rps();
        ctrl.process_signal(ServerSignal::WafDetected { vendor: "Cloudflare".into() }).await;
        // WAF cuts by 75%, so reduction should be greater than rate-limit halving
        assert!(ctrl.current_rps() < initial_rps * 0.5, "WAF should slash RPS aggressively");
    }

    #[tokio::test]
    async fn adaptive_normal_response_increases_rps() {
        let ctrl = AdaptiveController::new(10.0);
        // First reduce RPS via rate limit
        ctrl.process_signal(ServerSignal::RateLimited {
            retry_after: Some(Duration::from_millis(1)),
        }).await;
        let reduced_rps = ctrl.current_rps();
        // Now recover
        ctrl.process_signal(ServerSignal::NormalResponse).await;
        assert!(ctrl.current_rps() >= reduced_rps, "normal response should not further reduce RPS");
    }

    #[tokio::test]
    async fn adaptive_lockout_tracked() {
        let ctrl = AdaptiveController::new(5.0);
        ctrl.process_signal(ServerSignal::AccountLocked { username: "alice".into() }).await;
        assert!(ctrl.is_locked("alice"));
        assert!(!ctrl.is_locked("bob"));
        // Duplicate signal should not double-add
        ctrl.process_signal(ServerSignal::AccountLocked { username: "alice".into() }).await;
        assert_eq!(ctrl.stats().locked_usernames.len(), 1);
    }

    #[tokio::test]
    async fn adaptive_mfa_tracked() {
        let ctrl = AdaptiveController::new(5.0);
        ctrl.process_signal(ServerSignal::MfaRequired { username: "bob".into() }).await;
        assert_eq!(ctrl.stats().mfa_events, 1);
    }

    #[tokio::test]
    async fn adaptive_stats_counters() {
        let ctrl = AdaptiveController::new(5.0);
        ctrl.process_signal(ServerSignal::CaptchaRequired).await;
        ctrl.process_signal(ServerSignal::CaptchaRequired).await;
        ctrl.process_signal(ServerSignal::WafDetected { vendor: "Akamai".into() }).await;
        let s = ctrl.stats();
        assert_eq!(s.captcha_events, 2);
        assert_eq!(s.waf_events, 1);
        assert_eq!(s.total_signals, 3);
    }

    #[tokio::test]
    async fn adaptive_clone_shares_state() {
        let ctrl = AdaptiveController::new(10.0);
        let cloned = ctrl.clone();
        ctrl.process_signal(ServerSignal::AccountLocked { username: "carol".into() }).await;
        // Clone should see the same locked state
        assert!(cloned.is_locked("carol"));
    }

    #[test]
    fn adaptive_worker_interval_from_rps() {
        let ctrl = AdaptiveController::new(10.0);
        let interval = ctrl.worker_interval();
        // 1/10 RPS = 100ms
        assert!(interval.as_millis() >= 90 && interval.as_millis() <= 110,
            "expected ~100ms interval for 10 RPS, got {}ms", interval.as_millis());
    }
}
