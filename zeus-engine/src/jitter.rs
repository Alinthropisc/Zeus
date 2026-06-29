use std::time::Duration;

/// Jitter strategy for inter-request delays
#[derive(Debug, Clone)]
pub enum JitterMode {
    /// No jitter — constant rate
    None,
    /// Uniform random jitter: delay in [base - range, base + range]
    Uniform { base_ms: u64, range_ms: u64 },
    /// Gaussian-like jitter using Box-Muller approximation
    Gaussian { mean_ms: u64, std_ms: u64 },
    /// Human-like: short bursts then longer pauses
    Human { fast_ms: u64, slow_ms: u64, fast_ratio: f64 },
    /// Fixed delay (no randomness, but configurable)
    Fixed(u64),
}

/// Simple LCG PRNG (no external dep)
struct Lcg { state: u64 }
impl Lcg {
    fn new() -> Self {
        // Seed from system time
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now().duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64).unwrap_or(12345);
        Self { state: seed }
    }

    fn with_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_f64(&mut self) -> f64 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.state >> 11) as f64 / (1u64 << 53) as f64
    }

    fn next_u64_range(&mut self, min: u64, max: u64) -> u64 {
        if min >= max { return min; }
        min + (self.next_f64() * (max - min) as f64) as u64
    }
}

pub struct JitterTimer {
    mode: JitterMode,
    rng: Lcg,
}

impl JitterTimer {
    pub fn new(mode: JitterMode) -> Self {
        Self { mode, rng: Lcg::new() }
    }

    pub fn none() -> Self { Self::new(JitterMode::None) }
    pub fn uniform(base_ms: u64, range_ms: u64) -> Self { Self::new(JitterMode::Uniform { base_ms, range_ms }) }
    pub fn human() -> Self { Self::new(JitterMode::Human { fast_ms: 100, slow_ms: 2000, fast_ratio: 0.8 }) }

    /// Compute next delay
    pub fn next_delay(&mut self) -> Duration {
        let ms = match &self.mode {
            JitterMode::None => 0,
            JitterMode::Fixed(ms) => *ms,
            JitterMode::Uniform { base_ms, range_ms } => {
                let low = base_ms.saturating_sub(*range_ms);
                let high = base_ms + range_ms;
                self.rng.next_u64_range(low, high)
            }
            JitterMode::Gaussian { mean_ms, std_ms } => {
                // Box-Muller approximation
                let u1 = self.rng.next_f64();
                let u2 = self.rng.next_f64();
                let z = ((-2.0 * u1.ln()).sqrt()) * (2.0 * std::f64::consts::PI * u2).cos();
                let val = *mean_ms as f64 + *std_ms as f64 * z;
                val.max(0.0) as u64
            }
            JitterMode::Human { fast_ms, slow_ms, fast_ratio } => {
                if self.rng.next_f64() < *fast_ratio {
                    self.rng.next_u64_range(10, *fast_ms)
                } else {
                    self.rng.next_u64_range(*fast_ms, *slow_ms)
                }
            }
        };
        Duration::from_millis(ms)
    }

    /// Apply jitter — async sleep
    pub async fn sleep(&mut self) {
        let delay = self.next_delay();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_none_returns_zero() {
        let mut t = JitterTimer::none();
        for _ in 0..10 {
            assert_eq!(t.next_delay(), Duration::ZERO);
        }
    }

    #[test]
    fn jitter_fixed_constant() {
        let mut t = JitterTimer::new(JitterMode::Fixed(250));
        for _ in 0..10 {
            assert_eq!(t.next_delay(), Duration::from_millis(250));
        }
    }

    #[test]
    fn jitter_uniform_in_range() {
        let base_ms = 100u64;
        let range_ms = 50u64;
        let mut t = JitterTimer::uniform(base_ms, range_ms);
        for _ in 0..100 {
            let d = t.next_delay();
            let ms = d.as_millis() as u64;
            let low = base_ms.saturating_sub(range_ms);
            let high = base_ms + range_ms;
            assert!(
                ms >= low && ms <= high,
                "delay {}ms out of range [{}, {}]", ms, low, high
            );
        }
    }

    #[test]
    fn jitter_human_mostly_fast() {
        let fast_ms = 100u64;
        let mut t = JitterTimer::human();
        let mut fast_count = 0usize;
        let total = 1000;
        for _ in 0..total {
            let ms = t.next_delay().as_millis() as u64;
            if ms < fast_ms {
                fast_count += 1;
            }
        }
        let ratio = fast_count as f64 / total as f64;
        assert!(ratio > 0.60, "expected >60% fast delays, got {:.1}%", ratio * 100.0);
    }

    #[test]
    fn jitter_gaussian_non_negative() {
        let mut t = JitterTimer::new(JitterMode::Gaussian { mean_ms: 100, std_ms: 30 });
        for _ in 0..200 {
            let ms = t.next_delay().as_millis();
            assert!(ms < u128::MAX, "delay should be non-negative");
            // Duration is always >= 0, this just ensures no panics
        }
    }

    #[test]
    fn lcg_produces_values_0_to_1() {
        let mut rng = Lcg::with_seed(42);
        for _ in 0..1000 {
            let v = rng.next_f64();
            assert!(v >= 0.0 && v < 1.0, "LCG value {} out of [0,1)", v);
        }
    }
}
