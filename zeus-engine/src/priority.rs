//! Priority queue credential ordering — Strategy + Decorator pattern.
//!
//! `PriorityStrategy` wraps any `AttackStrategy` and re-orders credentials
//! by a scoring function before yielding them. High-probability credentials
//! (short passwords, common words) are tried first.
//!
//! Trade-off: up to `buffer_size` credentials are held in memory while the
//! heap is built. This is intentional — priority ordering requires lookahead.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use futures::StreamExt;
use zeus_attack::{AttackStrategy, CredentialStream};
use zeus_core::Credential;

// ---------------------------------------------------------------------------
// Internal heap entry
// ---------------------------------------------------------------------------

struct PrioritizedCredential {
    /// Higher score → tried first (BinaryHeap is a max-heap).
    priority: i32,
    credential: Credential,
}

impl PartialEq for PrioritizedCredential {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}

impl Eq for PrioritizedCredential {}

impl Ord for PrioritizedCredential {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority.cmp(&other.priority)
    }
}

impl PartialOrd for PrioritizedCredential {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ---------------------------------------------------------------------------
// Scoring functions
// ---------------------------------------------------------------------------

/// A function that assigns a numeric priority to a credential.
/// Higher values are tried first.
pub type ScoringFn = Box<dyn Fn(&Credential) -> i32 + Send + Sync>;

// ---------------------------------------------------------------------------
// PriorityStrategy
// ---------------------------------------------------------------------------

/// Wraps an inner `AttackStrategy` and buffers up to `buffer_size` credentials,
/// sorting them by the scorer before streaming them out.
pub struct PriorityStrategy {
    inner: Box<dyn AttackStrategy>,
    scorer: ScoringFn,
    buffer_size: usize,
}

impl PriorityStrategy {
    pub fn new(inner: Box<dyn AttackStrategy>, scorer: ScoringFn, buffer_size: usize) -> Self {
        Self {
            inner,
            scorer,
            buffer_size: buffer_size.max(1),
        }
    }

    // ------------------------------------------------------------------
    // Pre-built scorers
    // ------------------------------------------------------------------

    /// Shorter passwords score higher (negative length → bigger = shorter).
    pub fn short_first_scorer() -> ScoringFn {
        Box::new(|cred: &Credential| -(cred.password.len() as i32))
    }

    /// Common passwords get a large bonus score.
    pub fn common_first_scorer() -> ScoringFn {
        const COMMON: &[&str] = &[
            "password", "123456", "admin", "root", "test", "qwerty", "letmein", "welcome",
        ];
        Box::new(|cred: &Credential| {
            if COMMON.contains(&cred.password.as_str()) {
                1000
            } else {
                0
            }
        })
    }

    /// Composite scorer: sum the results of multiple scorers.
    pub fn composite(scorers: Vec<ScoringFn>) -> ScoringFn {
        Box::new(move |cred: &Credential| scorers.iter().map(|s| s(cred)).sum())
    }

    /// Async method that collects up to `buffer_size` credentials from the inner
    /// strategy, sorts them, and returns a prioritised stream.
    pub async fn sorted_credentials(&self) -> CredentialStream {
        let mut heap = BinaryHeap::new();
        let mut stream = self.inner.credentials();
        let mut count = 0usize;

        while let Some(cred) = stream.next().await {
            if count >= self.buffer_size {
                break;
            }
            let priority = (self.scorer)(&cred);
            heap.push(PrioritizedCredential {
                priority,
                credential: cred,
            });
            count += 1;
        }

        // `into_sorted_vec` returns ascending order; reverse so highest priority comes first.
        let sorted: Vec<Credential> = heap
            .into_sorted_vec()
            .into_iter()
            .rev()
            .map(|p| p.credential)
            .collect();

        Box::pin(tokio_stream::iter(sorted))
    }
}

impl AttackStrategy for PriorityStrategy {
    fn name(&self) -> &'static str {
        "priority"
    }

    fn credentials(&self) -> CredentialStream {
        // Block the current thread to collect and sort credentials.
        // This is an explicit trade-off: PriorityStrategy requires lookahead.
        // Callers that want async can use `sorted_credentials()` directly.
        futures::executor::block_on(self.sorted_credentials())
    }

    fn estimated_count(&self) -> Option<u64> {
        self.inner.estimated_count()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::iter as stream_iter;
    use zeus_attack::{AttackStrategy, CredentialStream};
    use zeus_core::Credential;

    struct StaticStrategy {
        creds: Vec<Credential>,
    }

    impl StaticStrategy {
        fn new(creds: Vec<Credential>) -> Self {
            Self { creds }
        }
    }

    impl AttackStrategy for StaticStrategy {
        fn name(&self) -> &'static str {
            "static"
        }
        fn credentials(&self) -> CredentialStream {
            Box::pin(stream_iter(self.creds.clone()))
        }
        fn estimated_count(&self) -> Option<u64> {
            Some(self.creds.len() as u64)
        }
    }

    fn cred(u: &str, p: &str) -> Credential {
        Credential::new(u, p)
    }

    #[test]
    fn priority_short_first_scorer() {
        let scorer = PriorityStrategy::short_first_scorer();
        let short = cred("u", "ab");
        let long = cred("u", "abcdefgh");
        // Short password should score higher (less negative).
        assert!(scorer(&short) > scorer(&long));
    }

    #[test]
    fn priority_common_first_scorer() {
        let scorer = PriorityStrategy::common_first_scorer();
        let common = cred("u", "password");
        let rare = cred("u", "x9z!q");
        assert_eq!(scorer(&common), 1000);
        assert_eq!(scorer(&rare), 0);
    }

    #[test]
    fn prioritized_cred_ordering() {
        let a = PrioritizedCredential {
            priority: 10,
            credential: cred("u", "a"),
        };
        let b = PrioritizedCredential {
            priority: 5,
            credential: cred("u", "b"),
        };
        let c = PrioritizedCredential {
            priority: 20,
            credential: cred("u", "c"),
        };

        let mut heap = BinaryHeap::new();
        heap.push(a);
        heap.push(b);
        heap.push(c);

        // Max-heap: highest priority should pop first.
        assert_eq!(heap.pop().unwrap().priority, 20);
        assert_eq!(heap.pop().unwrap().priority, 10);
        assert_eq!(heap.pop().unwrap().priority, 5);
    }

    #[test]
    fn composite_scorer_sums() {
        let scorer = PriorityStrategy::composite(vec![
            PriorityStrategy::short_first_scorer(),
            PriorityStrategy::common_first_scorer(),
        ]);
        // "password" is 8 chars (-8) + 1000 bonus = 992.
        let c = cred("u", "password");
        assert_eq!(scorer(&c), 992);
    }

    #[tokio::test]
    async fn priority_strategy_orders_by_score() {
        let creds = vec![
            cred("u", "averylongpassword"), // low priority
            cred("u", "password"),          // common → high priority
            cred("u", "ab"),                // short → medium
        ];

        let inner = Box::new(StaticStrategy::new(creds));
        let scorer = PriorityStrategy::composite(vec![
            PriorityStrategy::short_first_scorer(),
            PriorityStrategy::common_first_scorer(),
        ]);

        let strategy = PriorityStrategy::new(inner, scorer, 100);
        let mut stream = strategy.sorted_credentials().await;

        use futures::StreamExt;
        let first = stream.next().await.unwrap();
        // "password" has score 992 — should be first.
        assert_eq!(first.password, "password");
    }
}
