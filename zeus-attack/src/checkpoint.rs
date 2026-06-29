use crate::{AttackStrategy, CredentialStream};
use futures::StreamExt;

/// Decorator — wraps any `AttackStrategy` and skips the first N credentials.
///
/// Useful for resuming a previously interrupted attack: record how many
/// credentials were attempted, then construct with `resume_from` to continue
/// from where the session left off.
pub struct CheckpointStrategy {
    inner: Box<dyn AttackStrategy>,
    skip_first: u64,
}

impl CheckpointStrategy {
    /// Create a checkpoint strategy that passes all credentials through.
    pub fn new(inner: Box<dyn AttackStrategy>) -> Self {
        Self {
            inner,
            skip_first: 0,
        }
    }

    /// Resume from a checkpoint — skip the first `attempts_done` credentials.
    pub fn resume_from(inner: Box<dyn AttackStrategy>, attempts_done: u64) -> Self {
        Self {
            inner,
            skip_first: attempts_done,
        }
    }

    pub fn skip_count(&self) -> u64 {
        self.skip_first
    }
}

impl AttackStrategy for CheckpointStrategy {
    fn name(&self) -> &'static str {
        "checkpoint"
    }

    fn credentials(&self) -> CredentialStream {
        let skip = self.skip_first;
        let stream = self.inner.credentials();
        Box::pin(stream.skip(skip as usize))
    }

    fn estimated_count(&self) -> Option<u64> {
        self.inner
            .estimated_count()
            .map(|n| n.saturating_sub(self.skip_first))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttackStrategy, CredentialStream};
    use futures::StreamExt;
    use tokio_stream::iter;
    use zeus_core::Credential;

    struct FixedStrategy(Vec<Credential>);

    impl AttackStrategy for FixedStrategy {
        fn name(&self) -> &'static str {
            "fixed"
        }
        fn credentials(&self) -> CredentialStream {
            Box::pin(iter(self.0.clone()))
        }
        fn estimated_count(&self) -> Option<u64> {
            Some(self.0.len() as u64)
        }
    }

    fn creds_n(n: usize) -> Vec<Credential> {
        (0..n)
            .map(|i| Credential::new("u".to_string(), format!("pass{}", i)))
            .collect()
    }

    fn collect_sync(s: &dyn AttackStrategy) -> Vec<Credential> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { s.credentials().collect::<Vec<_>>().await })
    }

    #[test]
    fn checkpoint_skip_zero() {
        let inner = Box::new(FixedStrategy(creds_n(5)));
        let s = CheckpointStrategy::new(inner);
        assert_eq!(s.skip_count(), 0);
        assert_eq!(collect_sync(&s).len(), 5);
    }

    #[test]
    fn checkpoint_skip_n() {
        let inner = Box::new(FixedStrategy(creds_n(10)));
        let s = CheckpointStrategy::resume_from(inner, 3);
        let creds = collect_sync(&s);
        assert_eq!(creds.len(), 7);
        assert_eq!(creds[0].password, "pass3");
    }

    #[test]
    fn checkpoint_skip_all() {
        let inner = Box::new(FixedStrategy(creds_n(5)));
        let s = CheckpointStrategy::resume_from(inner, 5);
        assert!(collect_sync(&s).is_empty());
    }

    #[test]
    fn checkpoint_skip_more_than_total() {
        let inner = Box::new(FixedStrategy(creds_n(5)));
        let s = CheckpointStrategy::resume_from(inner, 100);
        assert!(collect_sync(&s).is_empty());
    }

    #[test]
    fn checkpoint_estimated_count_reduced() {
        let inner = Box::new(FixedStrategy(creds_n(10)));
        let s = CheckpointStrategy::resume_from(inner, 4);
        assert_eq!(s.estimated_count(), Some(6));
    }

    #[test]
    fn checkpoint_estimated_count_saturates_at_zero() {
        let inner = Box::new(FixedStrategy(creds_n(5)));
        let s = CheckpointStrategy::resume_from(inner, 100);
        assert_eq!(s.estimated_count(), Some(0));
    }

    #[test]
    fn resume_from_constructor() {
        let inner = Box::new(FixedStrategy(creds_n(6)));
        let s = CheckpointStrategy::resume_from(inner, 2);
        assert_eq!(s.skip_count(), 2);
        assert_eq!(collect_sync(&s).len(), 4);
    }
}
