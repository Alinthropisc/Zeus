use crate::{AttackStrategy, CredentialStream};
use futures::StreamExt;
use std::collections::HashSet;

/// Decorator — wraps any `AttackStrategy` and filters out duplicate passwords.
///
/// Deduplication key is `"username\x00password"` so identical passwords for
/// different usernames are each kept (only exact credential pairs are deduped).
/// The first occurrence of each credential wins; order is preserved.
pub struct DeduplicateStrategy {
    inner: Box<dyn AttackStrategy>,
}

impl DeduplicateStrategy {
    pub fn new(inner: Box<dyn AttackStrategy>) -> Self {
        Self { inner }
    }

    /// Convenience: wrap and return as a boxed trait object.
    pub fn wrap(inner: Box<dyn AttackStrategy>) -> Box<dyn AttackStrategy> {
        Box::new(Self::new(inner))
    }
}

impl AttackStrategy for DeduplicateStrategy {
    fn name(&self) -> &'static str {
        "dedup"
    }

    fn credentials(&self) -> CredentialStream {
        let mut seen: HashSet<String> = HashSet::new();
        let stream = self.inner.credentials();

        let filtered = stream.filter(move |cred| {
            let key = format!("{}\x00{}", cred.username, cred.password);
            let is_new = seen.insert(key);
            futures::future::ready(is_new)
        });

        Box::pin(filtered)
    }

    fn estimated_count(&self) -> Option<u64> {
        // Cannot know without materialising the stream.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttackStrategy, CredentialStream};
    use futures::StreamExt;
    use tokio_stream::iter;
    use zeus_core::Credential;

    /// Minimal stub strategy backed by a fixed credential list.
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

    fn cred(user: &str, pass: &str) -> Credential {
        Credential::new(user.to_string(), pass.to_string())
    }

    fn collect_sync(s: &dyn AttackStrategy) -> Vec<Credential> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { s.credentials().collect::<Vec<_>>().await })
    }

    #[test]
    fn dedup_removes_duplicates() {
        let inner = Box::new(FixedStrategy(vec![
            cred("u", "pass1"),
            cred("u", "pass2"),
            cred("u", "pass1"),
            cred("u", "pass3"),
            cred("u", "pass2"),
        ]));
        let s = DeduplicateStrategy::new(inner);
        let creds = collect_sync(&s);
        assert_eq!(creds.len(), 3);
        assert_eq!(creds[0].password, "pass1");
        assert_eq!(creds[1].password, "pass2");
        assert_eq!(creds[2].password, "pass3");
    }

    #[test]
    fn dedup_preserves_order() {
        let inner = Box::new(FixedStrategy(vec![
            cred("u", "z"),
            cred("u", "a"),
            cred("u", "m"),
            cred("u", "z"),
            cred("u", "a"),
        ]));
        let s = DeduplicateStrategy::new(inner);
        let creds = collect_sync(&s);
        assert_eq!(
            creds
                .iter()
                .map(|c| c.password.as_str())
                .collect::<Vec<_>>(),
            vec!["z", "a", "m"]
        );
    }

    #[test]
    fn dedup_different_usernames_not_deduped() {
        let inner = Box::new(FixedStrategy(vec![
            cred("alice", "pass"),
            cred("bob", "pass"),
        ]));
        let s = DeduplicateStrategy::new(inner);
        let creds = collect_sync(&s);
        assert_eq!(creds.len(), 2);
    }

    #[test]
    fn dedup_empty_stream() {
        let inner = Box::new(FixedStrategy(vec![]));
        let s = DeduplicateStrategy::new(inner);
        let creds = collect_sync(&s);
        assert!(creds.is_empty());
    }

    #[test]
    fn dedup_estimated_count_is_none() {
        let inner = Box::new(FixedStrategy(vec![cred("u", "p")]));
        let s = DeduplicateStrategy::new(inner);
        assert_eq!(s.estimated_count(), None);
    }
}
