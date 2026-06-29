use crate::{AttackStrategy, CredentialStream};
use tokio_stream::iter;
use zeus_core::Credential;

/// Combinator attack — Hashcat mode 1 equivalent.
///
/// Concatenates every word from `list1` with every word from `list2`,
/// optionally separated by a configurable separator string.
/// Total candidates = list1.len() × list2.len().
pub struct CombinatorStrategy {
    username: String,
    list1: Vec<String>,
    list2: Vec<String>,
    separator: String,
}

impl CombinatorStrategy {
    pub fn new(username: impl Into<String>, list1: Vec<String>, list2: Vec<String>) -> Self {
        Self {
            username: username.into(),
            list1,
            list2,
            separator: String::new(),
        }
    }

    pub fn with_separator(mut self, sep: impl Into<String>) -> Self {
        self.separator = sep.into();
        self
    }

    /// Total combos = list1.len() × list2.len()
    fn total(&self) -> u64 {
        (self.list1.len() as u64).saturating_mul(self.list2.len() as u64)
    }
}

impl AttackStrategy for CombinatorStrategy {
    fn name(&self) -> &'static str {
        "combinator"
    }

    fn credentials(&self) -> CredentialStream {
        let username = self.username.clone();
        let sep = self.separator.clone();
        let list1 = self.list1.clone();
        let list2 = self.list2.clone();

        let creds: Vec<Credential> = list1
            .iter()
            .flat_map(|w1| {
                let w1 = w1.clone();
                let sep = sep.clone();
                let username = username.clone();
                list2.iter().map(move |w2| {
                    Credential::new(username.clone(), format!("{}{}{}", w1, sep, w2))
                })
            })
            .collect();

        Box::pin(iter(creds))
    }

    fn estimated_count(&self) -> Option<u64> {
        Some(self.total())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    fn collect_sync(s: &CombinatorStrategy) -> Vec<Credential> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { s.credentials().collect::<Vec<_>>().await })
    }

    fn words(ws: &[&str]) -> Vec<String> {
        ws.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn combinator_count() {
        let s = CombinatorStrategy::new("user", words(&["a", "b", "c"]), words(&["x", "y", "z"]));
        assert_eq!(s.estimated_count(), Some(9));
        assert_eq!(collect_sync(&s).len(), 9);
    }

    #[test]
    fn combinator_separator() {
        let s =
            CombinatorStrategy::new("user", words(&["pass"]), words(&["word"])).with_separator("_");
        let creds = collect_sync(&s);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].password, "pass_word");
    }

    #[test]
    fn combinator_empty_list1() {
        let s = CombinatorStrategy::new("user", words(&[]), words(&["x", "y"]));
        assert_eq!(s.estimated_count(), Some(0));
        assert_eq!(collect_sync(&s).len(), 0);
    }

    #[test]
    fn combinator_single_elements() {
        let s = CombinatorStrategy::new("user", words(&["only"]), words(&["one"]));
        assert_eq!(s.estimated_count(), Some(1));
        let creds = collect_sync(&s);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].password, "onlyone");
    }

    #[test]
    fn combinator_no_separator() {
        let s = CombinatorStrategy::new("user", words(&["ab"]), words(&["cd"]));
        let creds = collect_sync(&s);
        assert_eq!(creds[0].password, "abcd");
    }
}
