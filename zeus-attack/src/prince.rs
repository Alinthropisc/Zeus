use crate::{AttackStrategy, CredentialStream};
use tokio_stream::iter;
use zeus_core::Credential;

/// PRINCE (PRobability INfinite Chained Elements) attack strategy.
///
/// Generates password candidates by chaining 1..=`max_chains` elements from
/// a wordlist.  Candidates are filtered to those whose total length falls
/// within `[min_len, max_len]` and optionally capped at `limit`.
pub struct PrinceStrategy {
    username: String,
    elements: Vec<String>,
    min_len: usize,
    max_len: usize,
    max_chains: usize,
    limit: Option<u64>,
}

impl PrinceStrategy {
    pub fn new(
        username: impl Into<String>,
        elements: Vec<String>,
        max_chains: usize,
    ) -> Self {
        Self {
            username: username.into(),
            elements,
            min_len: 0,
            max_len: usize::MAX,
            max_chains: max_chains.max(1),
            limit: None,
        }
    }

    pub fn with_len_bounds(mut self, min: usize, max: usize) -> Self {
        self.min_len = min;
        self.max_len = max;
        self
    }

    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }
}

impl AttackStrategy for PrinceStrategy {
    fn name(&self) -> &'static str { "prince" }

    fn credentials(&self) -> CredentialStream {
        let username = self.username.clone();
        let elements = self.elements.clone();
        let max_chains = self.max_chains;
        let min_len = self.min_len;
        let max_len = self.max_len;
        let limit = self.limit;

        let mut creds: Vec<Credential> = Vec::new();

        let accept = |s: &str| s.len() >= min_len && s.len() <= max_len;
        let at_limit = |c: &Vec<Credential>| limit.map_or(false, |l| c.len() as u64 >= l);

        // Chain 1: single elements
        for e in &elements {
            if accept(e) {
                creds.push(Credential::new(username.clone(), e.clone()));
            }
            if at_limit(&creds) { break; }
        }

        // Chain 2: pairs
        if max_chains >= 2 && !at_limit(&creds) {
            'outer2: for e1 in &elements {
                for e2 in &elements {
                    let combined = format!("{}{}", e1, e2);
                    if accept(&combined) {
                        creds.push(Credential::new(username.clone(), combined));
                    }
                    if at_limit(&creds) { break 'outer2; }
                }
            }
        }

        // Chain 3: triples
        if max_chains >= 3 && !at_limit(&creds) {
            'outer3: for e1 in &elements {
                for e2 in &elements {
                    for e3 in &elements {
                        let combined = format!("{}{}{}", e1, e2, e3);
                        if accept(&combined) {
                            creds.push(Credential::new(username.clone(), combined));
                        }
                        if at_limit(&creds) { break 'outer3; }
                    }
                }
            }
        }

        if let Some(lim) = limit {
            creds.truncate(lim as usize);
        }

        Box::pin(iter(creds))
    }

    fn estimated_count(&self) -> Option<u64> {
        let n = self.elements.len() as u64;
        let mut total = n;
        if self.max_chains >= 2 { total = total.saturating_add(n.saturating_mul(n)); }
        if self.max_chains >= 3 { total = total.saturating_add(n.saturating_mul(n).saturating_mul(n)); }
        Some(if let Some(lim) = self.limit { total.min(lim) } else { total })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    fn words(ws: &[&str]) -> Vec<String> {
        ws.iter().map(|s| s.to_string()).collect()
    }

    fn collect_sync(s: &PrinceStrategy) -> Vec<Credential> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { s.credentials().collect::<Vec<_>>().await })
    }

    #[test]
    fn prince_single_chain() {
        let s = PrinceStrategy::new("u", words(&["cat", "dog", "fox"]), 1);
        let creds = collect_sync(&s);
        assert_eq!(creds.len(), 3);
        assert!(creds.iter().all(|c| ["cat", "dog", "fox"].contains(&c.password.as_str())));
    }

    #[test]
    fn prince_double_chain() {
        let s = PrinceStrategy::new("u", words(&["a", "b"]), 2);
        let creds = collect_sync(&s);
        // 2 singles + 4 pairs = 6
        assert_eq!(creds.len(), 6);
        assert!(creds.iter().any(|c| c.password == "ab"));
        assert!(creds.iter().any(|c| c.password == "ba"));
        assert!(creds.iter().any(|c| c.password == "aa"));
        assert!(creds.iter().any(|c| c.password == "bb"));
    }

    #[test]
    fn prince_len_filter() {
        // Only words of length exactly 3 should pass with bounds [3,3]
        let s = PrinceStrategy::new("u", words(&["hi", "hey", "hello"]), 1)
            .with_len_bounds(3, 3);
        let creds = collect_sync(&s);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].password, "hey");
    }

    #[test]
    fn prince_limit() {
        let s = PrinceStrategy::new("u", words(&["a", "b", "c", "d"]), 2)
            .with_limit(3);
        let creds = collect_sync(&s);
        assert_eq!(creds.len(), 3);
    }

    #[test]
    fn prince_estimated_count_chain1() {
        let s = PrinceStrategy::new("u", words(&["x", "y", "z"]), 1);
        assert_eq!(s.estimated_count(), Some(3));
    }

    #[test]
    fn prince_estimated_count_chain2() {
        let s = PrinceStrategy::new("u", words(&["a", "b"]), 2);
        // 2 + 4 = 6
        assert_eq!(s.estimated_count(), Some(6));
    }

    #[test]
    fn prince_no_duplicates_in_small_set() {
        let s = PrinceStrategy::new("u", words(&["x", "y"]), 2);
        let creds = collect_sync(&s);
        // 2 singles + 4 pairs = 6 total, all distinct passwords
        let mut passwords: Vec<_> = creds.iter().map(|c| c.password.as_str()).collect();
        passwords.sort_unstable();
        passwords.dedup();
        assert_eq!(passwords.len(), 6);
    }

    #[test]
    fn prince_limit_via_estimated_count() {
        let s = PrinceStrategy::new("u", words(&["a", "b", "c"]), 2)
            .with_limit(5);
        assert_eq!(s.estimated_count(), Some(5));
    }
}
