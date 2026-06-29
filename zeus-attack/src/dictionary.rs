use crate::{AttackStrategy, CredentialStream, Wordlist};
use tokio_stream::iter;
use zeus_core::Credential;

/// Dictionary attack — try a fixed wordlist of passwords for one or more usernames.
pub struct DictionaryStrategy {
    usernames: Vec<String>,
    wordlist: Wordlist,
}

impl DictionaryStrategy {
    pub fn new(usernames: Vec<String>, wordlist: Wordlist) -> Self {
        Self { usernames, wordlist }
    }

    pub fn credential_pairs(wordlist: Wordlist) -> Self {
        Self { usernames: vec![], wordlist }
    }
}

impl AttackStrategy for DictionaryStrategy {
    fn name(&self) -> &'static str { "dictionary" }

    fn credentials(&self) -> CredentialStream {
        if self.usernames.is_empty() {
            let creds: Vec<Credential> = self.wordlist.credential_pairs().collect();
            Box::pin(iter(creds))
        } else {
            let mut creds = Vec::new();
            for user in &self.usernames {
                creds.extend(self.wordlist.credentials(user));
            }
            Box::pin(iter(creds))
        }
    }

    fn estimated_count(&self) -> Option<u64> {
        let factor = if self.usernames.is_empty() { 1 } else { self.usernames.len() };
        Some((self.wordlist.len() * factor) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wl(entries: &[&str]) -> Wordlist {
        Wordlist::from_vec(entries.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn estimated_count_with_users() {
        let s = DictionaryStrategy::new(vec!["admin".into(), "root".into()], wl(&["a", "b", "c"]));
        assert_eq!(s.estimated_count(), Some(6));
    }

    #[test]
    fn estimated_count_pair_mode() {
        let s = DictionaryStrategy::credential_pairs(wl(&["admin:pass", "root:toor"]));
        assert_eq!(s.estimated_count(), Some(2));
    }

    #[test]
    fn name() {
        let s = DictionaryStrategy::new(vec!["u".into()], wl(&["p"]));
        assert_eq!(s.name(), "dictionary");
    }
}
