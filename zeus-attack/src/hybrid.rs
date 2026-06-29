//! Hybrid attack — combines a wordlist with a mask to produce candidates.
//!
//! Two modes:
//! - `WordAndMask`: for each word, append every mask permutation  → `word + mask`
//! - `MaskAndWord`: for each mask permutation, append every word  → `mask + word`
//!
//! Candidates are streamed lazily using `futures::stream::iter` + `flat_map`
//! so the full cross-product is never held in memory at once.

use crate::{AttackStrategy, CredentialStream};
use futures::StreamExt;
use zeus_core::Credential;

/// The combination order for hybrid attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HybridMode {
    /// word + mask permutation (default, most common)
    #[default]
    WordAndMask,
    /// mask permutation + word
    MaskAndWord,
}

/// Generate all strings described by a mask.
///
/// Mask charset placeholders:
/// - `?l` → lowercase alpha (a-z)
/// - `?u` → uppercase alpha (A-Z)
/// - `?d` → digit (0-9)
/// - `?s` → special chars
/// - `?a` → all printable ASCII (l + u + d + s)
/// - Any other character → literal
fn expand_mask(mask: &str) -> Vec<String> {
    let mut segments: Vec<Vec<char>> = Vec::new();
    let chars: Vec<char> = mask.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '?' && i + 1 < chars.len() {
            let charset: Vec<char> = match chars[i + 1] {
                'l' => ('a'..='z').collect(),
                'u' => ('A'..='Z').collect(),
                'd' => ('0'..='9').collect(),
                's' => "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".chars().collect(),
                'a' => {
                    let mut all: Vec<char> = ('a'..='z').collect();
                    all.extend('A'..='Z');
                    all.extend('0'..='9');
                    all.extend("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".chars());
                    all
                }
                other => vec![other],
            };
            segments.push(charset);
            i += 2;
        } else {
            segments.push(vec![chars[i]]);
            i += 1;
        }
    }

    // Cross-product of all segments.
    let mut results = vec![String::new()];
    for seg in &segments {
        let mut next = Vec::with_capacity(results.len() * seg.len());
        for existing in &results {
            for &ch in seg {
                let mut s = existing.clone();
                s.push(ch);
                next.push(s);
            }
        }
        results = next;
    }
    results
}

/// Count the number of strings a mask produces without materialising them.
pub fn mask_permutation_count(mask: &str) -> u64 {
    let chars: Vec<char> = mask.chars().collect();
    let mut count: u64 = 1;
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '?' && i + 1 < chars.len() {
            let size: u64 = match chars[i + 1] {
                'l' => 26,
                'u' => 26,
                'd' => 10,
                's' => 32,
                'a' => 95,
                _ => 1,
            };
            count = count.saturating_mul(size);
            i += 2;
        } else {
            // Literal character — multiplier is 1.
            i += 1;
        }
    }
    count
}

/// Hybrid attack strategy.
pub struct HybridStrategy {
    usernames: Vec<String>,
    wordlist: Vec<String>,
    mask: String,
    mode: HybridMode,
}

impl HybridStrategy {
    pub fn new(wordlist: Vec<String>, mask: impl Into<String>) -> Self {
        Self {
            usernames: vec!["user".to_owned()],
            wordlist,
            mask: mask.into(),
            mode: HybridMode::default(),
        }
    }

    pub fn with_mode(mut self, mode: HybridMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_usernames(mut self, usernames: Vec<String>) -> Self {
        self.usernames = usernames;
        self
    }
}

impl AttackStrategy for HybridStrategy {
    fn name(&self) -> &'static str {
        "hybrid"
    }

    fn credentials(&self) -> CredentialStream {
        // Expand the mask once; mask combos are typically small enough (e.g. ?d?d?d = 1000).
        // For very large masks the caller should reconsider approach; streaming word × mask
        // is still lazy at the word level.
        let mask_combos: Vec<String> = expand_mask(&self.mask);
        let mode = self.mode;

        // Clone everything we need to own in the stream.
        let usernames = self.usernames.clone();
        let wordlist = self.wordlist.clone();

        let stream = futures::stream::iter(usernames).flat_map(move |user| {
            let mask_combos = mask_combos.clone();
            let wordlist = wordlist.clone();
            let user = user.clone();

            futures::stream::iter(wordlist).flat_map(move |word| {
                let user = user.clone();
                let mask_combos = mask_combos.clone();
                let word = word.clone();

                futures::stream::iter(mask_combos).map(move |combo| {
                    let password = match mode {
                        HybridMode::WordAndMask => format!("{}{}", word, combo),
                        HybridMode::MaskAndWord => format!("{}{}", combo, word),
                    };
                    Credential::new(user.clone(), password)
                })
            })
        });

        Box::pin(stream)
    }

    fn estimated_count(&self) -> Option<u64> {
        let mask_perms = mask_permutation_count(&self.mask);
        let words = self.wordlist.len() as u64;
        let users = self.usernames.len().max(1) as u64;
        Some(words.saturating_mul(mask_perms).saturating_mul(users))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    fn wl(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| s.to_string()).collect()
    }

    fn collect_sync(strategy: &HybridStrategy) -> Vec<Credential> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { strategy.credentials().collect::<Vec<_>>().await })
    }

    #[test]
    fn expand_mask_digit_1() {
        let m = expand_mask("?d");
        assert_eq!(m.len(), 10);
        assert!(m.contains(&"0".to_owned()));
        assert!(m.contains(&"9".to_owned()));
    }

    #[test]
    fn expand_mask_two_digits() {
        let m = expand_mask("?d?d");
        assert_eq!(m.len(), 100);
    }

    #[test]
    fn expand_mask_literal() {
        let m = expand_mask("ab");
        assert_eq!(m, vec!["ab"]);
    }

    #[test]
    fn mask_permutation_count_digits() {
        assert_eq!(mask_permutation_count("?d"), 10);
        assert_eq!(mask_permutation_count("?d?d"), 100);
    }

    #[test]
    fn mask_permutation_count_alpha() {
        assert_eq!(mask_permutation_count("?l"), 26);
    }

    #[test]
    fn estimated_count_word_and_mask() {
        let s = HybridStrategy::new(wl(&["a", "b", "c"]), "?d");
        // 3 words * 10 digit combos * 1 user = 30
        assert_eq!(s.estimated_count(), Some(30));
    }

    #[test]
    fn estimated_count_mask_and_word() {
        let s = HybridStrategy::new(wl(&["x", "y"]), "?l").with_mode(HybridMode::MaskAndWord);
        // 2 words * 26 alpha combos * 1 user = 52
        assert_eq!(s.estimated_count(), Some(52));
    }

    #[test]
    fn word_and_mask_suffixes_mask() {
        let s = HybridStrategy::new(wl(&["pass"]), "?d");
        let creds = collect_sync(&s);
        assert_eq!(creds.len(), 10);
        assert!(creds.iter().all(|c| c.password.starts_with("pass")));
        assert!(creds.iter().any(|c| c.password == "pass7"));
    }

    #[test]
    fn mask_and_word_prefixes_mask() {
        let s = HybridStrategy::new(wl(&["word"]), "?d").with_mode(HybridMode::MaskAndWord);
        let creds = collect_sync(&s);
        assert_eq!(creds.len(), 10);
        assert!(creds.iter().all(|c| c.password.ends_with("word")));
        assert!(creds.iter().any(|c| c.password == "3word"));
    }

    #[test]
    fn multiple_users_multiplies_count() {
        let s = HybridStrategy::new(wl(&["pw"]), "?d")
            .with_usernames(vec!["admin".into(), "root".into()]);
        assert_eq!(s.estimated_count(), Some(20));
        let creds = collect_sync(&s);
        assert_eq!(creds.len(), 20);
    }

    #[test]
    fn literal_mask_produces_one_combo_per_word() {
        let s = HybridStrategy::new(wl(&["hello", "world"]), "123");
        let creds = collect_sync(&s);
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0].password, "hello123");
        assert_eq!(creds[1].password, "world123");
    }
}
