use crate::{AttackStrategy, CredentialStream};
use futures::StreamExt;
use tokio_stream::iter;
use zeus_core::Credential;

/// Generates all strings of lengths [min_len..=max_len] over `charset`,
/// optionally wrapped with a fixed prefix and suffix.
pub struct PermutationStrategy {
    charset: Vec<char>,
    min_len: usize,
    max_len: usize,
    prefix: String,
    suffix: String,
    username: String,
}

impl PermutationStrategy {
    pub fn new(charset: impl Into<String>, min_len: usize, max_len: usize) -> Self {
        Self {
            charset: charset.into().chars().collect(),
            min_len,
            max_len,
            prefix: String::new(),
            suffix: String::new(),
            username: "user".to_owned(),
        }
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    pub fn with_suffix(mut self, suffix: impl Into<String>) -> Self {
        self.suffix = suffix.into();
        self
    }

    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }

    pub fn digits(min_len: usize, max_len: usize) -> Self {
        Self::new("0123456789", min_len, max_len)
    }

    pub fn alpha(min_len: usize, max_len: usize) -> Self {
        Self::new("abcdefghijklmnopqrstuvwxyz", min_len, max_len)
    }

    pub fn alphanumeric(min_len: usize, max_len: usize) -> Self {
        Self::new("abcdefghijklmnopqrstuvwxyz0123456789", min_len, max_len)
    }

    fn generate_all(&self) -> Vec<Credential> {
        let mut out = Vec::new();
        for len in self.min_len..=self.max_len {
            self.recurse(len, &mut String::new(), &mut out);
        }
        out
    }

    fn recurse(&self, remaining: usize, current: &mut String, out: &mut Vec<Credential>) {
        if remaining == 0 {
            let password = format!("{}{}{}", self.prefix, current, self.suffix);
            out.push(Credential::new(self.username.clone(), password));
            return;
        }
        for &ch in &self.charset {
            current.push(ch);
            self.recurse(remaining - 1, current, out);
            current.pop();
        }
    }
}

impl AttackStrategy for PermutationStrategy {
    fn name(&self) -> &'static str {
        "permutation"
    }

    fn credentials(&self) -> CredentialStream {
        Box::pin(iter(self.generate_all()))
    }

    fn estimated_count(&self) -> Option<u64> {
        let base = self.charset.len() as u64;
        if base == 0 {
            return Some(0);
        }
        let total: u64 = (self.min_len..=self.max_len)
            .map(|l| base.pow(l as u32))
            .sum();
        Some(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_2_2_has_100_items() {
        let s = PermutationStrategy::digits(2, 2);
        assert_eq!(s.estimated_count(), Some(100));
        let creds = s.generate_all();
        assert_eq!(creds.len(), 100);
    }

    #[test]
    fn estimated_count_matches_actual() {
        let s = PermutationStrategy::new("ab", 1, 3);
        let expected = s.estimated_count().unwrap();
        let actual = s.generate_all().len() as u64;
        assert_eq!(expected, actual);
    }

    #[test]
    fn with_prefix_prepends() {
        let s = PermutationStrategy::digits(1, 1).with_prefix("admin");
        let creds = s.generate_all();
        assert_eq!(creds.len(), 10);
        assert!(creds.iter().all(|c| c.password.starts_with("admin")));
        assert!(creds.iter().any(|c| c.password == "admin5"));
    }

    #[test]
    fn with_suffix_appends() {
        let s = PermutationStrategy::new("ab", 1, 1).with_suffix("!");
        let creds = s.generate_all();
        assert_eq!(creds.len(), 2);
        assert!(creds.iter().all(|c| c.password.ends_with('!')));
    }

    #[test]
    fn alpha_min_1_max_1_has_26() {
        let s = PermutationStrategy::alpha(1, 1);
        assert_eq!(s.estimated_count(), Some(26));
    }

    #[test]
    fn empty_charset_returns_zero() {
        let s = PermutationStrategy::new("", 1, 3);
        assert_eq!(s.estimated_count(), Some(0));
    }
}

// ─── Leetspeak / word-variation strategy ──────────────────────────────────────

const LEET_TABLE: &[(char, &[char])] = &[
    ('a', &['4', '@']),
    ('e', &['3']),
    ('i', &['1', '!']),
    ('o', &['0']),
    ('s', &['5', '$']),
    ('t', &['7']),
];

fn leet_substitutions(word: &str) -> Vec<String> {
    // For each character position we build a set of possible replacements
    // (always including the original).  We then cross-product them.
    let chars: Vec<char> = word.chars().collect();
    let mut positions: Vec<Vec<char>> = Vec::with_capacity(chars.len());

    for &ch in &chars {
        let lower = ch.to_lowercase().next().unwrap_or(ch);
        let mut options = vec![ch]; // always include original
        for &(src, replacements) in LEET_TABLE {
            if lower == src {
                for &rep in replacements {
                    if !options.contains(&rep) {
                        options.push(rep);
                    }
                }
            }
        }
        positions.push(options);
    }

    // Cross-product.
    let mut results = vec![String::new()];
    for opts in &positions {
        let mut next = Vec::with_capacity(results.len() * opts.len());
        for existing in &results {
            for &ch in opts {
                let mut s = existing.clone();
                s.push(ch);
                next.push(s);
            }
        }
        results = next;
    }
    results
}

/// Generates leet-speak / common-substitution variants for a list of words.
///
/// For each input word every combination of the substitutions is emitted,
/// including the original word itself.  Streaming is lazy at the word level.
pub struct LeetStrategy {
    username: String,
    words: Vec<String>,
}

impl LeetStrategy {
    pub fn new(username: impl Into<String>, words: Vec<String>) -> Self {
        Self {
            username: username.into(),
            words,
        }
    }
}

impl AttackStrategy for LeetStrategy {
    fn name(&self) -> &'static str {
        "leet"
    }

    fn credentials(&self) -> CredentialStream {
        let username = self.username.clone();
        let words = self.words.clone();

        let stream = futures::stream::iter(words).flat_map(move |word| {
            let variants = leet_substitutions(&word);
            let user = username.clone();
            futures::stream::iter(variants).map(move |pw| Credential::new(user.clone(), pw))
        });

        Box::pin(stream)
    }

    fn estimated_count(&self) -> Option<u64> {
        // Upper bound: product of options per char, summed over all words.
        let total: u64 = self
            .words
            .iter()
            .map(|word| {
                let chars: Vec<char> = word.chars().collect();
                let mut product: u64 = 1;
                for &ch in &chars {
                    let lower = ch.to_lowercase().next().unwrap_or(ch);
                    let count = LEET_TABLE
                        .iter()
                        .find(|&&(src, _)| src == lower)
                        .map(|&(_, replacements)| (replacements.len() + 1) as u64)
                        .unwrap_or(1);
                    product = product.saturating_mul(count);
                }
                product
            })
            .sum();
        Some(total)
    }
}

#[cfg(test)]
mod leet_tests {
    use super::*;

    fn collect_sync(strategy: &LeetStrategy) -> Vec<Credential> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { strategy.credentials().collect::<Vec<_>>().await })
    }

    #[test]
    fn leet_includes_original() {
        let variants = leet_substitutions("abc");
        assert!(
            variants.contains(&"abc".to_owned()),
            "original must be included"
        );
    }

    #[test]
    fn leet_substitutes_a() {
        let variants = leet_substitutions("a");
        assert!(variants.contains(&"4".to_owned()));
        assert!(variants.contains(&"@".to_owned()));
        assert!(variants.contains(&"a".to_owned()));
        assert_eq!(variants.len(), 3);
    }

    #[test]
    fn leet_substitutes_e() {
        let variants = leet_substitutions("e");
        assert!(variants.contains(&"3".to_owned()));
        assert_eq!(variants.len(), 2); // e and 3
    }

    #[test]
    fn leet_substitutes_i() {
        let v = leet_substitutions("i");
        assert!(v.contains(&"1".to_owned()));
        assert!(v.contains(&"!".to_owned()));
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn leet_substitutes_o() {
        let v = leet_substitutions("o");
        assert!(v.contains(&"0".to_owned()));
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn leet_substitutes_s() {
        let v = leet_substitutions("s");
        assert!(v.contains(&"5".to_owned()));
        assert!(v.contains(&"$".to_owned()));
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn leet_substitutes_t() {
        let v = leet_substitutions("t");
        assert!(v.contains(&"7".to_owned()));
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn leet_no_substitution_for_unaffected_chars() {
        let v = leet_substitutions("z");
        assert_eq!(v, vec!["z"]);
    }

    #[test]
    fn leet_word_password() {
        // p-a-s-s-w-o-r-d: a→3, s→2, o→2, rest→1  => 3*3*3*1*1*2*1*1 = 54
        let v = leet_substitutions("password");
        // Just check a known variant is present.
        assert!(v.contains(&"password".to_owned()));
        assert!(v.contains(&"p4ssw0rd".to_owned()));
        assert!(v.contains(&"p@$$w0rd".to_owned()));
    }

    #[test]
    fn leet_strategy_streams_all_variants() {
        let s = LeetStrategy::new("admin", vec!["a".into()]);
        let creds = collect_sync(&s);
        // 'a' → original + '4' + '@' = 3 variants
        assert_eq!(creds.len(), 3);
        let pws: Vec<_> = creds.iter().map(|c| c.password.as_str()).collect();
        assert!(pws.contains(&"a"));
        assert!(pws.contains(&"4"));
        assert!(pws.contains(&"@"));
    }

    #[test]
    fn leet_strategy_multiple_words() {
        let s = LeetStrategy::new("user", vec!["e".into(), "z".into()]);
        let creds = collect_sync(&s);
        // 'e' → 2 variants; 'z' → 1 variant = 3 total
        assert_eq!(creds.len(), 3);
    }

    #[test]
    fn leet_strategy_estimated_count() {
        // 'a' → 3 options, 'e' → 2 options; word "ae" → 6 combos
        let s = LeetStrategy::new("u", vec!["ae".into()]);
        assert_eq!(s.estimated_count(), Some(6));
    }
}
