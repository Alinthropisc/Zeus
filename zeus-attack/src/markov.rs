use crate::{AttackStrategy, CredentialStream};
use std::collections::HashMap;
use tokio_stream::iter;
use zeus_core::Credential;

// ── Simple LCG PRNG (no external dep) ────────────────────────────────────────

struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self { Self { state: seed } }

    fn next(&mut self) -> u64 {
        self.state = self.state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }

    fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 { return 0; }
        (self.next() as usize) % max
    }
}

// ── Markov chain ──────────────────────────────────────────────────────────────

/// N-gram Markov chain for statistical password generation.
///
/// `order` controls how many characters are used as the look-back state
/// (1 = bigram, 2 = trigram, etc.).  After training on sample passwords the
/// chain can generate new candidates that statistically resemble the training
/// corpus.
pub struct MarkovChain {
    order: usize,
    /// state → Vec<(next_char, frequency_weight)>
    transitions: HashMap<String, Vec<(char, u32)>>,
    /// first-character frequencies
    starts: HashMap<char, u32>,
}

impl MarkovChain {
    pub fn new(order: usize) -> Self {
        Self {
            order: order.max(1),
            transitions: HashMap::new(),
            starts: HashMap::new(),
        }
    }

    /// Train on a slice of sample password strings.
    pub fn train(&mut self, samples: &[&str]) {
        for sample in samples {
            let chars: Vec<char> = sample.chars().collect();
            if chars.is_empty() { continue; }

            *self.starts.entry(chars[0]).or_insert(0) += 1;

            for i in 0..chars.len().saturating_sub(self.order) {
                let state: String = chars[i..i + self.order].iter().collect();
                let next = chars[i + self.order];
                let entry = self.transitions.entry(state).or_default();
                if let Some(item) = entry.iter_mut().find(|(c, _)| *c == next) {
                    item.1 += 1;
                } else {
                    entry.push((next, 1));
                }
            }
        }
    }

    /// Generate `count` password candidates of lengths in `[min_len, max_len]`.
    ///
    /// Uses the LCG PRNG seeded with `seed` for deterministic output.
    pub fn generate(
        &self,
        count: usize,
        min_len: usize,
        max_len: usize,
        seed: u64,
    ) -> Vec<String> {
        let mut rng = Lcg::new(seed);
        let mut results = Vec::with_capacity(count);

        let start_chars: Vec<(char, u32)> =
            self.starts.iter().map(|(c, w)| (*c, *w)).collect();
        if start_chars.is_empty() { return results; }

        let total_start: u32 = start_chars.iter().map(|(_, w)| w).sum();
        let len_range = max_len.saturating_sub(min_len);

        for _ in 0..count {
            let target_len = min_len + rng.next_usize(len_range + 1);
            let mut password = String::with_capacity(target_len);

            // Pick starting character by weighted sampling.
            let roll = (rng.next() % total_start as u64) as u32;
            let mut acc = 0u32;
            let mut current = start_chars[0].0;
            for (c, w) in &start_chars {
                acc += w;
                if roll < acc { current = *c; break; }
            }
            password.push(current);

            // Extend via transitions.
            for _ in 1..target_len {
                let state: String = if password.len() >= self.order {
                    password
                        .chars()
                        .rev()
                        .take(self.order)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect()
                } else {
                    password.clone()
                };

                if let Some(nexts) = self.transitions.get(&state) {
                    let total: u32 = nexts.iter().map(|(_, w)| w).sum();
                    if total == 0 { break; }
                    let roll = (rng.next() % total as u64) as u32;
                    let mut acc = 0u32;
                    for (c, w) in nexts {
                        acc += w;
                        if roll < acc { password.push(*c); break; }
                    }
                } else {
                    break;
                }
            }

            if password.len() >= min_len {
                results.push(password);
            }
        }
        results
    }

    /// Pre-trained chain using common English password patterns.
    pub fn english_common() -> Self {
        let mut chain = Self::new(1);
        chain.train(&[
            "password", "qwerty", "letmein", "dragon", "master",
            "monkey", "shadow", "sunshine", "princess", "welcome",
            "football", "baseball", "superman", "batman", "batman1",
            "hello", "hello1", "iloveyou", "trustno1", "starwars",
            "passw0rd", "password1", "abc123", "111111", "123456",
            "michael", "jessica", "access", "ranger", "hunter",
            "buster", "thomas", "robert", "hockey", "killer",
        ]);
        chain
    }
}

// ── MarkovStrategy ────────────────────────────────────────────────────────────

/// Attack strategy that generates password candidates via a Markov chain model.
pub struct MarkovStrategy {
    username: String,
    chain: MarkovChain,
    count: usize,
    min_len: usize,
    max_len: usize,
    seed: u64,
}

impl MarkovStrategy {
    pub fn new(
        username: impl Into<String>,
        chain: MarkovChain,
        count: usize,
        min_len: usize,
        max_len: usize,
    ) -> Self {
        Self {
            username: username.into(),
            chain,
            count,
            min_len,
            max_len,
            seed: 42,
        }
    }

    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Convenience constructor using a pre-trained English common-password chain.
    pub fn english_common(username: impl Into<String>, count: usize) -> Self {
        Self::new(username, MarkovChain::english_common(), count, 6, 12)
    }
}

impl AttackStrategy for MarkovStrategy {
    fn name(&self) -> &'static str { "markov" }

    fn credentials(&self) -> CredentialStream {
        let passwords =
            self.chain.generate(self.count, self.min_len, self.max_len, self.seed);
        let username = self.username.clone();
        let creds: Vec<Credential> = passwords
            .into_iter()
            .map(|p| Credential::new(username.clone(), p))
            .collect();
        Box::pin(iter(creds))
    }

    fn estimated_count(&self) -> Option<u64> {
        Some(self.count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    fn trained_chain() -> MarkovChain {
        let mut c = MarkovChain::new(1);
        c.train(&["password", "passphrase", "passage", "dragon", "dragoon"]);
        c
    }

    fn collect_sync(s: &MarkovStrategy) -> Vec<Credential> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { s.credentials().collect::<Vec<_>>().await })
    }

    #[test]
    fn markov_chain_train_starts() {
        let chain = trained_chain();
        assert!(!chain.starts.is_empty());
        // "password", "passphrase", "passage" all start with 'p'
        assert!(chain.starts.contains_key(&'p'));
        assert!(chain.starts.contains_key(&'d'));
    }

    #[test]
    fn markov_chain_train_transitions() {
        let chain = trained_chain();
        assert!(!chain.transitions.is_empty());
        // 'p' → 'a' should appear (from "pass*")
        let pa = chain.transitions.get("p");
        assert!(pa.is_some());
        let nexts = pa.unwrap();
        assert!(nexts.iter().any(|(c, _)| *c == 'a'));
    }

    #[test]
    fn markov_generate_count() {
        let chain = trained_chain();
        // Request exactly 20 candidates
        let passwords = chain.generate(20, 4, 10, 1234);
        // Some may be dropped if they fall below min_len, but with trained data
        // most will meet the minimum. We allow up to 20.
        assert!(passwords.len() <= 20);
        // At least some should be generated from a trained chain
        assert!(!passwords.is_empty());
    }

    #[test]
    fn markov_generate_len_bounds() {
        let chain = trained_chain();
        let passwords = chain.generate(50, 3, 8, 9999);
        for p in &passwords {
            assert!(p.len() >= 3, "password '{}' too short", p);
            assert!(p.len() <= 8, "password '{}' too long", p);
        }
    }

    #[test]
    fn markov_generate_deterministic() {
        let chain = trained_chain();
        let a = chain.generate(10, 4, 8, 42);
        let b = chain.generate(10, 4, 8, 42);
        assert_eq!(a, b);
    }

    #[test]
    fn markov_generate_different_seeds() {
        let chain = trained_chain();
        let a = chain.generate(10, 4, 8, 1);
        let b = chain.generate(10, 4, 8, 2);
        // Different seeds should (almost always) produce different output
        assert_ne!(a, b);
    }

    #[test]
    fn markov_english_common_not_empty() {
        let s = MarkovStrategy::english_common("admin", 20);
        let creds = collect_sync(&s);
        assert!(!creds.is_empty());
    }

    #[test]
    fn lcg_different_seeds() {
        let mut a = Lcg::new(1);
        let mut b = Lcg::new(2);
        let seq_a: Vec<u64> = (0..5).map(|_| a.next()).collect();
        let seq_b: Vec<u64> = (0..5).map(|_| b.next()).collect();
        assert_ne!(seq_a, seq_b);
    }

    #[test]
    fn markov_strategy_estimated_count() {
        let s = MarkovStrategy::english_common("u", 30);
        assert_eq!(s.estimated_count(), Some(30));
    }
}
