use crate::{AttackStrategy, CredentialStream};
use tokio_stream::iter;
use zeus_core::Credential;

/// Brute-force attack — generate all combinations from a charset up to max_length.
pub struct BruteForceStrategy {
    username: String,
    charset: Vec<char>,
    min_length: usize,
    max_length: usize,
}

impl BruteForceStrategy {
    pub fn new(
        username: impl Into<String>,
        charset: impl Into<String>,
        min_length: usize,
        max_length: usize,
    ) -> Self {
        Self {
            username: username.into(),
            charset: charset.into().chars().collect(),
            min_length,
            max_length,
        }
    }

    pub fn alphanumeric(username: impl Into<String>, max_length: usize) -> Self {
        Self::new(
            username,
            "abcdefghijklmnopqrstuvwxyz0123456789",
            1,
            max_length,
        )
    }

    fn generate_all(&self) -> Vec<Credential> {
        let mut results = Vec::new();
        for len in self.min_length..=self.max_length {
            self.combinations(len, &mut String::new(), &mut results);
        }
        results
    }

    fn combinations(&self, remaining: usize, current: &mut String, out: &mut Vec<Credential>) {
        if remaining == 0 {
            out.push(Credential::new(self.username.clone(), current.clone()));
            return;
        }
        for &ch in &self.charset {
            current.push(ch);
            self.combinations(remaining - 1, current, out);
            current.pop();
        }
    }

    fn charset_pow(base: usize, exp: usize) -> u64 {
        (base as u64).pow(exp as u32)
    }
}

impl AttackStrategy for BruteForceStrategy {
    fn name(&self) -> &'static str { "brute-force" }

    fn credentials(&self) -> CredentialStream {
        Box::pin(iter(self.generate_all()))
    }

    fn estimated_count(&self) -> Option<u64> {
        let base = self.charset.len();
        let total: u64 = (self.min_length..=self.max_length)
            .map(|l| Self::charset_pow(base, l))
            .sum();
        Some(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brute_force_1_char() {
        let bf = BruteForceStrategy::new("admin", "ab", 1, 1);
        let count = bf.estimated_count().unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn brute_force_2_char() {
        let bf = BruteForceStrategy::new("admin", "ab", 1, 2);
        // 2 + 4 = 6
        assert_eq!(bf.estimated_count().unwrap(), 6);
    }
}
