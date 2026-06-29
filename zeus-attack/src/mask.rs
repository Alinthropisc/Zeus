//! Mask attack strategy — hashcat-style character-position masks.

use crate::{AttackStrategy, CredentialStream};
use tokio_stream::iter;
use zeus_core::Credential;

const CHARSET_LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const CHARSET_UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const CHARSET_DIGIT: &str = "0123456789";
const CHARSET_SPECIAL: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";

pub struct MaskStrategy {
    username: String,
    positions: Vec<Vec<char>>,
    mask: String,
}

impl MaskStrategy {
    pub fn new(username: impl Into<String>, mask: impl Into<String>) -> Self {
        let mask = mask.into();
        let positions = Self::parse_mask(&mask);
        Self {
            username: username.into(),
            positions,
            mask,
        }
    }

    fn parse_mask(mask: &str) -> Vec<Vec<char>> {
        let mut positions = Vec::new();
        let mut chars = mask.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '?' {
                let charset: Vec<char> = match chars.next() {
                    Some('l') => CHARSET_LOWER.chars().collect(),
                    Some('u') => CHARSET_UPPER.chars().collect(),
                    Some('d') => CHARSET_DIGIT.chars().collect(),
                    Some('s') => CHARSET_SPECIAL.chars().collect(),
                    Some('a') => {
                        let mut all: Vec<char> = CHARSET_LOWER
                            .chars()
                            .chain(CHARSET_UPPER.chars())
                            .chain(CHARSET_DIGIT.chars())
                            .chain(CHARSET_SPECIAL.chars())
                            .collect();
                        all.sort_unstable();
                        all.dedup();
                        all
                    }
                    Some(other) => vec![other],
                    None => vec!['?'],
                };
                positions.push(charset);
            } else {
                positions.push(vec![ch]);
            }
        }
        positions
    }

    fn generate_all(&self) -> Vec<Credential> {
        if self.positions.is_empty() {
            return vec![Credential::new(self.username.clone(), String::new())];
        }

        // Iterative cartesian product.
        let mut results: Vec<String> = vec![String::new()];
        for charset in &self.positions {
            let mut next = Vec::with_capacity(results.len() * charset.len());
            for prefix in &results {
                for &ch in charset {
                    let mut s = prefix.clone();
                    s.push(ch);
                    next.push(s);
                }
            }
            results = next;
        }

        results
            .into_iter()
            .map(|pw| Credential::new(self.username.clone(), pw))
            .collect()
    }

    pub fn estimated_count_from_positions(positions: &[Vec<char>]) -> u64 {
        if positions.is_empty() {
            return 1;
        }
        positions.iter().map(|p| p.len() as u64).product()
    }

    pub fn mask(&self) -> &str {
        &self.mask
    }
}

impl AttackStrategy for MaskStrategy {
    fn name(&self) -> &'static str {
        "mask"
    }

    fn credentials(&self) -> CredentialStream {
        Box::pin(iter(self.generate_all()))
    }

    fn estimated_count(&self) -> Option<u64> {
        Some(Self::estimated_count_from_positions(&self.positions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digit_mask_count() {
        let m = MaskStrategy::new("admin", "?d");
        assert_eq!(m.estimated_count().unwrap(), 10);
    }

    #[test]
    fn lower_digit_mask_count() {
        let m = MaskStrategy::new("admin", "?l?d");
        assert_eq!(m.estimated_count().unwrap(), 26 * 10);
    }

    #[test]
    fn upper_lower_digit_mask_count() {
        let m = MaskStrategy::new("admin", "?u?l?d");
        assert_eq!(m.estimated_count().unwrap(), 26 * 26 * 10);
    }

    #[test]
    fn literal_chars() {
        let m = MaskStrategy::new("admin", "ab");
        // 'a' and 'b' are literals, so positions = [['a'], ['b']]
        assert_eq!(m.estimated_count().unwrap(), 1);
        let creds = m.generate_all();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].password, "ab");
    }

    #[test]
    fn mixed_literal_and_placeholder() {
        // "pw?d" => literal 'p', literal 'w', digit charset
        let m = MaskStrategy::new("user", "pw?d");
        assert_eq!(m.estimated_count().unwrap(), 10);
        let creds = m.generate_all();
        assert_eq!(creds.len(), 10);
        assert!(creds.iter().all(|c| c.password.starts_with("pw")));
    }

    #[test]
    fn all_charset_has_printable_chars() {
        let m = MaskStrategy::new("admin", "?a");
        let count = m.estimated_count().unwrap();
        // ?a = lower(26) + upper(26) + digit(10) + special(26) = 88 unique
        assert!(count >= 88);
        let creds = m.generate_all();
        assert_eq!(creds.len() as u64, count);
    }

    #[test]
    fn empty_mask_yields_empty_password() {
        let m = MaskStrategy::new("admin", "");
        assert_eq!(m.estimated_count().unwrap(), 1);
        let creds = m.generate_all();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].password, "");
    }

    #[test]
    fn generate_all_digit_correct_values() {
        let m = MaskStrategy::new("admin", "?d");
        let creds = m.generate_all();
        let passwords: Vec<&str> = creds.iter().map(|c| c.password.as_str()).collect();
        for d in '0'..='9' {
            assert!(passwords.contains(&d.to_string().as_str()));
        }
    }
}
