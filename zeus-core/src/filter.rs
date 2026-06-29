//! `FilterChain` — decorator pattern for composable credential filters.

use std::collections::HashSet;

use crate::Credential;

/// A filter that decides whether to attempt a credential or skip it.
pub trait CredentialFilter: Send + Sync {
    /// Return `true` if the credential should be attempted.
    fn should_attempt(&self, cred: &Credential) -> bool;
    /// Human-readable name for this filter (used in diagnostics).
    fn name(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// FilterChain
// ---------------------------------------------------------------------------

/// Chain of filters using AND logic — all filters must pass for a credential
/// to be attempted.
pub struct FilterChain {
    filters: Vec<Box<dyn CredentialFilter>>,
}

impl FilterChain {
    /// Create an empty chain (passes everything).
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
        }
    }

    /// Builder method — append a filter to the chain.
    pub fn with(mut self, filter: impl CredentialFilter + 'static) -> Self {
        self.filters.push(Box::new(filter));
        self
    }

    /// Returns `true` only if every filter in the chain passes.
    pub fn should_attempt(&self, cred: &Credential) -> bool {
        self.filters.iter().all(|f| f.should_attempt(cred))
    }

    /// Number of filters currently in the chain.
    pub fn filter_count(&self) -> usize {
        self.filters.len()
    }
}

impl Default for FilterChain {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Built-in filters
// ---------------------------------------------------------------------------

/// Reject credentials whose password is shorter than `min` characters.
pub struct MinLengthFilter {
    pub min: usize,
}

impl CredentialFilter for MinLengthFilter {
    fn should_attempt(&self, cred: &Credential) -> bool {
        cred.password.len() >= self.min
    }
    fn name(&self) -> &'static str {
        "MinLengthFilter"
    }
}

/// Reject credentials whose password is longer than `max` characters.
pub struct MaxLengthFilter {
    pub max: usize,
}

impl CredentialFilter for MaxLengthFilter {
    fn should_attempt(&self, cred: &Credential) -> bool {
        cred.password.len() <= self.max
    }
    fn name(&self) -> &'static str {
        "MaxLengthFilter"
    }
}

/// Reject credentials whose password contains no ASCII digit.
pub struct RequiresDigitFilter;

impl CredentialFilter for RequiresDigitFilter {
    fn should_attempt(&self, cred: &Credential) -> bool {
        cred.password.chars().any(|c| c.is_ascii_digit())
    }
    fn name(&self) -> &'static str {
        "RequiresDigitFilter"
    }
}

/// Reject credentials where the username equals the password (case-sensitive).
pub struct NoSameUserPassFilter;

impl CredentialFilter for NoSameUserPassFilter {
    fn should_attempt(&self, cred: &Credential) -> bool {
        cred.username != cred.password
    }
    fn name(&self) -> &'static str {
        "NoSameUserPassFilter"
    }
}

/// Reject credentials whose password appears in a blacklist.
pub struct BlacklistFilter {
    passwords: HashSet<String>,
}

impl BlacklistFilter {
    /// Construct from an explicit list of disallowed passwords.
    pub fn new(passwords: Vec<String>) -> Self {
        Self {
            passwords: passwords.into_iter().collect(),
        }
    }

    /// Pre-loaded with a set of common trivial passwords that are almost never
    /// worth attempting (they are low-signal and inflate attempt counts).
    pub fn common() -> Self {
        Self::new(
            ["", "password", "123456", "admin", "root", "test"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
    }
}

impl CredentialFilter for BlacklistFilter {
    fn should_attempt(&self, cred: &Credential) -> bool {
        !self.passwords.contains(&cred.password)
    }
    fn name(&self) -> &'static str {
        "BlacklistFilter"
    }
}

// ---------------------------------------------------------------------------
// PatternFilter — hashcat-style mask matching
// ---------------------------------------------------------------------------

/// Filter that only allows passwords matching a hashcat-style mask pattern.
///
/// Supported mask tokens:
/// - `?l` — lowercase letter
/// - `?u` — uppercase letter
/// - `?d` — digit
/// - `?s` — special / punctuation character
/// - `?a` — any printable ASCII character
/// - `?b` — any byte value (always matches)
/// - Any other character — literal match
pub struct PatternFilter {
    pattern: String,
}

impl PatternFilter {
    /// Create a `PatternFilter` from a hashcat-style mask string,
    /// e.g. `"?u?l?l?d?d?d?d"`.
    pub fn from_mask(mask: &str) -> Self {
        Self {
            pattern: mask.to_string(),
        }
    }

    fn matches(&self, s: &str) -> bool {
        let chars: Vec<char> = s.chars().collect();
        let pat: Vec<char> = self.pattern.chars().collect();

        // Walk through the pattern, consuming one or two pattern chars per
        // position and exactly one string char.
        let mut si = 0usize; // index into `chars`
        let mut pi = 0usize; // index into `pat`

        while pi < pat.len() {
            if si >= chars.len() {
                return false; // string exhausted before pattern
            }

            if pat[pi] == '?' && pi + 1 < pat.len() {
                let token = pat[pi + 1];
                let ch = chars[si];
                let ok = match token {
                    'l' => ch.is_ascii_lowercase(),
                    'u' => ch.is_ascii_uppercase(),
                    'd' => ch.is_ascii_digit(),
                    's' => ch.is_ascii_punctuation(),
                    'a' => ch.is_ascii() && !ch.is_ascii_control(),
                    'b' => true,
                    _ => ch == token, // unknown token — treat as literal
                };
                if !ok {
                    return false;
                }
                pi += 2;
                si += 1;
            } else {
                // Literal character
                if chars[si] != pat[pi] {
                    return false;
                }
                pi += 1;
                si += 1;
            }
        }

        // Both pattern and string must be fully consumed.
        si == chars.len()
    }
}

impl CredentialFilter for PatternFilter {
    fn should_attempt(&self, cred: &Credential) -> bool {
        self.matches(&cred.password)
    }
    fn name(&self) -> &'static str {
        "PatternFilter"
    }
}

// ---------------------------------------------------------------------------
// ClosureFilter
// ---------------------------------------------------------------------------

/// A filter backed by an arbitrary closure — useful for one-off rules without
/// writing a new type.
pub struct ClosureFilter<F: Fn(&Credential) -> bool + Send + Sync> {
    func: F,
    label: &'static str,
}

impl<F: Fn(&Credential) -> bool + Send + Sync> ClosureFilter<F> {
    /// Create a closure-based filter with a human-readable `label`.
    pub fn new(label: &'static str, func: F) -> Self {
        Self { func, label }
    }
}

impl<F: Fn(&Credential) -> bool + Send + Sync> CredentialFilter for ClosureFilter<F> {
    fn should_attempt(&self, cred: &Credential) -> bool {
        (self.func)(cred)
    }
    fn name(&self) -> &'static str {
        self.label
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(user: &str, pass: &str) -> Credential {
        Credential::new(user, pass)
    }

    #[test]
    fn filter_chain_all_must_pass() {
        let chain = FilterChain::new()
            .with(MinLengthFilter { min: 4 })
            .with(MaxLengthFilter { max: 8 });

        assert!(chain.should_attempt(&cred("u", "abcd"))); // 4 chars — ok
        assert!(!chain.should_attempt(&cred("u", "ab"))); // too short
        assert!(!chain.should_attempt(&cred("u", "abcdefghi"))); // too long
    }

    #[test]
    fn filter_chain_empty_passes_all() {
        let chain = FilterChain::new();
        assert!(chain.should_attempt(&cred("u", "")));
        assert_eq!(chain.filter_count(), 0);
    }

    #[test]
    fn min_length_filter() {
        let f = MinLengthFilter { min: 6 };
        assert!(!f.should_attempt(&cred("u", "abc")));
        assert!(f.should_attempt(&cred("u", "abcdef")));
    }

    #[test]
    fn max_length_filter() {
        let f = MaxLengthFilter { max: 4 };
        assert!(f.should_attempt(&cred("u", "ab")));
        assert!(!f.should_attempt(&cred("u", "abcde")));
    }

    #[test]
    fn requires_digit_filter() {
        let f = RequiresDigitFilter;
        assert!(!f.should_attempt(&cred("u", "password")));
        assert!(f.should_attempt(&cred("u", "pass1word")));
    }

    #[test]
    fn no_same_user_pass() {
        let f = NoSameUserPassFilter;
        assert!(!f.should_attempt(&cred("admin", "admin")));
        assert!(f.should_attempt(&cred("admin", "secret")));
    }

    #[test]
    fn blacklist_common() {
        let f = BlacklistFilter::common();
        assert!(!f.should_attempt(&cred("u", "password")));
        assert!(!f.should_attempt(&cred("u", "admin")));
        assert!(!f.should_attempt(&cred("u", "")));
        assert!(f.should_attempt(&cred("u", "S3cur3P@ss!")));
    }

    #[test]
    fn blacklist_custom() {
        let f = BlacklistFilter::new(vec!["hunter2".into(), "letmein".into()]);
        assert!(!f.should_attempt(&cred("u", "hunter2")));
        assert!(f.should_attempt(&cred("u", "password")));
    }

    #[test]
    fn pattern_filter_digits_only() {
        // "?d?d?d?d" should match any 4-digit string
        let f = PatternFilter::from_mask("?d?d?d?d");
        assert!(f.should_attempt(&cred("u", "1234")));
        assert!(!f.should_attempt(&cred("u", "12a4")));
        assert!(!f.should_attempt(&cred("u", "123"))); // too short
        assert!(!f.should_attempt(&cred("u", "12345"))); // too long
    }

    #[test]
    fn pattern_filter_upper_lower_digits() {
        // "?u?l?l?d" — uppercase, two lowercase, one digit
        let f = PatternFilter::from_mask("?u?l?l?d");
        assert!(f.should_attempt(&cred("u", "Abc9")));
        assert!(!f.should_attempt(&cred("u", "abc9")));
        assert!(!f.should_attempt(&cred("u", "Abc")));
    }

    #[test]
    fn closure_filter() {
        let f = ClosureFilter::new("no-root-pass", |c: &Credential| c.username != "root");
        assert!(f.should_attempt(&cred("admin", "pass")));
        assert!(!f.should_attempt(&cred("root", "pass")));
        assert_eq!(f.name(), "no-root-pass");
    }
}
