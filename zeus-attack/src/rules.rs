use crate::{AttackStrategy, CredentialStream};
use tokio_stream::iter;
use zeus_core::Credential;

/// Hashcat-compatible transformation rules for password mutation.
#[derive(Debug, Clone)]
pub enum Rule {
    Capitalize,
    ToUpper,
    ToLower,
    Reverse,
    ToggleCase,
    Append(char),
    Prepend(char),
    AppendYear(u16),
    AppendNum(u8),
    L33tSpeak,
    Duplicate,
    TruncateTo(usize),
    AppendStr(String),
    Repeat(u8),
}

impl Rule {
    pub fn apply(&self, s: &str) -> String {
        match self {
            Rule::Capitalize => {
                let mut chars = s.chars();
                match chars.next() {
                    None => String::new(),
                    Some(f) => {
                        let upper: String = f.to_uppercase().collect();
                        upper + &chars.as_str().to_lowercase()
                    }
                }
            }
            Rule::ToUpper => s.to_uppercase(),
            Rule::ToLower => s.to_lowercase(),
            Rule::Reverse => s.chars().rev().collect(),
            Rule::ToggleCase => s
                .chars()
                .map(|c| {
                    if c.is_uppercase() {
                        c.to_lowercase().next().unwrap_or(c)
                    } else {
                        c.to_uppercase().next().unwrap_or(c)
                    }
                })
                .collect(),
            Rule::Append(ch) => format!("{}{}", s, ch),
            Rule::Prepend(ch) => format!("{}{}", ch, s),
            Rule::AppendYear(y) => format!("{}{}", s, y),
            Rule::AppendNum(n) => format!("{}{}", s, n),
            Rule::L33tSpeak => s
                .replace('e', "3")
                .replace('E', "3")
                .replace('a', "4")
                .replace('A', "4")
                .replace('o', "0")
                .replace('O', "0")
                .replace('i', "1")
                .replace('I', "1")
                .replace('s', "5")
                .replace('S', "5")
                .replace('t', "7")
                .replace('T', "7"),
            Rule::Duplicate => format!("{}{}", s, s),
            Rule::TruncateTo(n) => s.chars().take(*n).collect(),
            Rule::AppendStr(suffix) => format!("{}{}", s, suffix),
            Rule::Repeat(n) => s.repeat(*n as usize),
        }
    }
}

/// An ordered sequence of Rules applied left-to-right.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    pub fn apply(&self, s: &str) -> String {
        self.rules.iter().fold(s.to_owned(), |acc, r| r.apply(&acc))
    }

    pub fn apply_all(&self, words: &[String]) -> Vec<String> {
        words.iter().map(|w| self.apply(w)).collect()
    }

    /// Legacy builder API for backwards compat with existing code.
    pub fn with_rule(mut self, rule: impl Into<Rule>) -> Self
    where
        Rule: From<Rule>,
    {
        self.rules.push(rule.into());
        self
    }

    /// Generate all mutations of `password` from all rules (one per rule + original).
    pub fn mutate(&self, password: &str) -> Vec<String> {
        let mut results = vec![password.to_owned()];
        for rule in &self.rules {
            let new: Vec<_> = results.iter().map(|p| rule.apply(p)).collect();
            results.extend(new);
        }
        results.dedup();
        results
    }

    pub fn mutate_credential(&self, cred: &Credential) -> Vec<Credential> {
        self.mutate(&cred.password)
            .into_iter()
            .map(|p| Credential::new(cred.username.clone(), p))
            .collect()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ─── Hashcat-style string-rule engine ─────────────────────────────────────────

/// Parse a single hashcat-style rule string into a closure.
///
/// Supported rules:
/// - `:`        → identity (passthrough)
/// - `l`        → lowercase
/// - `u`        → uppercase
/// - `c`        → capitalize first char, lowercase rest
/// - `r`        → reverse
/// - `d`        → duplicate (word+word)
/// - `f`        → reflect (word+reverse(word))
/// - `t`        → toggle case of all chars
/// - `$X`       → append char X
/// - `^X`       → prepend char X
/// - `[`        → delete first char
/// - `]`        → delete last char
/// - `{`        → rotate left (first char moves to end)
/// - `}`        → rotate right (last char moves to front)
/// - `sXY`      → substitute all X with Y
/// - `TN`       → toggle case of char at position N (0-indexed, hex digit)
/// - `DN`       → delete char at position N (0-indexed, hex digit)
/// - `iNX`      → insert char X before position N (0-indexed, hex digit)
/// - `oNX`      → overwrite char at position N with X (0-indexed, hex digit)
pub fn parse_rule(rule: &str) -> Box<dyn Fn(&str) -> String + Send + Sync> {
    let bytes: Vec<char> = rule.chars().collect();
    match bytes.as_slice() {
        // Identity
        [':'] | [] => Box::new(|s: &str| s.to_owned()),
        // Lowercase
        ['l'] => Box::new(|s: &str| s.to_lowercase()),
        // Uppercase
        ['u'] => Box::new(|s: &str| s.to_uppercase()),
        // Capitalize
        ['c'] => Box::new(|s: &str| {
            let mut chars = s.chars();
            match chars.next() {
                None => String::new(),
                Some(f) => {
                    let upper: String = f.to_uppercase().collect();
                    upper + &chars.as_str().to_lowercase()
                }
            }
        }),
        // Reverse
        ['r'] => Box::new(|s: &str| s.chars().rev().collect()),
        // Duplicate
        ['d'] => Box::new(|s: &str| format!("{}{}", s, s)),
        // Reflect
        ['f'] => Box::new(|s: &str| {
            let rev: String = s.chars().rev().collect();
            format!("{}{}", s, rev)
        }),
        // Toggle case
        ['t'] => Box::new(|s: &str| {
            s.chars()
                .map(|c| {
                    if c.is_uppercase() {
                        c.to_lowercase().next().unwrap_or(c)
                    } else {
                        c.to_uppercase().next().unwrap_or(c)
                    }
                })
                .collect()
        }),
        // Delete first char
        ['['] => Box::new(|s: &str| {
            let mut chars = s.chars();
            chars.next();
            chars.collect()
        }),
        // Delete last char
        [']'] => Box::new(|s: &str| {
            let mut chars = s.chars();
            chars.next_back();
            chars.collect()
        }),
        // Rotate left: first char moves to end
        ['{'] => Box::new(|s: &str| {
            if s.is_empty() {
                return s.to_owned();
            }
            let mut chars = s.chars();
            let first = chars.next().unwrap();
            let rest: String = chars.collect();
            format!("{}{}", rest, first)
        }),
        // Rotate right: last char moves to front
        ['}'] => Box::new(|s: &str| {
            if s.is_empty() {
                return s.to_owned();
            }
            let mut chars = s.chars();
            let last = chars.next_back().unwrap();
            let rest: String = chars.collect();
            format!("{}{}", last, rest)
        }),
        // Append char
        ['$', x] => {
            let ch = *x;
            Box::new(move |s: &str| format!("{}{}", s, ch))
        }
        // Prepend char
        ['^', x] => {
            let ch = *x;
            Box::new(move |s: &str| format!("{}{}", ch, s))
        }
        // Substitute sXY
        ['s', from, to] => {
            let f = *from;
            let t = *to;
            Box::new(move |s: &str| s.replace(f, &t.to_string()))
        }
        // Toggle char at position TN
        ['T', n] => {
            let pos = n.to_digit(16).unwrap_or(0) as usize;
            Box::new(move |s: &str| {
                s.chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if i == pos {
                            if c.is_uppercase() {
                                c.to_lowercase().next().unwrap_or(c)
                            } else {
                                c.to_uppercase().next().unwrap_or(c)
                            }
                        } else {
                            c
                        }
                    })
                    .collect()
            })
        }
        // Delete char at position DN
        ['D', n] => {
            let pos = n.to_digit(16).unwrap_or(0) as usize;
            Box::new(move |s: &str| {
                s.chars()
                    .enumerate()
                    .filter_map(|(i, c)| if i == pos { None } else { Some(c) })
                    .collect()
            })
        }
        // Insert char at position iNX
        ['i', n, x] => {
            let pos = n.to_digit(16).unwrap_or(0) as usize;
            let ch = *x;
            Box::new(move |s: &str| {
                let mut chars: Vec<char> = s.chars().collect();
                let insert_at = pos.min(chars.len());
                chars.insert(insert_at, ch);
                chars.into_iter().collect()
            })
        }
        // Overwrite char at position oNX
        ['o', n, x] => {
            let pos = n.to_digit(16).unwrap_or(0) as usize;
            let ch = *x;
            Box::new(move |s: &str| {
                s.chars()
                    .enumerate()
                    .map(|(i, c)| if i == pos { ch } else { c })
                    .collect()
            })
        }
        // Unknown rule — identity
        _ => {
            let rule_str = rule.to_owned();
            Box::new(move |s: &str| {
                tracing::warn!(rule = %rule_str, "unknown hashcat rule — treating as identity");
                s.to_owned()
            })
        }
    }
}

/// Applies a chain of hashcat-style rules to each word in a wordlist and
/// streams the resulting credentials.
///
/// Rules are parsed once at construction time. For each word, every rule is
/// applied in sequence (left-to-right chaining) to produce a single mutated
/// candidate.  If you want each rule applied independently to the original
/// word, build one `RulesStrategy` per rule or use `RuleSet::mutate`.
pub struct RulesStrategy {
    username: String,
    wordlist: Vec<String>,
    rules: Vec<Box<dyn Fn(&str) -> String + Send + Sync>>,
}

impl RulesStrategy {
    /// Build from a wordlist and a slice of hashcat rule strings.
    pub fn new(
        username: impl Into<String>,
        wordlist: Vec<String>,
        rule_strings: &[&str],
    ) -> Self {
        let rules = rule_strings.iter().map(|r| parse_rule(r)).collect();
        Self {
            username: username.into(),
            wordlist,
            rules,
        }
    }

    /// Build with pre-parsed rule closures (useful for testing or dynamic composition).
    pub fn with_rule_fns(
        username: impl Into<String>,
        wordlist: Vec<String>,
        rules: Vec<Box<dyn Fn(&str) -> String + Send + Sync>>,
    ) -> Self {
        Self {
            username: username.into(),
            wordlist,
            rules,
        }
    }
}

impl AttackStrategy for RulesStrategy {
    fn name(&self) -> &'static str { "rules" }

    fn credentials(&self) -> CredentialStream {
        let mut creds: Vec<Credential> = Vec::with_capacity(self.wordlist.len());
        for word in &self.wordlist {
            // Apply all rules left-to-right as a chain.
            let mutated = self.rules.iter().fold(word.clone(), |acc, rule| rule(&acc));
            creds.push(Credential::new(self.username.clone(), mutated));
        }
        Box::pin(iter(creds))
    }

    fn estimated_count(&self) -> Option<u64> {
        Some(self.wordlist.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l33t_replaces_e() {
        assert_eq!(Rule::L33tSpeak.apply("elite"), "3l1t3");
    }

    #[test]
    fn l33t_replaces_all_targets() {
        assert_eq!(Rule::L33tSpeak.apply("east"), "3457");
    }

    #[test]
    fn capitalize_works() {
        assert_eq!(Rule::Capitalize.apply("hELLO"), "Hello");
        assert_eq!(Rule::Capitalize.apply("password"), "Password");
        assert_eq!(Rule::Capitalize.apply(""), "");
    }

    #[test]
    fn append_year_appends() {
        assert_eq!(Rule::AppendYear(2024).apply("pass"), "pass2024");
    }

    #[test]
    fn append_num_appends() {
        assert_eq!(Rule::AppendNum(7).apply("pass"), "pass7");
    }

    #[test]
    fn duplicate_doubles() {
        assert_eq!(Rule::Duplicate.apply("abc"), "abcabc");
    }

    #[test]
    fn truncate_truncates() {
        assert_eq!(Rule::TruncateTo(3).apply("abcdef"), "abc");
        assert_eq!(Rule::TruncateTo(10).apply("ab"), "ab");
    }

    #[test]
    fn toggle_case_toggles() {
        assert_eq!(Rule::ToggleCase.apply("Hello"), "hELLO");
    }

    #[test]
    fn repeat_repeats() {
        assert_eq!(Rule::Repeat(3).apply("ab"), "ababab");
    }

    #[test]
    fn append_str_appends() {
        assert_eq!(Rule::AppendStr("!@#".into()).apply("pass"), "pass!@#");
    }

    #[test]
    fn ruleset_chains_rules() {
        let rs = RuleSet::new(vec![
            Rule::Capitalize,
            Rule::AppendYear(2023),
        ]);
        assert_eq!(rs.apply("password"), "Password2023");
    }

    #[test]
    fn ruleset_apply_all() {
        let rs = RuleSet::new(vec![Rule::ToUpper]);
        let words = vec!["abc".to_string(), "def".to_string()];
        let result = rs.apply_all(&words);
        assert_eq!(result, vec!["ABC", "DEF"]);
    }

    #[test]
    fn ruleset_empty_is_identity() {
        let rs = RuleSet::new(vec![]);
        assert_eq!(rs.apply("unchanged"), "unchanged");
    }

    // ── parse_rule / RulesStrategy tests ──────────────────────────────────────

    fn apply(rule: &str, word: &str) -> String {
        parse_rule(rule)(word)
    }

    #[test]
    fn rule_identity() {
        assert_eq!(apply(":", "hello"), "hello");
    }

    #[test]
    fn rule_lowercase() {
        assert_eq!(apply("l", "HELLO"), "hello");
    }

    #[test]
    fn rule_uppercase() {
        assert_eq!(apply("u", "hello"), "HELLO");
    }

    #[test]
    fn rule_capitalize() {
        assert_eq!(apply("c", "hELLO"), "Hello");
        assert_eq!(apply("c", ""), "");
    }

    #[test]
    fn rule_reverse() {
        assert_eq!(apply("r", "abc"), "cba");
    }

    #[test]
    fn rule_duplicate() {
        assert_eq!(apply("d", "ab"), "abab");
    }

    #[test]
    fn rule_reflect() {
        assert_eq!(apply("f", "abc"), "abccba");
    }

    #[test]
    fn rule_toggle_case() {
        assert_eq!(apply("t", "Hello"), "hELLO");
    }

    #[test]
    fn rule_append_char() {
        assert_eq!(apply("$1", "pass"), "pass1");
        assert_eq!(apply("$!", "pass"), "pass!");
    }

    #[test]
    fn rule_prepend_char() {
        assert_eq!(apply("^1", "pass"), "1pass");
    }

    #[test]
    fn rule_delete_first() {
        assert_eq!(apply("[", "hello"), "ello");
        assert_eq!(apply("[", ""), "");
    }

    #[test]
    fn rule_delete_last() {
        assert_eq!(apply("]", "hello"), "hell");
        assert_eq!(apply("]", ""), "");
    }

    #[test]
    fn rule_rotate_left() {
        assert_eq!(apply("{", "abcd"), "bcda");
        assert_eq!(apply("{", ""), "");
    }

    #[test]
    fn rule_rotate_right() {
        assert_eq!(apply("}", "abcd"), "dabc");
        assert_eq!(apply("}", ""), "");
    }

    #[test]
    fn rule_substitute() {
        assert_eq!(apply("sao", "password"), "pAssword".replace('a', "o"));
        assert_eq!(apply("sae", "banana"), "benene");
    }

    #[test]
    fn rule_toggle_at_position() {
        // T0 → toggle char at index 0
        assert_eq!(apply("T0", "hello"), "Hello");
        // T2 → toggle char at index 2
        assert_eq!(apply("T2", "hello"), "heLlo");
    }

    #[test]
    fn rule_delete_at_position() {
        assert_eq!(apply("D0", "hello"), "ello");
        assert_eq!(apply("D2", "hello"), "helo");
    }

    #[test]
    fn rule_insert_at_position() {
        assert_eq!(apply("i0X", "hello"), "Xhello");
        assert_eq!(apply("i2X", "hello"), "heXllo");
    }

    #[test]
    fn rule_overwrite_at_position() {
        assert_eq!(apply("o0X", "hello"), "Xello");
        assert_eq!(apply("o4X", "hello"), "hellX");
    }

    #[test]
    fn rules_strategy_chains_rules() {
        // uppercase then append '1'
        let s = RulesStrategy::new(
            "admin",
            vec!["pass".to_owned(), "word".to_owned()],
            &["u", "$1"],
        );
        let creds: Vec<_> = {
            use futures::StreamExt;
            // Collect synchronously via block_on
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async { s.credentials().collect::<Vec<_>>().await })
        };
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0].password, "PASS1");
        assert_eq!(creds[1].password, "WORD1");
    }

    #[test]
    fn rules_strategy_estimated_count() {
        let s = RulesStrategy::new("u", vec!["a".into(), "b".into(), "c".into()], &["l"]);
        assert_eq!(s.estimated_count(), Some(3));
    }
}
