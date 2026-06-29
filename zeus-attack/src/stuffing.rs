use crate::{AttackStrategy, CredentialStream};
use std::collections::HashMap;
use tokio_stream::iter;
use zeus_core::Credential;

/// A single entry parsed from a breach dump, augmented with occurrence count and source tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreachEntry {
    pub username: String,
    pub password: String,
    /// Number of times this exact pair appeared across all ingested lines.
    pub frequency: u32,
    /// Human-readable label for the originating dump (e.g. `"breach-2023-01"`).
    pub source: String,
}

/// Pipeline that ingests raw breach-dump lines, deduplicates credential pairs,
/// tracks occurrence frequency, and surfaces the most common pairs first.
///
/// Accepted line format: `username:password` (including `email@host:password`).
/// Lines that do not contain `:` are silently skipped.
pub struct CredentialStuffingPipeline {
    entries: Vec<BreachEntry>,
    domain_filter: Option<String>,
    normalize_usernames: bool,
    _source: String,
}

impl CredentialStuffingPipeline {
    /// Parse `lines` into a pipeline backed by `source` as a provenance label.
    pub fn from_lines(lines: impl Iterator<Item = String>, source: impl Into<String>) -> Self {
        let source = source.into();
        let mut freq: HashMap<(String, String), u32> = HashMap::new();

        for line in lines {
            let line = line.trim().to_string();
            if let Some((user, pass)) = line.split_once(':') {
                let key = (user.to_string(), pass.to_string());
                *freq.entry(key).or_insert(0) += 1;
            }
        }

        let entries = freq
            .into_iter()
            .map(|((username, password), frequency)| BreachEntry {
                username,
                password,
                frequency,
                source: source.clone(),
            })
            .collect();

        Self {
            entries,
            domain_filter: None,
            normalize_usernames: false,
            _source: source,
        }
    }

    /// Retain only entries whose username contains `@<domain>` (case-insensitive).
    pub fn with_domain_filter(mut self, domain: &str) -> Self {
        self.domain_filter = Some(domain.to_lowercase());
        self
    }

    /// When `true`, strip the domain portion from email usernames so that
    /// `alice@example.com` becomes `alice`.
    pub fn with_normalize_usernames(mut self, normalize: bool) -> Self {
        self.normalize_usernames = normalize;
        self
    }

    /// Apply filters and normalization, sort by frequency descending, and return
    /// the final `Credential` list ready for use in an attack.
    pub fn into_credentials(self) -> Vec<Credential> {
        let mut entries = self.entries;

        if let Some(ref domain) = self.domain_filter {
            let suffix = format!("@{}", domain);
            entries.retain(|e| e.username.to_lowercase().ends_with(&suffix));
        }

        if self.normalize_usernames {
            for entry in &mut entries {
                if let Some((local, _)) = entry.username.split_once('@') {
                    entry.username = local.to_string();
                }
            }
        }

        entries.sort_by(|a, b| b.frequency.cmp(&a.frequency));

        entries
            .into_iter()
            .map(|e| Credential::new(e.username, e.password))
            .collect()
    }
}

/// `AttackStrategy` wrapper around `CredentialStuffingPipeline`.
///
/// Construct via `CredentialStuffingStrategy::from_pipeline` after configuring
/// the pipeline, or use `CredentialStuffingStrategy::from_lines` as a shortcut.
pub struct CredentialStuffingStrategy {
    credentials: Vec<Credential>,
}

impl CredentialStuffingStrategy {
    pub fn from_pipeline(pipeline: CredentialStuffingPipeline) -> Self {
        Self { credentials: pipeline.into_credentials() }
    }

    pub fn from_lines(lines: impl Iterator<Item = String>, source: impl Into<String>) -> Self {
        Self::from_pipeline(CredentialStuffingPipeline::from_lines(lines, source))
    }
}

impl AttackStrategy for CredentialStuffingStrategy {
    fn name(&self) -> &'static str { "credential-stuffing" }

    fn credentials(&self) -> CredentialStream {
        Box::pin(iter(self.credentials.clone()))
    }

    fn estimated_count(&self) -> Option<u64> {
        Some(self.credentials.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    fn lines(raw: &[&str]) -> impl Iterator<Item = String> {
        raw.iter().map(|s| s.to_string()).collect::<Vec<_>>().into_iter()
    }

    fn pipeline(raw: &[&str]) -> CredentialStuffingPipeline {
        CredentialStuffingPipeline::from_lines(lines(raw), "test")
    }

    #[test]
    fn parses_colon_pairs() {
        let creds = pipeline(&["alice:hunter2", "bob:letmein"]).into_credentials();
        assert_eq!(creds.len(), 2);
    }

    #[test]
    fn skips_lines_without_colon() {
        let creds = pipeline(&["nodivider", "alice:pass"]).into_credentials();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "alice");
    }

    #[test]
    fn deduplicates_exact_pairs() {
        let creds = pipeline(&[
            "alice:hunter2",
            "alice:hunter2",
            "alice:hunter2",
            "bob:letmein",
        ])
        .into_credentials();
        assert_eq!(creds.len(), 2);
    }

    #[test]
    fn priority_ordering_by_frequency() {
        let creds = pipeline(&[
            "alice:hunter2",
            "bob:letmein",
            "bob:letmein",
            "bob:letmein",
            "carol:pass",
            "carol:pass",
        ])
        .into_credentials();
        assert_eq!(creds[0], Credential::new("bob", "letmein"));
        assert_eq!(creds[1], Credential::new("carol", "pass"));
        assert_eq!(creds[2], Credential::new("alice", "hunter2"));
    }

    #[test]
    fn domain_filter_retains_matching() {
        let creds = pipeline(&[
            "alice@example.com:pass",
            "bob@other.org:pass",
            "carol@example.com:pass",
        ])
        .with_domain_filter("example.com")
        .into_credentials();
        assert_eq!(creds.len(), 2);
        assert!(creds.iter().all(|c| c.username.ends_with("@example.com")));
    }

    #[test]
    fn domain_filter_case_insensitive() {
        let creds = pipeline(&["ALICE@Example.COM:pass"])
            .with_domain_filter("example.com")
            .into_credentials();
        assert_eq!(creds.len(), 1);
    }

    #[test]
    fn normalize_usernames_strips_domain() {
        let creds = pipeline(&["alice@example.com:secret"])
            .with_normalize_usernames(true)
            .into_credentials();
        assert_eq!(creds[0].username, "alice");
        assert_eq!(creds[0].password, "secret");
    }

    #[test]
    fn normalize_false_leaves_username_intact() {
        let creds = pipeline(&["alice@example.com:secret"])
            .with_normalize_usernames(false)
            .into_credentials();
        assert_eq!(creds[0].username, "alice@example.com");
    }

    #[test]
    fn domain_filter_then_normalize_combined() {
        let creds = pipeline(&[
            "alice@example.com:pass",
            "eve@evil.net:pass",
        ])
        .with_domain_filter("example.com")
        .with_normalize_usernames(true)
        .into_credentials();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "alice");
    }

    #[test]
    fn empty_input() {
        let creds = pipeline(&[]).into_credentials();
        assert!(creds.is_empty());
    }

    #[test]
    fn strategy_name() {
        let s = CredentialStuffingStrategy::from_lines(lines(&["u:p"]), "test");
        assert_eq!(s.name(), "credential-stuffing");
    }

    #[test]
    fn strategy_estimated_count() {
        let s = CredentialStuffingStrategy::from_lines(lines(&["u:p", "v:q"]), "test");
        assert_eq!(s.estimated_count(), Some(2));
    }

    #[test]
    fn strategy_stream_matches_credentials() {
        let s = CredentialStuffingStrategy::from_lines(lines(&["admin:admin"]), "test");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let creds = rt.block_on(async { s.credentials().collect::<Vec<_>>().await });
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0], Credential::new("admin", "admin"));
    }
}
