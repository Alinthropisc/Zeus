//! `CredentialStore` — repository pattern for storing and querying found credentials.

use std::collections::HashSet;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Credential, ZeusError};

/// A credential that was successfully authenticated against a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundCredential {
    /// The username/password pair that succeeded.
    pub credential: Credential,
    /// `"host:port:protocol"` of the target.
    pub target: String,
    /// Protocol name (e.g. `"ssh"`, `"http"`).
    pub protocol: String,
    /// UTC timestamp when the credential was found.
    pub found_at: DateTime<Utc>,
    /// How many milliseconds elapsed from the start of the attempt.
    pub elapsed_ms: u64,
}

impl FoundCredential {
    /// Construct a new `FoundCredential` stamped with the current UTC time.
    pub fn new(
        credential: Credential,
        target: impl Into<String>,
        protocol: impl Into<String>,
        elapsed_ms: u64,
    ) -> Self {
        Self {
            credential,
            target: target.into(),
            protocol: protocol.into(),
            found_at: Utc::now(),
            elapsed_ms,
        }
    }

    /// The deduplication key used internally: `"user:pass@host:port:protocol"`.
    fn dedup_key(&self) -> String {
        format!(
            "{}:{}@{}",
            self.credential.username, self.credential.password, self.target
        )
    }
}

/// Repository for found credentials with deduplication and export helpers.
pub struct CredentialStore {
    found: Vec<FoundCredential>,
    /// Set of dedup keys already stored.
    seen: HashSet<String>,
}

impl CredentialStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            found: Vec::new(),
            seen: HashSet::new(),
        }
    }

    /// Add a found credential.  Returns `false` if an identical entry
    /// (same username, password, and target) already exists.
    pub fn add(&mut self, cred: FoundCredential) -> bool {
        let key = cred.dedup_key();
        if self.seen.contains(&key) {
            return false;
        }
        self.seen.insert(key);
        self.found.push(cred);
        true
    }

    /// Returns `true` if a credential with `username`, `password` on `target`
    /// is already stored.
    pub fn contains(&self, username: &str, password: &str, target: &str) -> bool {
        let key = format!("{}:{}@{}", username, password, target);
        self.seen.contains(&key)
    }

    /// All stored credentials in insertion order.
    pub fn all(&self) -> &[FoundCredential] {
        &self.found
    }

    /// All credentials found against a specific target string.
    pub fn by_target(&self, target: &str) -> Vec<&FoundCredential> {
        self.found.iter().filter(|c| c.target == target).collect()
    }

    /// All credentials found via a specific protocol.
    pub fn by_protocol(&self, protocol: &str) -> Vec<&FoundCredential> {
        self.found.iter().filter(|c| c.protocol == protocol).collect()
    }

    /// Number of stored credentials.
    pub fn count(&self) -> usize {
        self.found.len()
    }

    /// Serialize the store to a JSON file.
    pub async fn save_json(&self, path: impl AsRef<Path>) -> Result<(), ZeusError> {
        let json = serde_json::to_string_pretty(&self.found)
            .map_err(|e| ZeusError::Config(format!("JSON serialization failed: {}", e)))?;
        tokio::fs::write(path, json).await?;
        Ok(())
    }

    /// Deserialize a store from a JSON file previously written by [`save_json`].
    pub async fn load_json(path: impl AsRef<Path>) -> Result<Self, ZeusError> {
        let contents = tokio::fs::read_to_string(path).await?;
        let found: Vec<FoundCredential> = serde_json::from_str(&contents)
            .map_err(|e| ZeusError::Config(format!("JSON parse failed: {}", e)))?;
        let mut store = Self::new();
        for c in found {
            store.add(c);
        }
        Ok(store)
    }

    /// Export all credentials as a CSV string.
    ///
    /// Header: `username,password,target,protocol,found_at,elapsed_ms`
    pub fn to_csv(&self) -> String {
        let mut out = String::from("username,password,target,protocol,found_at,elapsed_ms\n");
        for c in &self.found {
            out.push_str(&format!(
                "{},{},{},{},{},{}\n",
                c.credential.username,
                c.credential.password,
                c.target,
                c.protocol,
                c.found_at.to_rfc3339(),
                c.elapsed_ms,
            ));
        }
        out
    }

    /// Export as plaintext `"user:pass@host"` — one entry per line.
    pub fn to_plaintext(&self) -> String {
        self.found
            .iter()
            .map(|c| format!("{}:{}@{}", c.credential.username, c.credential.password, c.target))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Merge `other` into this store; deduplication still applies.
    pub fn merge(&mut self, other: CredentialStore) {
        for c in other.found {
            self.add(c);
        }
    }
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_found(user: &str, pass: &str, target: &str, protocol: &str) -> FoundCredential {
        FoundCredential::new(
            Credential::new(user, pass),
            target,
            protocol,
            100,
        )
    }

    #[test]
    fn add_dedup() {
        let mut store = CredentialStore::new();
        let c = make_found("admin", "pass", "10.0.0.1:22:ssh", "ssh");
        assert!(store.add(c.clone()));
        assert!(!store.add(c)); // duplicate
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn contains_check() {
        let mut store = CredentialStore::new();
        store.add(make_found("root", "toor", "host:22:ssh", "ssh"));
        assert!(store.contains("root", "toor", "host:22:ssh"));
        assert!(!store.contains("root", "wrong", "host:22:ssh"));
    }

    #[test]
    fn by_target_filter() {
        let mut store = CredentialStore::new();
        store.add(make_found("a", "b", "10.0.0.1:22:ssh", "ssh"));
        store.add(make_found("c", "d", "10.0.0.2:22:ssh", "ssh"));
        let results = store.by_target("10.0.0.1:22:ssh");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].credential.username, "a");
    }

    #[test]
    fn by_protocol_filter() {
        let mut store = CredentialStore::new();
        store.add(make_found("a", "b", "host:22:ssh", "ssh"));
        store.add(make_found("c", "d", "host:80:http", "http"));
        assert_eq!(store.by_protocol("ssh").len(), 1);
        assert_eq!(store.by_protocol("http").len(), 1);
        assert_eq!(store.by_protocol("ftp").len(), 0);
    }

    #[test]
    fn count_after_merge() {
        let mut a = CredentialStore::new();
        a.add(make_found("u1", "p1", "t:22:ssh", "ssh"));

        let mut b = CredentialStore::new();
        b.add(make_found("u2", "p2", "t:22:ssh", "ssh"));
        // duplicate from a — should not increase count
        b.add(make_found("u1", "p1", "t:22:ssh", "ssh"));

        a.merge(b);
        assert_eq!(a.count(), 2);
    }

    #[test]
    fn to_csv_format() {
        let mut store = CredentialStore::new();
        store.add(make_found("admin", "secret", "10.0.0.1:80:http", "http"));
        let csv = store.to_csv();
        assert!(csv.starts_with("username,password,target,protocol,found_at,elapsed_ms\n"));
        assert!(csv.contains("admin,secret,10.0.0.1:80:http,http,"));
    }

    #[test]
    fn to_plaintext_format() {
        let mut store = CredentialStore::new();
        store.add(make_found("root", "toor", "srv:22:ssh", "ssh"));
        let plain = store.to_plaintext();
        assert_eq!(plain, "root:toor@srv:22:ssh");
    }

    #[test]
    fn to_plaintext_multiple() {
        let mut store = CredentialStore::new();
        store.add(make_found("a", "b", "h1:22:ssh", "ssh"));
        store.add(make_found("c", "d", "h2:80:http", "http"));
        let plain = store.to_plaintext();
        let lines: Vec<&str> = plain.lines().collect();
        assert_eq!(lines.len(), 2);
    }
}
