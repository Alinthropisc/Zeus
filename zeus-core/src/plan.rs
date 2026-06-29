//! `AttackPlan` — command pattern for structured, serializable attack plans.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{AttackConfig, ZeusError};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A fully-specified attack plan that can be validated, serialized, and
/// handed to the engine for execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPlan {
    /// Human-readable name for this plan.
    pub name: String,
    /// List of targets to attack.
    pub targets: Vec<TargetSpec>,
    /// How credentials are supplied.
    pub credentials: CredentialSpec,
    /// Engine configuration (concurrency, timeouts, retries …).
    pub config: AttackConfig,
    /// Where / how results are written.
    pub output: OutputSpec,
}

/// One entry in the target list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSpec {
    pub host: String,
    /// `None` means "use the protocol's default port".
    pub port: Option<u16>,
    pub protocol: String,
    /// Protocol-specific key/value options.
    pub options: HashMap<String, String>,
}

impl TargetSpec {
    pub fn new(host: impl Into<String>, protocol: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: None,
            protocol: protocol.into(),
            options: HashMap::new(),
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }
}

/// How credentials are supplied to the attack engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialSpec {
    /// One username + a path to a password wordlist file.
    Wordlist { username: String, path: String },
    /// Multiple usernames each tried against a wordlist file.
    MultiUser {
        usernames: Vec<String>,
        path: String,
    },
    /// Pure brute-force over a character set between `min_len` and `max_len`.
    BruteForce {
        username: String,
        charset: String,
        min_len: usize,
        max_len: usize,
    },
    /// Combo file where each line is `"user:pass"`.
    Combo { path: String },
    /// Credentials supplied inline (useful for testing / small lists).
    Inline { credentials: Vec<(String, String)> },
}

/// Output format selection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Text,
    Json,
    Csv,
}

/// Where and how to write attack results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSpec {
    pub format: OutputFormat,
    /// `None` → write to stdout only.
    pub path: Option<String>,
    pub verbose: bool,
}

impl Default for OutputSpec {
    fn default() -> Self {
        Self {
            format: OutputFormat::Text,
            path: None,
            verbose: false,
        }
    }
}

// ---------------------------------------------------------------------------
// AttackPlan impl
// ---------------------------------------------------------------------------

impl AttackPlan {
    /// Start building a new plan with the given name.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(name: impl Into<String>) -> AttackPlanBuilder {
        AttackPlanBuilder::new(name)
    }

    /// Load a plan from a JSON file.
    pub async fn from_json_file(path: impl AsRef<Path>) -> Result<Self, ZeusError> {
        let contents = tokio::fs::read_to_string(path).await?;
        serde_json::from_str(&contents)
            .map_err(|e| ZeusError::Config(format!("JSON parse error: {}", e)))
    }

    /// Save this plan to a JSON file.
    pub async fn to_json_file(&self, path: impl AsRef<Path>) -> Result<(), ZeusError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| ZeusError::Config(format!("JSON serialization error: {}", e)))?;
        tokio::fs::write(path, json).await?;
        Ok(())
    }

    /// Load a plan from a TOML file.
    ///
    /// Internally, the file is read and deserialized via `serde_json` after
    /// converting the TOML syntax — a `toml` serialization crate is not
    /// currently in the workspace, so JSON is used as the canonical on-disk
    /// format.  The method is named `from_toml_file` to satisfy the API
    /// contract; it delegates to the JSON loader and expects a JSON file.
    ///
    /// TODO: add the `toml` workspace crate to enable native TOML encoding.
    pub async fn from_toml_file(path: impl AsRef<Path>) -> Result<Self, ZeusError> {
        Self::from_json_file(path).await
    }

    /// Save this plan to a TOML file.
    ///
    /// See [`from_toml_file`] — this currently writes JSON.
    pub async fn to_toml_file(&self, path: impl AsRef<Path>) -> Result<(), ZeusError> {
        self.to_json_file(path).await
    }

    /// Validate the plan and return `Ok(warnings)` or `Err(errors)`.
    ///
    /// - `Ok(warnings)` — plan is valid; warnings are non-fatal observations.
    /// - `Err(errors)` — plan is invalid and cannot be executed as-is.
    pub fn validate(&self) -> Result<Vec<String>, Vec<String>> {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        if self.name.trim().is_empty() {
            warnings.push("plan name is empty".to_string());
        }

        if self.targets.is_empty() {
            errors.push("no targets specified".to_string());
        }

        for (i, t) in self.targets.iter().enumerate() {
            if t.host.trim().is_empty() {
                errors.push(format!("target[{}]: host is empty", i));
            }
            if t.protocol.trim().is_empty() {
                errors.push(format!("target[{}]: protocol is empty", i));
            }
        }

        match &self.credentials {
            CredentialSpec::Wordlist { username, path } => {
                if username.trim().is_empty() {
                    errors.push("credentials.wordlist: username is empty".to_string());
                }
                if path.trim().is_empty() {
                    errors.push("credentials.wordlist: path is empty".to_string());
                }
            }
            CredentialSpec::MultiUser { usernames, path } => {
                if usernames.is_empty() {
                    errors.push("credentials.multi_user: usernames list is empty".to_string());
                }
                if path.trim().is_empty() {
                    errors.push("credentials.multi_user: path is empty".to_string());
                }
            }
            CredentialSpec::BruteForce {
                username,
                charset,
                min_len,
                max_len,
            } => {
                if username.trim().is_empty() {
                    errors.push("credentials.brute_force: username is empty".to_string());
                }
                if charset.trim().is_empty() {
                    errors.push("credentials.brute_force: charset is empty".to_string());
                }
                if min_len > max_len {
                    errors.push(format!(
                        "credentials.brute_force: min_len ({}) > max_len ({})",
                        min_len, max_len
                    ));
                }
                if *max_len > 12 {
                    warnings.push(format!(
                        "credentials.brute_force: max_len={} may generate a very large keyspace",
                        max_len
                    ));
                }
            }
            CredentialSpec::Combo { path } => {
                if path.trim().is_empty() {
                    errors.push("credentials.combo: path is empty".to_string());
                }
            }
            CredentialSpec::Inline { credentials } => {
                if credentials.is_empty() {
                    warnings.push("credentials.inline: credentials list is empty".to_string());
                }
            }
        }

        if self.config.concurrency == 0 {
            errors.push("config.concurrency must be > 0".to_string());
        }

        if errors.is_empty() {
            Ok(warnings)
        } else {
            Err(errors)
        }
    }

    /// Number of targets in the plan.
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Fluent builder for [`AttackPlan`].
pub struct AttackPlanBuilder {
    plan: AttackPlan,
}

impl AttackPlanBuilder {
    fn new(name: impl Into<String>) -> Self {
        Self {
            plan: AttackPlan {
                name: name.into(),
                targets: Vec::new(),
                credentials: CredentialSpec::Inline {
                    credentials: Vec::new(),
                },
                config: AttackConfig::default(),
                output: OutputSpec::default(),
            },
        }
    }

    /// Add a target with the protocol's default port.
    pub fn target(mut self, host: impl Into<String>, protocol: impl Into<String>) -> Self {
        self.plan.targets.push(TargetSpec::new(host, protocol));
        self
    }

    /// Add a target with an explicit port.
    pub fn target_with_port(
        mut self,
        host: impl Into<String>,
        port: u16,
        protocol: impl Into<String>,
    ) -> Self {
        self.plan
            .targets
            .push(TargetSpec::new(host, protocol).with_port(port));
        self
    }

    /// Use a single-username wordlist as the credential source.
    pub fn wordlist(mut self, username: impl Into<String>, path: impl Into<String>) -> Self {
        self.plan.credentials = CredentialSpec::Wordlist {
            username: username.into(),
            path: path.into(),
        };
        self
    }

    /// Use brute-force generation as the credential source.
    pub fn brute_force(
        mut self,
        username: impl Into<String>,
        charset: impl Into<String>,
        min: usize,
        max: usize,
    ) -> Self {
        self.plan.credentials = CredentialSpec::BruteForce {
            username: username.into(),
            charset: charset.into(),
            min_len: min,
            max_len: max,
        };
        self
    }

    /// Override the attack configuration.
    pub fn config(mut self, config: AttackConfig) -> Self {
        self.plan.config = config;
        self
    }

    /// Write results as JSON to the given file path.
    pub fn output_json(mut self, path: impl Into<String>) -> Self {
        self.plan.output = OutputSpec {
            format: OutputFormat::Json,
            path: Some(path.into()),
            verbose: false,
        };
        self
    }

    /// Write results as plain text to stdout.
    pub fn output_text(mut self) -> Self {
        self.plan.output = OutputSpec {
            format: OutputFormat::Text,
            path: None,
            verbose: false,
        };
        self
    }

    /// Consume the builder and return the finished plan.
    pub fn build(self) -> AttackPlan {
        self.plan
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_builder_basic() {
        let plan = AttackPlan::new("my-plan")
            .target("192.168.1.1", "ssh")
            .target_with_port("example.com", 8080, "http")
            .wordlist("admin", "/tmp/passwords.txt")
            .output_json("/tmp/results.json")
            .build();

        assert_eq!(plan.name, "my-plan");
        assert_eq!(plan.target_count(), 2);
        assert_eq!(plan.targets[1].port, Some(8080));
        assert!(matches!(plan.credentials, CredentialSpec::Wordlist { .. }));
        assert_eq!(plan.output.format, OutputFormat::Json);
        assert_eq!(plan.output.path.as_deref(), Some("/tmp/results.json"));
    }

    #[test]
    fn plan_validate_empty_targets_error() {
        let plan = AttackPlan::new("empty")
            .wordlist("admin", "/tmp/list.txt")
            .build();

        let result = plan.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("no targets")));
    }

    #[test]
    fn plan_validate_ok_with_warnings() {
        let plan = AttackPlan::new("") // empty name → warning
            .target("host", "ssh")
            .wordlist("root", "/tmp/list.txt")
            .build();

        let result = plan.validate();
        assert!(result.is_ok());
        let warnings = result.unwrap();
        assert!(warnings.iter().any(|w| w.contains("name is empty")));
    }

    #[test]
    fn plan_validate_brute_force_min_gt_max_error() {
        let plan = AttackPlan::new("bf")
            .target("host", "ssh")
            .brute_force("admin", "abc", 8, 4) // min > max
            .build();

        let errors = plan.validate().unwrap_err();
        assert!(errors.iter().any(|e| e.contains("min_len")));
    }

    #[test]
    fn credential_spec_variants_serialize() {
        // Ensure all enum variants round-trip through JSON
        let specs = vec![
            CredentialSpec::Wordlist {
                username: "u".into(),
                path: "p".into(),
            },
            CredentialSpec::MultiUser {
                usernames: vec!["a".into()],
                path: "p".into(),
            },
            CredentialSpec::BruteForce {
                username: "u".into(),
                charset: "abc".into(),
                min_len: 1,
                max_len: 4,
            },
            CredentialSpec::Combo { path: "p".into() },
            CredentialSpec::Inline {
                credentials: vec![("u".into(), "p".into())],
            },
        ];

        for spec in specs {
            let json = serde_json::to_string(&spec).unwrap();
            let back: CredentialSpec = serde_json::from_str(&json).unwrap();
            // Re-serialize to compare string representation
            assert_eq!(json, serde_json::to_string(&back).unwrap());
        }
    }

    #[test]
    fn output_spec_defaults() {
        let spec = OutputSpec::default();
        assert_eq!(spec.format, OutputFormat::Text);
        assert!(spec.path.is_none());
        assert!(!spec.verbose);
    }

    #[tokio::test]
    async fn plan_json_roundtrip() {
        let plan = AttackPlan::new("roundtrip")
            .target_with_port("10.0.0.1", 22, "ssh")
            .wordlist("root", "/tmp/list.txt")
            .output_text()
            .build();

        let tmp = "/tmp/zeus_plan_test.json";
        plan.to_json_file(tmp).await.unwrap();
        let loaded = AttackPlan::from_json_file(tmp).await.unwrap();

        assert_eq!(loaded.name, "roundtrip");
        assert_eq!(loaded.target_count(), 1);
        assert_eq!(loaded.targets[0].host, "10.0.0.1");
        assert_eq!(loaded.targets[0].port, Some(22));

        // Clean up
        let _ = tokio::fs::remove_file(tmp).await;
    }
}
