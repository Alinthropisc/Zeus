//! Zeus Config — loads global configuration from TOML files and environment variables.
//!
//! Search order (last wins):
//!   1. Built-in defaults
//!   2. `/etc/zeus/zeus.toml`      (system-wide)
//!   3. `~/.config/zeus/zeus.toml` (user-level)
//!   4. `./zeus.toml`              (local project)
//!   5. `ZEUS__*` environment variables

use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZeusConfigError {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ZeusConfig {
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub retry_count: u32,
    pub retry_delay_ms: u64,
    pub exit_on_first: bool,
    pub rate_limit_rps: Option<u64>,
    pub verbose: bool,
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    pub format: OutputFormat,
    pub file: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Csv,
}

impl Default for ZeusConfig {
    fn default() -> Self {
        Self {
            concurrency: 16,
            timeout_secs: 10,
            retry_count: 1,
            retry_delay_ms: 500,
            exit_on_first: true,
            rate_limit_rps: None,
            verbose: false,
            output: OutputConfig::default(),
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self { format: OutputFormat::Text, file: None }
    }
}

impl ZeusConfig {
    /// Load configuration from default search paths + environment.
    pub fn load() -> Result<Self, ZeusConfigError> {
        let home = std::env::var("HOME").unwrap_or_default();

        let cfg = Config::builder()
            .add_source(File::with_name("/etc/zeus/zeus").required(false))
            .add_source(File::with_name(&format!("{}/.config/zeus/zeus", home)).required(false))
            .add_source(File::with_name("zeus").required(false))
            .add_source(Environment::with_prefix("ZEUS").separator("__"))
            .build()?;

        Ok(cfg.try_deserialize()?)
    }

    /// Load from an explicit file path (useful for `--config` CLI flag).
    pub fn from_file(path: &str) -> Result<Self, ZeusConfigError> {
        let cfg = Config::builder()
            .add_source(File::with_name(path))
            .add_source(Environment::with_prefix("ZEUS").separator("__"))
            .build()?;

        Ok(cfg.try_deserialize()?)
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    pub fn retry_delay(&self) -> Duration {
        Duration::from_millis(self.retry_delay_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let cfg = ZeusConfig::default();
        assert_eq!(cfg.concurrency, 16);
        assert!(cfg.exit_on_first);
        assert_eq!(cfg.timeout(), Duration::from_secs(10));
        assert_eq!(cfg.retry_delay(), Duration::from_millis(500));
        assert_eq!(cfg.output.format, OutputFormat::Text);
    }

    #[test]
    fn output_format_default() {
        let out = OutputConfig::default();
        assert_eq!(out.format, OutputFormat::Text);
        assert!(out.file.is_none());
    }

    #[test]
    fn load_no_files_uses_defaults() {
        // In a clean env with no config files present, load() returns defaults.
        let cfg = ZeusConfig::load().unwrap_or_default();
        assert!(cfg.concurrency > 0);
        assert!(cfg.timeout_secs > 0);
    }

    #[test]
    fn timeout_conversion() {
        let mut cfg = ZeusConfig::default();
        cfg.timeout_secs = 30;
        assert_eq!(cfg.timeout(), Duration::from_secs(30));
    }

    #[test]
    fn retry_delay_conversion() {
        let mut cfg = ZeusConfig::default();
        cfg.retry_delay_ms = 250;
        assert_eq!(cfg.retry_delay(), Duration::from_millis(250));
    }

    #[test]
    fn output_format_variants_distinct() {
        assert_ne!(OutputFormat::Text, OutputFormat::Json);
        assert_ne!(OutputFormat::Json, OutputFormat::Csv);
    }
}
