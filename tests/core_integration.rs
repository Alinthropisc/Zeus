//! Integration tests for zeus-core public API.
//!
//! Covers:
//! - `Credential` construction, parsing, display, and equality
//! - `Target` construction, builder methods, URI generation, and URL parsing
//! - `AttackConfig` / `AttackConfigBuilder` default values and overrides

use zeus_core::config::{AttackConfig, AttackConfigBuilder};
use zeus_core::credential::Credential;
use zeus_core::target::Target;

// ─── Credential ──────────────────────────────────────────────────────────────

#[test]
fn credential_construction_stores_fields() {
    let cred = Credential::new("admin", "secret");
    assert_eq!(cred.username, "admin");
    assert_eq!(cred.password, "secret");
}

#[test]
fn credential_from_colon_str_valid() {
    let cred = Credential::from_colon_str("root:toor")
        .expect("colon-separated credential should parse");
    assert_eq!(cred.username, "root");
    assert_eq!(cred.password, "toor");
}

#[test]
fn credential_from_colon_str_missing_colon_returns_none() {
    assert!(
        Credential::from_colon_str("nocolon").is_none(),
        "input without ':' must return None"
    );
}

#[test]
fn credential_from_colon_str_empty_password() {
    // "user:" is valid — empty password after colon
    let cred = Credential::from_colon_str("user:").expect("empty password is valid");
    assert_eq!(cred.username, "user");
    assert_eq!(cred.password, "");
}

#[test]
fn credential_display_is_colon_separated() {
    let cred = Credential::new("alice", "hunter2");
    assert_eq!(cred.to_string(), "alice:hunter2");
}

#[test]
fn credential_equality_same_fields() {
    let a = Credential::new("admin", "admin");
    let b = Credential::new("admin", "admin");
    assert_eq!(a, b);
}

#[test]
fn credential_inequality_different_password() {
    let a = Credential::new("admin", "right");
    let b = Credential::new("admin", "wrong");
    assert_ne!(a, b);
}

#[test]
fn credential_clone_is_independent_value() {
    let original = Credential::new("user", "pass");
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

// ─── Target ──────────────────────────────────────────────────────────────────

#[test]
fn target_construction_sets_defaults() {
    let target = Target::new("192.168.1.1", 22, "ssh");
    assert_eq!(target.host, "192.168.1.1");
    assert_eq!(target.port, 22);
    assert_eq!(target.protocol, "ssh");
    assert!(!target.tls, "tls should default to false");
    assert!(target.path.is_none(), "path should default to None");
    assert!(target.options.is_empty(), "options should default to empty");
}

#[test]
fn target_with_tls_builder() {
    let target = Target::new("example.com", 443, "http").with_tls(true);
    assert!(target.tls);
}

#[test]
fn target_with_path_builder() {
    let target = Target::new("example.com", 80, "http").with_path("/admin");
    assert_eq!(target.path.as_deref(), Some("/admin"));
}

#[test]
fn target_with_option_builder() {
    let target = Target::new("host", 22, "ssh").with_option("timeout", "5");
    assert_eq!(
        target.options.get("timeout").map(String::as_str),
        Some("5")
    );
}

#[test]
fn target_uri_plain() {
    let target = Target::new("192.168.1.1", 21, "ftp");
    assert_eq!(target.uri(), "ftp://192.168.1.1:21");
}

#[test]
fn target_uri_tls_appends_s_to_scheme() {
    let target = Target::new("example.com", 443, "http").with_tls(true);
    assert!(target.uri().starts_with("https://"));
}

#[test]
fn target_uri_includes_path() {
    let target = Target::new("example.com", 443, "http")
        .with_tls(true)
        .with_path("/login");
    assert_eq!(target.uri(), "https://example.com:443/login");
}

#[test]
fn target_from_url_http_parses_all_fields() {
    let target = Target::from_url("http://example.com:80/path").expect("valid URL");
    assert_eq!(target.host, "example.com");
    assert_eq!(target.port, 80);
    assert_eq!(target.protocol, "http");
    assert!(!target.tls);
    assert_eq!(target.path.as_deref(), Some("/path"));
}

#[test]
fn target_from_url_https_sets_tls_flag() {
    let target = Target::from_url("https://example.com:443").expect("valid HTTPS URL");
    assert_eq!(target.protocol, "http");
    assert!(target.tls);
    assert_eq!(target.port, 443);
}

#[test]
fn target_from_url_ftp() {
    let target = Target::from_url("ftp://192.168.1.1:21").expect("valid FTP URL");
    assert_eq!(target.protocol, "ftp");
    assert_eq!(target.port, 21);
    assert!(!target.tls);
}

#[test]
fn target_from_url_missing_scheme_returns_error() {
    assert!(Target::from_url("example.com:80").is_err());
}

#[test]
fn target_from_url_invalid_port_returns_error() {
    assert!(Target::from_url("http://example.com:notaport").is_err());
}

// ─── AttackConfig / AttackConfigBuilder ──────────────────────────────────────

#[test]
fn attack_config_default_values() {
    let config = AttackConfig::default();
    assert_eq!(config.concurrency, 16);
    assert_eq!(config.max_tasks, 16);
    assert_eq!(config.retry_count, 1);
    assert_eq!(config.max_retries, 2);
    assert!(config.exit_on_first);
    assert!(config.stop_on_first);
    assert!(!config.verbose);
    assert!(config.rate_limit.is_none());
    assert_eq!(config.target_rps, 0);
}

#[test]
fn attack_config_builder_concurrency_syncs_max_tasks() {
    let config = AttackConfigBuilder::new().concurrency(4).build();
    assert_eq!(config.concurrency, 4);
    assert_eq!(config.max_tasks, 4);
}

#[test]
fn attack_config_builder_max_tasks_syncs_concurrency() {
    let config = AttackConfigBuilder::new().max_tasks(8).build();
    assert_eq!(config.max_tasks, 8);
    assert_eq!(config.concurrency, 8);
}

#[test]
fn attack_config_builder_stop_on_first_syncs_exit_on_first() {
    let config = AttackConfigBuilder::new().stop_on_first(false).build();
    assert!(!config.stop_on_first);
    assert!(!config.exit_on_first);
}

#[test]
fn attack_config_builder_verbose_flag() {
    let config = AttackConfigBuilder::new().verbose(true).build();
    assert!(config.verbose);
}

#[test]
fn attack_config_builder_rate_limit() {
    let config = AttackConfigBuilder::new().rate_limit(100).build();
    assert_eq!(config.rate_limit, Some(100));
}

// ─── Async smoke tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn credential_hash_usable_in_hashset() {
    use std::collections::HashSet;
    let mut set: HashSet<Credential> = HashSet::new();
    let c = Credential::new("admin", "pass");
    set.insert(c.clone());
    set.insert(c.clone()); // duplicate — should not grow set
    assert_eq!(set.len(), 1);
    assert!(set.contains(&c));
}

#[tokio::test]
async fn target_options_multiple_entries() {
    let target = Target::new("host", 22, "ssh")
        .with_option("timeout", "10")
        .with_option("retries", "3");
    assert_eq!(target.options.len(), 2);
    assert_eq!(target.options.get("timeout").map(String::as_str), Some("10"));
    assert_eq!(target.options.get("retries").map(String::as_str), Some("3"));
}
