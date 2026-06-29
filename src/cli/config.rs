use anyhow::{Context, Result};
use std::path::PathBuf;
use zeus_core::Target;

use crate::cli::args::AttackArgs;

/// Parsed, validated configuration built from CLI arguments.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub target: Target,
    pub protocol: String,
    pub threads: usize,
    pub timeout_secs: u64,
    pub use_tui: bool,
    pub userlist_path: PathBuf,
    pub passlist_path: PathBuf,
}

impl AppConfig {
    pub fn from_args(args: &AttackArgs) -> Result<Self> {
        let (host, port) = parse_host_port(&args.target)
            .with_context(|| format!("invalid target '{}': expected host:port", args.target))?;

        let target = Target::new(host, port, &args.protocol);

        Ok(Self {
            target,
            protocol: args.protocol.clone(),
            threads: args.threads,
            timeout_secs: args.timeout,
            use_tui: args.tui,
            userlist_path: args.userlist.clone(),
            passlist_path: args.passlist.clone(),
        })
    }
}

fn parse_host_port(s: &str) -> Result<(String, u16)> {
    let (host, port_str) = s
        .rsplit_once(':')
        .with_context(|| "missing ':' separator")?;
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("invalid port '{}'", port_str))?;
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_args(target: &str, threads: usize) -> AttackArgs {
        AttackArgs {
            target: target.to_string(),
            protocol: "ssh".to_string(),
            userlist: PathBuf::from("users.txt"),
            passlist: PathBuf::from("pass.txt"),
            threads,
            timeout: 5,
            tui: false,
        }
    }

    #[test]
    fn valid_host_port_parses() {
        let args = make_args("localhost:22", 10);
        let cfg = AppConfig::from_args(&args).expect("should succeed");
        assert_eq!(cfg.target.host, "localhost");
        assert_eq!(cfg.target.port, 22);
    }

    #[test]
    fn invalid_port_non_numeric_returns_err() {
        let args = make_args("localhost:abc", 10);
        assert!(AppConfig::from_args(&args).is_err());
    }

    #[test]
    fn missing_port_separator_returns_err() {
        let args = make_args("localhost", 10);
        assert!(AppConfig::from_args(&args).is_err());
    }

    #[test]
    fn default_threads_is_ten() {
        let args = make_args("localhost:22", 10);
        let cfg = AppConfig::from_args(&args).expect("should succeed");
        assert_eq!(cfg.threads, 10);
    }
}
