use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Zeus — async network login auditing tool (educational purposes only).
#[derive(Debug, Parser)]
#[command(name = "zeus", version, about, long_about = None)]
pub struct ZeusArgs {
    #[command(subcommand)]
    pub command: ZeusSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ZeusSubcommand {
    /// Run a login-brute-force / dictionary attack against a target.
    Attack(AttackArgs),
    /// Probe a target to verify connectivity and identify the protocol.
    Probe(ProbeArgs),
    /// List available protocols.
    List,
}

#[derive(Debug, clap::Args)]
pub struct AttackArgs {
    /// Target in `host:port` format (e.g. `192.168.1.1:22`).
    #[arg(short = 't', long)]
    pub target: String,

    /// Protocol to use (e.g. ssh, ftp, http).
    #[arg(short = 'p', long)]
    pub protocol: String,

    /// Path to username list file.
    #[arg(short = 'U', long)]
    pub userlist: PathBuf,

    /// Path to password list file.
    #[arg(short = 'P', long)]
    pub passlist: PathBuf,

    /// Number of concurrent worker threads.
    #[arg(short = 'T', long, default_value_t = 10)]
    pub threads: usize,

    /// Per-attempt timeout in seconds.
    #[arg(long, default_value_t = 5)]
    pub timeout: u64,

    /// Launch the TUI dashboard instead of plain log output.
    #[arg(long)]
    pub tui: bool,
}

#[derive(Debug, clap::Args)]
pub struct ProbeArgs {
    /// Target in `host:port` or `proto://host:port` format.
    #[arg(short = 't', long)]
    pub target: String,

    /// Protocol hint (optional).
    #[arg(short = 'p', long)]
    pub protocol: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn attack_subcommand_parses_correctly() {
        let args = ZeusArgs::try_parse_from([
            "zeus", "attack",
            "-t", "localhost:22",
            "-p", "ssh",
            "-U", "users.txt",
            "-P", "pass.txt",
        ])
        .expect("should parse");
        match args.command {
            ZeusSubcommand::Attack(a) => {
                assert_eq!(a.target, "localhost:22");
                assert_eq!(a.protocol, "ssh");
                assert_eq!(a.userlist, PathBuf::from("users.txt"));
                assert_eq!(a.passlist, PathBuf::from("pass.txt"));
                assert_eq!(a.threads, 10); // default
            }
            _ => panic!("expected Attack"),
        }
    }

    #[test]
    fn threads_flag_overrides_default() {
        let args = ZeusArgs::try_parse_from([
            "zeus", "attack",
            "-t", "localhost:22",
            "-p", "ssh",
            "-U", "users.txt",
            "-P", "pass.txt",
            "-T", "20",
        ])
        .expect("should parse");
        match args.command {
            ZeusSubcommand::Attack(a) => assert_eq!(a.threads, 20),
            _ => panic!("expected Attack"),
        }
    }

    #[test]
    fn list_subcommand_parses() {
        let args = ZeusArgs::try_parse_from(["zeus", "list"]).expect("should parse");
        assert!(matches!(args.command, ZeusSubcommand::List));
    }

    #[test]
    fn probe_subcommand_parses() {
        let args = ZeusArgs::try_parse_from([
            "zeus", "probe", "-t", "localhost:80", "-p", "http",
        ])
        .expect("should parse");
        match args.command {
            ZeusSubcommand::Probe(p) => {
                assert_eq!(p.target, "localhost:80");
                assert_eq!(p.protocol, Some("http".to_string()));
            }
            _ => panic!("expected Probe"),
        }
    }

    #[test]
    fn missing_required_args_returns_error() {
        // attack without -t / -p / -U / -P should fail
        let result = ZeusArgs::try_parse_from(["zeus", "attack"]);
        assert!(result.is_err());
    }
}
