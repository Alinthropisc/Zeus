//! `TargetList` — a collection of [`Target`] values with iterator support,
//! string/file parsing, and CIDR expansion.

use std::path::Path;
use std::str::FromStr;

use crate::{Target, ZeusError};

/// A collection of targets with iterator support and parsing helpers.
pub struct TargetList {
    targets: Vec<Target>,
}

impl TargetList {
    /// Create an empty list.
    pub fn new() -> Self {
        Self { targets: Vec::new() }
    }

    /// Add a target to the list.
    pub fn add(&mut self, target: Target) {
        self.targets.push(target);
    }

    /// Construct from an existing `Vec<Target>`.
    pub fn from_vec(targets: Vec<Target>) -> Self {
        Self { targets }
    }

    /// Parse from a multi-line string where each line is `"host:port:protocol"`.
    ///
    /// Lines starting with `#` or blank lines are skipped.
    pub fn parse_str(s: &str) -> Result<Self, ZeusError> {
        let mut list = Self::new();
        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            list.add(Self::parse_target(line)?);
        }
        Ok(list)
    }

    /// Read targets from a file, one `"host:port:protocol"` entry per line.
    pub async fn from_file(path: impl AsRef<Path>) -> Result<Self, ZeusError> {
        let contents = tokio::fs::read_to_string(path).await?;
        Self::parse_str(&contents)
    }

    /// Parse a single target string.
    ///
    /// Accepted formats:
    /// - `"host:port:protocol"` — e.g. `"192.168.1.1:22:ssh"`
    /// - `"host:protocol"` — port defaults based on common protocols
    pub fn parse_target(s: &str) -> Result<Target, ZeusError> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        match parts.as_slice() {
            [host, port_str, protocol] => {
                let port: u16 = port_str.parse().map_err(|_| {
                    ZeusError::Config(format!("invalid port '{}' in target '{}'", port_str, s))
                })?;
                Ok(Target::new(*host, port, *protocol))
            }
            [host, protocol] => {
                let port = default_port_for(protocol);
                Ok(Target::new(*host, port, *protocol))
            }
            _ => Err(ZeusError::Config(format!(
                "invalid target format '{}': expected 'host:port:protocol' or 'host:protocol'",
                s
            ))),
        }
    }

    /// Number of targets in the list.
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    /// Returns `true` if the list contains no targets.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Iterate over references to each target.
    pub fn iter(&self) -> impl Iterator<Item = &Target> {
        self.targets.iter()
    }

    /// Expand a CIDR notation string into individual `Target` values.
    ///
    /// For example, `"192.168.1.0/24"` with port `22` and protocol `"ssh"`
    /// yields 254 targets (skipping network and broadcast addresses).
    ///
    /// `/32` yields exactly 1 target (the host address itself).
    pub fn expand_cidr(cidr: &str, port: u16, protocol: &str) -> Result<Vec<Target>, ZeusError> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(ZeusError::Config(format!("invalid CIDR notation: '{}'", cidr)));
        }

        let ip: std::net::Ipv4Addr = parts[0]
            .parse()
            .map_err(|_| ZeusError::Config(format!("invalid IP address in CIDR: '{}'", parts[0])))?;

        let prefix: u8 = parts[1]
            .parse()
            .map_err(|_| ZeusError::Config(format!("invalid prefix length in CIDR: '{}'", parts[1])))?;

        if prefix > 32 {
            return Err(ZeusError::Config(format!("prefix length {} > 32", prefix)));
        }

        let host_bits = 32 - prefix as u32;
        let count = 1u32 << host_bits;
        let mask: u32 = if prefix == 0 { 0 } else { !((1u32 << host_bits) - 1) };
        let network = u32::from(ip) & mask;

        // /32 — single host, no network/broadcast to strip
        if prefix == 32 {
            let addr = std::net::Ipv4Addr::from(network);
            return Ok(vec![Target::new(addr.to_string(), port, protocol)]);
        }

        // For all other prefix lengths skip first (network) and last (broadcast).
        let targets = (1..count - 1)
            .map(|i| {
                let addr = std::net::Ipv4Addr::from(network + i);
                Target::new(addr.to_string(), port, protocol)
            })
            .collect();

        Ok(targets)
    }
}

impl Default for TargetList {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoIterator for TargetList {
    type Item = Target;
    type IntoIter = std::vec::IntoIter<Target>;

    fn into_iter(self) -> Self::IntoIter {
        self.targets.into_iter()
    }
}

impl FromStr for TargetList {
    type Err = ZeusError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_str(s)
    }
}

/// Return a sensible default port for well-known protocol names.
fn default_port_for(protocol: &str) -> u16 {
    match protocol.to_lowercase().as_str() {
        "ssh" => 22,
        "ftp" => 21,
        "http" => 80,
        "https" => 443,
        "smtp" => 25,
        "pop3" => 110,
        "imap" => 143,
        "rdp" => 3389,
        "smb" => 445,
        "mysql" => 3306,
        "postgres" | "postgresql" => 5432,
        "redis" => 6379,
        "mongodb" => 27017,
        "telnet" => 23,
        "ldap" => 389,
        "vnc" => 5900,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_valid_three_parts() {
        let t = TargetList::parse_target("192.168.1.1:22:ssh").unwrap();
        assert_eq!(t.host, "192.168.1.1");
        assert_eq!(t.port, 22);
        assert_eq!(t.protocol, "ssh");
    }

    #[test]
    fn parse_target_two_parts_default_port() {
        let t = TargetList::parse_target("example.com:ssh").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 22);
        assert_eq!(t.protocol, "ssh");
    }

    #[test]
    fn parse_target_invalid() {
        assert!(TargetList::parse_target("onlyone").is_err());
    }

    #[test]
    fn parse_target_invalid_port() {
        assert!(TargetList::parse_target("host:notaport:ssh").is_err());
    }

    #[test]
    fn cidr_expansion_count_24() {
        let targets = TargetList::expand_cidr("192.168.1.0/24", 22, "ssh").unwrap();
        assert_eq!(targets.len(), 254);
    }

    #[test]
    fn cidr_expansion_single_32() {
        let targets = TargetList::expand_cidr("10.0.0.1/32", 22, "ssh").unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "10.0.0.1");
    }

    #[test]
    fn cidr_expansion_30() {
        // /30 → 4 addresses − 2 (network + broadcast) = 2 hosts
        let targets = TargetList::expand_cidr("10.0.0.0/30", 80, "http").unwrap();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn from_str_multiline() {
        let input = "192.168.0.1:22:ssh\n# comment\n\n10.0.0.1:80:http\n";
        let list: TargetList = input.parse().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn iter_len() {
        let mut list = TargetList::new();
        list.add(Target::new("a", 22, "ssh"));
        list.add(Target::new("b", 80, "http"));
        assert_eq!(list.iter().count(), 2);
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn into_iter_consumes() {
        let list = TargetList::from_vec(vec![
            Target::new("a", 22, "ssh"),
            Target::new("b", 80, "http"),
        ]);
        let collected: Vec<_> = list.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }
}
