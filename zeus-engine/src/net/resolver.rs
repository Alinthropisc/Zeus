//! Smart address resolver combining [`DnsCache`] with IPv4/IPv6 preference.
//!
//! Handles IP literals directly (no DNS), and delegates hostnames to
//! [`DnsCache`] for cached async resolution.

use crate::dns::DnsCache;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

// ──────────────────────────────────────────────────────────────────────────────
// AddressResolver
// ──────────────────────────────────────────────────────────────────────────────

/// Smart resolver that combines DNS caching with address-family preference.
///
/// Detects IP literals and skips DNS for them; falls back to [`DnsCache`] for
/// hostnames.
pub struct AddressResolver {
    dns: DnsCache,
    prefer_ipv4: bool,
}

impl AddressResolver {
    /// Create with default DNS cache (5-min TTL) and IPv4 preference.
    pub fn new() -> Self {
        Self {
            dns: DnsCache::new_default(),
            prefer_ipv4: true,
        }
    }

    /// Create with a custom [`DnsCache`].
    pub fn with_dns(dns: DnsCache) -> Self {
        Self { dns, prefer_ipv4: true }
    }

    /// Prefer IPv6 addresses over IPv4 when both are available.
    pub fn prefer_ipv6(mut self) -> Self {
        self.prefer_ipv4 = false;
        self
    }

    /// Resolve `host` to a single [`SocketAddr`] with `port`.
    ///
    /// Accepts:
    /// - IPv4 literals: `"192.168.1.1"`
    /// - IPv6 literals: `"::1"` or `"[::1]"`
    /// - Hostnames: `"example.com"`
    pub async fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> Result<SocketAddr, std::io::Error> {
        // Strip brackets from IPv6 literals like "[::1]"
        let bare = host.trim_start_matches('[').trim_end_matches(']');

        if let Ok(ip) = IpAddr::from_str(bare) {
            return Ok(SocketAddr::new(ip, port));
        }

        if self.prefer_ipv4 {
            self.dns.resolve_ipv4_preferred(host, port).await
        } else {
            self.dns.resolve_to_addr(host, port).await
        }
    }

    /// Resolve `host` to **all** available [`SocketAddr`]s with `port`.
    pub async fn resolve_all(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Vec<SocketAddr>, std::io::Error> {
        let bare = host.trim_start_matches('[').trim_end_matches(']');

        if let Ok(ip) = IpAddr::from_str(bare) {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        let addrs = self.dns.resolve(host).await?;
        Ok(addrs.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
    }

    /// Return `true` if `s` is an IP address literal (IPv4 or IPv6, with or
    /// without brackets).
    pub fn is_ip_literal(s: &str) -> bool {
        let bare = s.trim_start_matches('[').trim_end_matches(']');
        IpAddr::from_str(bare).is_ok()
    }
}

impl Default for AddressResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_ip_literal_v4() {
        assert!(AddressResolver::is_ip_literal("192.168.1.1"));
        assert!(AddressResolver::is_ip_literal("10.0.0.1"));
        assert!(AddressResolver::is_ip_literal("127.0.0.1"));
    }

    #[test]
    fn is_ip_literal_v6() {
        assert!(AddressResolver::is_ip_literal("::1"));
        assert!(AddressResolver::is_ip_literal("[::1]"));
        assert!(AddressResolver::is_ip_literal("2001:db8::1"));
        assert!(AddressResolver::is_ip_literal("[2001:db8::1]"));
    }

    #[test]
    fn is_ip_literal_hostname() {
        assert!(!AddressResolver::is_ip_literal("example.com"));
        assert!(!AddressResolver::is_ip_literal("localhost"));
        assert!(!AddressResolver::is_ip_literal("my-host.internal"));
    }

    #[test]
    fn resolver_default_prefer_ipv4() {
        let r = AddressResolver::new();
        assert!(r.prefer_ipv4, "default should prefer IPv4");
    }

    #[test]
    fn resolver_prefer_ipv6_flag() {
        let r = AddressResolver::new().prefer_ipv6();
        assert!(!r.prefer_ipv4);
    }

    #[tokio::test]
    async fn resolve_ipv4_literal_no_dns() {
        let r = AddressResolver::new();
        let addr = r.resolve("127.0.0.1", 80).await.unwrap();
        assert_eq!(addr.port(), 80);
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
    }

    #[tokio::test]
    async fn resolve_ipv6_literal_bracketed() {
        let r = AddressResolver::new();
        let addr = r.resolve("[::1]", 443).await.unwrap();
        assert_eq!(addr.port(), 443);
        assert_eq!(addr.ip().to_string(), "::1");
    }

    #[tokio::test]
    async fn resolve_all_ip_literal_returns_one() {
        let r = AddressResolver::new();
        let addrs = r.resolve_all("10.0.0.1", 22).await.unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].port(), 22);
    }
}
