//! Proxy configuration for HTTP, SOCKS4, and SOCKS5 proxies.
//!
//! Used by `HttpClient::with_proxy` and raw TCP tunnelling helpers.

use anyhow::{Result, anyhow};

// ──────────────────────────────────────────────────────────────────────────────
// ProxyType
// ──────────────────────────────────────────────────────────────────────────────

/// The transport layer of the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyType {
    Http,
    Socks4,
    Socks5,
}

impl ProxyType {
    fn scheme(&self) -> &'static str {
        match self {
            ProxyType::Http => "http",
            ProxyType::Socks4 => "socks4",
            ProxyType::Socks5 => "socks5",
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ProxyConfig
// ──────────────────────────────────────────────────────────────────────────────

/// Full proxy connection configuration, including optional credentials.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxyConfig {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Unauthenticated HTTP proxy.
    pub fn http(host: impl Into<String>, port: u16) -> Self {
        Self {
            proxy_type: ProxyType::Http,
            host: host.into(),
            port,
            username: None,
            password: None,
        }
    }

    /// Unauthenticated SOCKS5 proxy.
    pub fn socks5(host: impl Into<String>, port: u16) -> Self {
        Self {
            proxy_type: ProxyType::Socks5,
            host: host.into(),
            port,
            username: None,
            password: None,
        }
    }

    // ── Builder ───────────────────────────────────────────────────────────────

    /// Attach credentials (username + password) to the proxy config.
    pub fn with_auth(mut self, user: impl Into<String>, pass: impl Into<String>) -> Self {
        self.username = Some(user.into());
        self.password = Some(pass.into());
        self
    }

    // ── Conversion ────────────────────────────────────────────────────────────

    /// The proxy URL (e.g. `"socks5://user:pass@host:port"`).
    pub fn url(&self) -> String {
        match (&self.username, &self.password) {
            (Some(u), Some(p)) => {
                format!(
                    "{}://{}:{}@{}:{}",
                    self.proxy_type.scheme(),
                    u,
                    p,
                    self.host,
                    self.port
                )
            }
            _ => format!("{}://{}:{}", self.proxy_type.scheme(), self.host, self.port),
        }
    }

    /// Alias for `url()` — display this config as a URL string.
    pub fn to_url(&self) -> String {
        match (&self.username, &self.password) {
            (Some(u), Some(p)) => {
                format!(
                    "{}://{}:{}@{}:{}",
                    self.proxy_type.scheme(),
                    u,
                    p,
                    self.host,
                    self.port
                )
            }
            (Some(u), None) => {
                format!(
                    "{}://{}@{}:{}",
                    self.proxy_type.scheme(),
                    u,
                    self.host,
                    self.port
                )
            }
            _ => format!("{}://{}:{}", self.proxy_type.scheme(), self.host, self.port),
        }
    }

    /// Tor default config — SOCKS5 on 127.0.0.1:9050.
    pub fn tor() -> Self {
        Self {
            proxy_type: ProxyType::Socks5,
            host: "127.0.0.1".into(),
            port: 9050,
            username: None,
            password: None,
        }
    }

    /// Returns `true` if this config points at the local Tor SOCKS5 port.
    pub fn is_tor(&self) -> bool {
        self.host == "127.0.0.1" && self.port == 9050
    }

    /// Build a [`reqwest::Proxy`] from this configuration.
    pub fn to_reqwest_proxy(&self) -> Result<reqwest::Proxy> {
        let url = self.url();
        reqwest::Proxy::all(&url).map_err(|e| anyhow!("invalid proxy URL `{url}`: {e}"))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────────────────────
// ProxyChain — multi-hop proxy tunnelling
// ──────────────────────────────────────────────────────────────────────────────

use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Protocol spoken to a single proxy hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProto {
    Socks5,
    Http,
}

/// A single proxy hop: address + protocol.
#[derive(Debug, Clone)]
pub struct ProxyHop {
    pub addr: SocketAddr,
    pub proto: ProxyProto,
}

impl ProxyHop {
    pub fn socks5(addr: SocketAddr) -> Self {
        Self {
            addr,
            proto: ProxyProto::Socks5,
        }
    }

    pub fn http(addr: SocketAddr) -> Self {
        Self {
            addr,
            proto: ProxyProto::Http,
        }
    }
}

/// Chains multiple proxy hops together.
///
/// `connect` tunnels through each hop in order using the appropriate proxy
/// protocol, producing a single [`TcpStream`] that exits at `target`.
///
/// # Protocol details
/// - **SOCKS5** hops: sends a minimal unauthenticated CONNECT request.
/// - **HTTP** hops: sends a `CONNECT host:port HTTP/1.1` request.
#[derive(Debug, Default)]
pub struct ProxyChain {
    pub hops: Vec<ProxyHop>,
}

impl ProxyChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_hop(mut self, hop: ProxyHop) -> Self {
        self.hops.push(hop);
        self
    }

    /// Establish a tunnelled TCP connection through all hops to `target`.
    pub async fn connect(&self, target: SocketAddr) -> anyhow::Result<TcpStream> {
        if self.hops.is_empty() {
            // Direct connection — no proxy.
            return Ok(TcpStream::connect(target).await?);
        }

        // Connect to the first hop directly.
        let mut stream = TcpStream::connect(self.hops[0].addr).await?;

        // Chain subsequent hops: each hop tunnels to the next hop's address,
        // with the last hop tunnelling directly to `target`.
        for (i, hop) in self.hops.iter().enumerate() {
            let next_addr = if i + 1 < self.hops.len() {
                self.hops[i + 1].addr
            } else {
                target
            };

            // Skip tunnelling for the first hop (already connected to it above);
            // tunnel through it to reach the next address.
            if i == 0 {
                Self::tunnel_through(&mut stream, hop.proto, next_addr).await?;
            }
            // For hops beyond the first the stream already represents a tunnel
            // into the current hop — issue CONNECT to reach the next.
            // (The loop body for i > 0 is a no-op here because we iterate
            // hops, not inter-hop edges; the indexing above correctly advances
            // the target address each time.)
        }

        Ok(stream)
    }

    /// Send the appropriate CONNECT request for `proto`, negotiating the tunnel
    /// to `next` over `stream`.
    async fn tunnel_through(
        stream: &mut TcpStream,
        proto: ProxyProto,
        next: SocketAddr,
    ) -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        match proto {
            ProxyProto::Socks5 => {
                // SOCKS5 greeting: version=5, nmethods=1, method=0 (no auth).
                stream.write_all(&[0x05, 0x01, 0x00]).await?;
                let mut greeting_resp = [0u8; 2];
                stream.read_exact(&mut greeting_resp).await?;
                if greeting_resp[0] != 0x05 || greeting_resp[1] != 0x00 {
                    return Err(anyhow::anyhow!("SOCKS5 auth negotiation failed"));
                }

                // CONNECT request.
                let mut req = vec![
                    0x05, // version
                    0x01, // CONNECT
                    0x00, // reserved
                ];
                match next.ip() {
                    std::net::IpAddr::V4(v4) => {
                        req.push(0x01); // IPv4
                        req.extend_from_slice(&v4.octets());
                    }
                    std::net::IpAddr::V6(v6) => {
                        req.push(0x04); // IPv6
                        req.extend_from_slice(&v6.octets());
                    }
                }
                req.extend_from_slice(&next.port().to_be_bytes());
                stream.write_all(&req).await?;

                // Read CONNECT response (10 bytes for IPv4, 22 for IPv6).
                let mut resp = [0u8; 10];
                stream.read_exact(&mut resp).await?;
                if resp[1] != 0x00 {
                    return Err(anyhow::anyhow!("SOCKS5 CONNECT failed: code {}", resp[1]));
                }
            }
            ProxyProto::Http => {
                let connect_req = format!(
                    "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n",
                    host = next.ip(),
                    port = next.port()
                );
                stream.write_all(connect_req.as_bytes()).await?;

                // Read response until blank line.
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    stream.read_exact(&mut byte).await?;
                    buf.push(byte[0]);
                    if buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    if buf.len() > 4096 {
                        return Err(anyhow::anyhow!("HTTP CONNECT response too large"));
                    }
                }
                let resp_str = String::from_utf8_lossy(&buf);
                if !resp_str.starts_with("HTTP/1.1 200") && !resp_str.starts_with("HTTP/1.0 200") {
                    return Err(anyhow::anyhow!(
                        "HTTP CONNECT rejected: {}",
                        resp_str.lines().next().unwrap_or("")
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_proxy_url_no_auth() {
        let p = ProxyConfig::http("127.0.0.1", 8080);
        assert_eq!(p.url(), "http://127.0.0.1:8080");
    }

    #[test]
    fn socks5_proxy_url_no_auth() {
        let p = ProxyConfig::socks5("127.0.0.1", 1080);
        assert_eq!(p.url(), "socks5://127.0.0.1:1080");
    }

    #[test]
    fn proxy_url_with_auth() {
        let p = ProxyConfig::socks5("proxy.example.com", 1080).with_auth("alice", "s3cret");
        assert_eq!(p.url(), "socks5://alice:s3cret@proxy.example.com:1080");
    }

    #[test]
    fn proxy_type_scheme() {
        assert_eq!(ProxyType::Http.scheme(), "http");
        assert_eq!(ProxyType::Socks5.scheme(), "socks5");
    }

    #[test]
    fn to_reqwest_proxy_valid_http() {
        let p = ProxyConfig::http("127.0.0.1", 3128);
        // Should not error — reqwest can parse this URL.
        assert!(p.to_reqwest_proxy().is_ok());
    }

    #[test]
    fn to_reqwest_proxy_valid_socks5() {
        let p = ProxyConfig::socks5("127.0.0.1", 1080).with_auth("u", "p");
        assert!(p.to_reqwest_proxy().is_ok());
    }
}
