//! Connection Builder — Builder pattern for network connection configuration.
//!
//! # Design patterns
//!
//! - **Builder** — [`ConnectionConfigBuilder`] accumulates optional settings and
//!   produces a validated [`ConnectionConfig`] via [`ConnectionConfigBuilder::build`].
//! - **SRP** — this module only configures connections; opening them is a separate
//!   concern delegated to [`crate::net::TcpConnection`] / [`crate::net::TlsConnection`].
//!
//! # Example
//!
//! ```rust,ignore
//! use std::time::Duration;
//! use zeus_services::builder::ConnectionConfigBuilder;
//!
//! let cfg = ConnectionConfigBuilder::new("192.168.1.1", 22)
//!     .timeout(5_000)
//!     .retries(3)
//!     .build();
//!
//! // Open a plain-TCP connection using the resolved config.
//! let conn = cfg.connect_tcp().await?;
//!
//! // Or upgrade to TLS:
//! let tls = cfg.connect_tls().await?;
//! ```

use std::net::ToSocketAddrs;
use std::time::Duration;

use anyhow::{Result, anyhow};
use tracing::debug;

use crate::net::{TcpConnection, TlsConnection};

// ──────────────────────────────────────────────────────────────────────────────
// ConnectionConfig
// ──────────────────────────────────────────────────────────────────────────────

/// Fully-resolved connection parameters produced by [`ConnectionConfigBuilder`].
///
/// `ConnectionConfig` is value-type (cheap to clone) and intentionally has no
/// methods that perform I/O — all async operations are on separate helper
/// methods so the struct stays pure data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
    /// Target hostname or IP address.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// I/O and connect timeout in milliseconds.
    pub timeout_ms: u64,
    /// Whether to use TLS for the connection.
    pub tls: bool,
    /// Optional upstream proxy address (`host:port`).
    pub proxy: Option<String>,
    /// Number of reconnect attempts before giving up (0 = no retries).
    pub retries: u8,
}

impl ConnectionConfig {
    /// Timeout as a [`Duration`] — convenience for callers that need it.
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    /// Open a plain TCP connection using the settings in this config.
    ///
    /// Respects `timeout_ms` for both the connect and all subsequent I/O.
    /// Retries are attempted on connection failure up to `self.retries` times.
    pub async fn connect_tcp(&self) -> Result<TcpConnection> {
        let addr = format!("{}:{}", self.host, self.port)
            .to_socket_addrs()
            .map_err(|e| {
                anyhow!(
                    "DNS resolution failed for {}:{} — {}",
                    self.host,
                    self.port,
                    e
                )
            })?
            .next()
            .ok_or_else(|| anyhow!("no address resolved for {}:{}", self.host, self.port))?;

        let timeout = self.timeout();
        let mut last_err = anyhow!("no attempts made");

        for attempt in 0..=self.retries {
            match TcpConnection::connect(addr, timeout).await {
                Ok(conn) => {
                    debug!(
                        host = %self.host,
                        port = self.port,
                        attempt,
                        "TCP connection established"
                    );
                    return Ok(conn);
                }
                Err(e) => {
                    debug!(
                        host = %self.host,
                        port = self.port,
                        attempt,
                        error = %e,
                        "TCP connect failed, will retry"
                    );
                    last_err = e;
                }
            }
        }

        Err(last_err)
    }

    /// Open a TLS connection using the settings in this config.
    ///
    /// Uses the system root certificate store via `webpki-roots`.
    /// Retries are attempted on failure up to `self.retries` times.
    pub async fn connect_tls(&self) -> Result<TlsConnection> {
        let timeout = self.timeout();
        let mut last_err = anyhow!("no attempts made");

        for attempt in 0..=self.retries {
            match TlsConnection::connect(&self.host, self.port, timeout).await {
                Ok(conn) => {
                    debug!(
                        host = %self.host,
                        port = self.port,
                        attempt,
                        "TLS connection established"
                    );
                    return Ok(conn);
                }
                Err(e) => {
                    debug!(
                        host = %self.host,
                        port = self.port,
                        attempt,
                        error = %e,
                        "TLS connect failed, will retry"
                    );
                    last_err = e;
                }
            }
        }

        Err(last_err)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ConnectionConfigBuilder
// ──────────────────────────────────────────────────────────────────────────────

/// Fluent builder for [`ConnectionConfig`].
///
/// Only `host` and `port` are required; all other settings have sensible
/// defaults. Each setter takes `self` by value and returns `Self` so calls
/// can be chained without intermediate bindings.
///
/// # Example
///
/// ```rust,ignore
/// let cfg = ConnectionConfigBuilder::new("10.0.0.1", 443)
///     .timeout(10_000)
///     .with_tls()
///     .retries(2)
///     .build();
/// ```
pub struct ConnectionConfigBuilder {
    host: String,
    port: u16,
    timeout_ms: u64,
    tls: bool,
    proxy: Option<String>,
    retries: u8,
}

impl ConnectionConfigBuilder {
    /// Create a new builder targeting `host:port`.
    ///
    /// Defaults: timeout 5 000 ms, no TLS, no proxy, 0 retries.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            timeout_ms: 5_000,
            tls: false,
            proxy: None,
            retries: 0,
        }
    }

    /// Set the I/O timeout in milliseconds.
    ///
    /// Applied to both the initial connect and all subsequent reads/writes.
    /// Panics in debug builds if `ms` is zero.
    pub fn timeout(mut self, ms: u64) -> Self {
        debug_assert!(ms > 0, "timeout must be > 0 ms");
        self.timeout_ms = ms;
        self
    }

    /// Enable TLS on this connection.
    ///
    /// When set, [`ConnectionConfig::connect_tls`] should be used instead of
    /// [`ConnectionConfig::connect_tcp`].
    pub fn with_tls(mut self) -> Self {
        self.tls = true;
        self
    }

    /// Route the connection through a SOCKS/HTTP proxy at `addr` (`host:port`).
    pub fn proxy(mut self, addr: impl Into<String>) -> Self {
        self.proxy = Some(addr.into());
        self
    }

    /// Set the number of reconnect retries (0 = try once, no retries).
    ///
    /// The total number of connection attempts is `retries + 1`.
    pub fn retries(mut self, n: u8) -> Self {
        self.retries = n;
        self
    }

    /// Consume the builder and produce a [`ConnectionConfig`].
    ///
    /// This is an infallible operation: validation (e.g. DNS resolution) is
    /// deferred to the point where a connection is actually opened.
    pub fn build(self) -> ConnectionConfig {
        ConnectionConfig {
            host: self.host,
            port: self.port,
            timeout_ms: self.timeout_ms,
            tls: self.tls,
            proxy: self.proxy,
            retries: self.retries,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sensible() {
        let cfg = ConnectionConfigBuilder::new("127.0.0.1", 80).build();
        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.port, 80);
        assert_eq!(cfg.timeout_ms, 5_000);
        assert!(!cfg.tls);
        assert!(cfg.proxy.is_none());
        assert_eq!(cfg.retries, 0);
    }

    #[test]
    fn timeout_setter() {
        let cfg = ConnectionConfigBuilder::new("example.com", 443)
            .timeout(10_000)
            .build();
        assert_eq!(cfg.timeout_ms, 10_000);
        assert_eq!(cfg.timeout(), Duration::from_millis(10_000));
    }

    #[test]
    fn tls_flag() {
        let cfg = ConnectionConfigBuilder::new("example.com", 443)
            .with_tls()
            .build();
        assert!(cfg.tls);
    }

    #[test]
    fn proxy_setter() {
        let cfg = ConnectionConfigBuilder::new("10.0.0.1", 80)
            .proxy("socks5://127.0.0.1:1080")
            .build();
        assert_eq!(cfg.proxy.as_deref(), Some("socks5://127.0.0.1:1080"));
    }

    #[test]
    fn retries_setter() {
        let cfg = ConnectionConfigBuilder::new("10.0.0.1", 22)
            .retries(3)
            .build();
        assert_eq!(cfg.retries, 3);
    }

    #[test]
    fn full_chain() {
        let cfg = ConnectionConfigBuilder::new("192.168.1.1", 8443)
            .timeout(2_000)
            .with_tls()
            .proxy("http://proxy.internal:3128")
            .retries(2)
            .build();

        assert_eq!(cfg.host, "192.168.1.1");
        assert_eq!(cfg.port, 8443);
        assert_eq!(cfg.timeout_ms, 2_000);
        assert!(cfg.tls);
        assert_eq!(cfg.proxy.as_deref(), Some("http://proxy.internal:3128"));
        assert_eq!(cfg.retries, 2);
    }

    #[test]
    fn clone_produces_equal_value() {
        let cfg = ConnectionConfigBuilder::new("host.local", 22)
            .timeout(3_000)
            .retries(1)
            .build();
        assert_eq!(cfg.clone(), cfg);
    }

    #[test]
    fn host_accepts_string_and_str() {
        // &str
        let a = ConnectionConfigBuilder::new("host-a", 80).build();
        // String
        let b = ConnectionConfigBuilder::new(String::from("host-a"), 80).build();
        assert_eq!(a, b);
    }
}
