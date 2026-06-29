use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub tls: bool,
    pub path: Option<String>,
    pub options: HashMap<String, String>,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16, protocol: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            protocol: protocol.into(),
            tls: false,
            path: None,
            options: HashMap::new(),
        }
    }

    pub fn with_tls(mut self, tls: bool) -> Self { self.tls = tls; self }
    pub fn with_path(mut self, path: impl Into<String>) -> Self { self.path = Some(path.into()); self }
    pub fn with_option(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.insert(key.into(), value.into()); self
    }

    pub fn uri(&self) -> String {
        let scheme = if self.tls { format!("{}s", self.protocol) } else { self.protocol.clone() };
        let path = self.path.as_deref().unwrap_or("");
        format!("{}://{}:{}{}", scheme, self.host, self.port, path)
    }

    /// Parse a Target from a URL string like `proto://host:port/path`
    pub fn from_url(url: &str) -> Result<Self, crate::ZeusError> {
        let url = url.trim();
        // Split scheme
        let (scheme, rest) = url.split_once("://")
            .ok_or_else(|| crate::ZeusError::Config(format!("missing '://' in URL: {}", url)))?;

        // Detect TLS: scheme ends with 's' and base is known protocol
        let (protocol, tls) = if scheme.ends_with('s') && scheme.len() > 1 {
            (scheme[..scheme.len() - 1].to_string(), true)
        } else {
            (scheme.to_string(), false)
        };

        // Split path from host:port
        let (hostport, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], Some(rest[idx..].to_string())),
            None => (rest, None),
        };

        let (host, port_str) = hostport.rsplit_once(':')
            .ok_or_else(|| crate::ZeusError::Config(format!("missing port in URL: {}", url)))?;

        let port: u16 = port_str.parse()
            .map_err(|_| crate::ZeusError::Config(format!("invalid port '{}' in URL: {}", port_str, url)))?;

        let mut target = Self::new(host, port, protocol);
        target.tls = tls;
        target.path = path;
        Ok(target)
    }

    /// Validate that the host resolves in DNS.
    pub fn validate(&self) -> Result<(), crate::ZeusError> {
        use std::net::ToSocketAddrs;
        let addr = format!("{}:{}", self.host, self.port);
        addr.to_socket_addrs()
            .map_err(|e| crate::ZeusError::Network(e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_url_http() {
        let t = Target::from_url("http://example.com:80/login").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 80);
        assert_eq!(t.protocol, "http");
        assert!(!t.tls);
        assert_eq!(t.path.as_deref(), Some("/login"));
    }

    #[test]
    fn from_url_https_tls() {
        let t = Target::from_url("https://example.com:443").unwrap();
        assert_eq!(t.protocol, "http");
        assert!(t.tls);
        assert_eq!(t.port, 443);
    }

    #[test]
    fn from_url_ftp() {
        let t = Target::from_url("ftp://192.168.1.1:21").unwrap();
        assert_eq!(t.protocol, "ftp");
        assert_eq!(t.port, 21);
        assert!(!t.tls);
    }

    #[test]
    fn from_url_missing_scheme() {
        assert!(Target::from_url("example.com:80").is_err());
    }

    #[test]
    fn from_url_invalid_port() {
        assert!(Target::from_url("http://example.com:notaport").is_err());
    }

    #[test]
    fn with_option_builder() {
        let t = Target::new("host", 22, "ssh").with_option("timeout", "5");
        assert_eq!(t.options.get("timeout").map(String::as_str), Some("5"));
    }

    #[test]
    fn uri_plain() {
        let t = Target::new("192.168.1.1", 21, "ftp");
        assert_eq!(t.uri(), "ftp://192.168.1.1:21");
    }

    #[test]
    fn uri_tls_with_path() {
        let t = Target::new("example.com", 443, "http").with_tls(true).with_path("/admin/login");
        assert_eq!(t.uri(), "https://example.com:443/admin/login");
    }
}
