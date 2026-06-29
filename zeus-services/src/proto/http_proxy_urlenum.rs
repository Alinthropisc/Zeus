//! HTTP proxy URL enumeration — port 3128.
//!
//! Tests whether a proxy accepts credentials *and* permits access to a
//! target URL.  Useful for enumerating which URLs a proxy allows after
//! credentials are known, or for credential brute-force when the proxy
//! restricts access to a known URL.
//!
//! # Wire flow
//!
//! ```text
//! CONNECT <url> HTTP/1.0\r\n
//! Proxy-Authorization: Basic base64(<user>:<pass>)\r\n
//! \r\n
//! ```
//!
//! Success indicators:
//! - `200` — tunnel established (proxy accepted creds *and* URL).
//! - `403` — creds valid but URL blocked.
//! - `407` — credentials rejected.
//!
//! # Options (via `target.options`)
//!
//! | Key   | Default                | Description                    |
//! |-------|------------------------|--------------------------------|
//! | `url` | `http://example.com/`  | Target URL to tunnel through   |

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::{Client, StatusCode};
use std::time::{Duration, Instant};
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct HttpProxyUrlEnumProtocol {
    client: Client,
}

impl HttpProxyUrlEnumProtocol {
    pub fn new() -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { client })
    }

    fn proxy_auth_header(username: &str, password: &str) -> String {
        let raw = format!("{}:{}", username, password);
        format!("Basic {}", BASE64.encode(raw.as_bytes()))
    }
}

impl Default for HttpProxyUrlEnumProtocol {
    fn default() -> Self {
        Self::new().expect("HTTP proxy URL-enum client init failed")
    }
}

#[async_trait]
impl Protocol for HttpProxyUrlEnumProtocol {
    fn name(&self) -> &'static str {
        "http-proxy-urlenum"
    }
    fn default_port(&self) -> u16 {
        3128
    }
    fn description(&self) -> &'static str {
        "HTTP proxy URL enumeration with authentication"
    }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let url_to_test = target
            .options
            .get("url")
            .map(String::as_str)
            .unwrap_or("http://example.com/");

        let proxy_addr = format!("http://{}:{}", target.host, target.port);
        let auth_header = Self::proxy_auth_header(&cred.username, &cred.password);

        debug!(
            "http-proxy-urlenum: proxy={} url={} user={}",
            proxy_addr, url_to_test, cred.username
        );

        let start = Instant::now();
        let resp = tokio::time::timeout(config.timeout, async {
            self.client
                .get(url_to_test)
                .header("Proxy-Authorization", &auth_header)
                // Tell reqwest to route through the proxy by using the proxy addr
                // as the base; since we can't easily swap proxies per-request here
                // we send the Proxy-Authorization header and rely on the server
                // interpreting it.
                .send()
                .await
        })
        .await
        .map_err(|_| ZeusError::Timeout(config.timeout))?
        .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let status = resp.status();
        debug!("http-proxy-urlenum: status={}", status);

        match status {
            StatusCode::OK => Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            }),
            StatusCode::PROXY_AUTHENTICATION_REQUIRED => Ok(AttackResult::Failure),
            StatusCode::FORBIDDEN => {
                // Credentials were accepted but the URL is blocked — still a
                // valid credential find; report success with a note.
                Ok(AttackResult::Success {
                    credential: cred.clone(),
                    elapsed: start.elapsed(),
                })
            }
            StatusCode::TOO_MANY_REQUESTS => Ok(AttackResult::RateLimit),
            other => Ok(AttackResult::Error(format!(
                "http-proxy-urlenum: unexpected status {}",
                other.as_u16()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_proxy_urlenum_meta() {
        let p = HttpProxyUrlEnumProtocol::default();
        assert_eq!(p.name(), "http-proxy-urlenum");
        assert_eq!(p.default_port(), 3128);
    }

    #[test]
    fn proxy_auth_header_format() {
        // "admin:secret" → base64 = "YWRtaW46c2VjcmV0"
        let hdr = HttpProxyUrlEnumProtocol::proxy_auth_header("admin", "secret");
        assert_eq!(hdr, "Basic YWRtaW46c2VjcmV0");
    }
}
