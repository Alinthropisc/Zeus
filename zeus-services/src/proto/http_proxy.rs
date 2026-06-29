use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::{Client, StatusCode};
use std::time::Duration;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct HttpProxyProtocol {
    client: Client,
}

impl HttpProxyProtocol {
    pub fn new() -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { client })
    }
}

impl Default for HttpProxyProtocol {
    fn default() -> Self {
        Self::new().expect("HTTP proxy client")
    }
}

#[async_trait]
impl Protocol for HttpProxyProtocol {
    fn name(&self) -> &'static str {
        "http-proxy"
    }
    fn default_port(&self) -> u16 {
        3128
    }
    fn description(&self) -> &'static str {
        "HTTP proxy Basic authentication"
    }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let proxy_url = format!("http://{}:{}", target.host, target.port);
        let credentials = format!("{}:{}", cred.username, cred.password);
        let auth = format!("Basic {}", BASE64.encode(credentials.as_bytes()));

        // Try to CONNECT through the proxy with Proxy-Authorization header
        let test_url = target
            .options
            .get("test_url")
            .map(String::as_str)
            .unwrap_or("http://www.google.com");

        debug!("HTTP-PROXY {} auth for {}", proxy_url, cred.username);

        let start = std::time::Instant::now();
        let resp = tokio::time::timeout(config.timeout, async {
            self.client
                .get(test_url)
                .header("Proxy-Authorization", &auth)
                .send()
                .await
        })
        .await
        .map_err(|_| ZeusError::Timeout(config.timeout))?
        .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let status = resp.status();
        debug!("HTTP-PROXY resp: {}", status);

        if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
            Ok(AttackResult::Failure)
        } else if status == StatusCode::FORBIDDEN {
            Ok(AttackResult::Failure)
        } else {
            Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proxy_meta() {
        let p = HttpProxyProtocol::default();
        assert_eq!(p.name(), "http-proxy");
        assert_eq!(p.default_port(), 3128);
    }
}
