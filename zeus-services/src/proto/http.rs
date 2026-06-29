//! HTTP/HTTPS form-based authentication.
//!
//! Template Method pattern: `authenticate` calls hook methods that subclasses
//! can override (here kept simple with configurable field names).

use anyhow::Result;
use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, warn};
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct HttpProtocol {
    client: Client,
}

impl HttpProtocol {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .danger_accept_invalid_certs(false)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()?;
        Ok(Self { client })
    }
}

impl Default for HttpProtocol {
    fn default() -> Self { Self::new().expect("HTTP client init failed") }
}

#[async_trait]
impl Protocol for HttpProtocol {
    fn name(&self) -> &'static str { "http" }
    fn default_port(&self) -> u16 { 80 }
    fn description(&self) -> &'static str { "HTTP/HTTPS form-based login" }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let scheme = if target.tls { "https" } else { "http" };
        let path = target.path.as_deref().unwrap_or("/");
        let url = format!("{}://{}:{}{}", scheme, target.host, target.port, path);

        let user_field = target.options.get("user_field").map(String::as_str).unwrap_or("username");
        let pass_field = target.options.get("pass_field").map(String::as_str).unwrap_or("password");
        let fail_str = target.options.get("fail_str").map(String::as_str).unwrap_or("Invalid");

        let mut form = HashMap::new();
        form.insert(user_field, cred.username.as_str());
        form.insert(pass_field, cred.password.as_str());

        debug!("HTTP POST {} as {}", url, cred.username);

        let resp = tokio::time::timeout(config.timeout, self.client.post(&url).form(&form).send())
            .await
            .map_err(|_| ZeusError::Timeout(config.timeout))?
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status == StatusCode::TOO_MANY_REQUESTS {
            warn!("Rate limited by {}", target.host);
            return Ok(AttackResult::RateLimit);
        }

        if body.contains(fail_str) || status == StatusCode::UNAUTHORIZED {
            return Ok(AttackResult::Failure);
        }

        if status.is_success() || status.is_redirection() {
            return Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: std::time::Duration::ZERO,
            });
        }

        Ok(AttackResult::Failure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_name() {
        let p = HttpProtocol::default();
        assert_eq!(p.name(), "http");
        assert_eq!(p.default_port(), 80);
    }
}
