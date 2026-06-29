use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, warn};
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct HttpFormProtocol {
    client: Client,
}

impl HttpFormProtocol {
    pub fn new() -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;
        Ok(Self { client })
    }
}

impl Default for HttpFormProtocol {
    fn default() -> Self {
        Self::new().expect("HTTP client init")
    }
}

#[async_trait]
impl Protocol for HttpFormProtocol {
    fn name(&self) -> &'static str {
        "http-form"
    }
    fn default_port(&self) -> u16 {
        80
    }
    fn description(&self) -> &'static str {
        "HTTP/HTTPS form login (POST/GET). Options: user_field, pass_field, fail_str, ok_str, method"
    }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let scheme = if target.tls { "https" } else { "http" };
        let path = target.path.as_deref().unwrap_or("/");
        let url = format!("{}://{}:{}{}", scheme, target.host, target.port, path);

        let user_field = target
            .options
            .get("user_field")
            .map(String::as_str)
            .unwrap_or("username");
        let pass_field = target
            .options
            .get("pass_field")
            .map(String::as_str)
            .unwrap_or("password");
        let fail_str = target.options.get("fail_str").map(String::as_str);
        let ok_str = target.options.get("ok_str").map(String::as_str);
        let method = target
            .options
            .get("method")
            .map(String::as_str)
            .unwrap_or("POST");

        let mut form = HashMap::new();
        form.insert(user_field.to_owned(), cred.username.clone());
        form.insert(pass_field.to_owned(), cred.password.clone());

        // Add any extra fields from options (prefix "field_")
        for (k, v) in &target.options {
            if k.starts_with("field_") {
                form.insert(k.trim_start_matches("field_").to_owned(), v.clone());
            }
        }

        debug!("{} {} as {}", method, url, cred.username);

        let start = std::time::Instant::now();
        let resp = tokio::time::timeout(config.timeout, async {
            if method.eq_ignore_ascii_case("GET") {
                self.client.get(&url).query(&form).send().await
            } else {
                self.client.post(&url).form(&form).send().await
            }
        })
        .await
        .map_err(|_| ZeusError::Timeout(config.timeout))?
        .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status == StatusCode::TOO_MANY_REQUESTS {
            warn!("Rate limited by {}", target.host);
            return Ok(AttackResult::RateLimit);
        }

        // ok_str takes priority (explicit success indicator)
        if let Some(ok) = ok_str
            && body.contains(ok)
        {
            return Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            });
        }

        // fail_str = known failure indicator
        if let Some(fail) = fail_str {
            if body.contains(fail) {
                return Ok(AttackResult::Failure);
            }
            // If fail_str not found and no error status, assume success
            if status.is_success() || status.is_redirection() {
                return Ok(AttackResult::Success {
                    credential: cred.clone(),
                    elapsed: start.elapsed(),
                });
            }
        }

        // Fallback heuristics
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Ok(AttackResult::Failure);
        }
        if status.is_success() || status.is_redirection() {
            return Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            });
        }

        Ok(AttackResult::Failure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn http_form_meta() {
        let p = HttpFormProtocol::default();
        assert_eq!(p.name(), "http-form");
    }
}
