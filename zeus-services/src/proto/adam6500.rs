//! Advantech Adam 6500 series industrial I/O module — HTTP Basic authentication.
//!
//! The Adam 6500 family exposes a simple web interface (port 80) protected by
//! HTTP Basic Auth.  A successful login returns HTTP 200 with a body that
//! contains device-specific strings ("Adam", "ADAM", or "Advantech").
//! An HTTP 401 means the credentials were rejected.

use crate::net::HttpClient;
use async_trait::async_trait;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct Adam6500Protocol;

#[async_trait]
impl Protocol for Adam6500Protocol {
    fn name(&self) -> &'static str {
        "adam6500"
    }
    fn default_port(&self) -> u16 {
        80
    }
    fn description(&self) -> &'static str {
        "Advantech Adam 6500 series I/O module HTTP authentication"
    }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let scheme = if target.tls { "https" } else { "http" };
        let base_url = format!("{}://{}:{}", scheme, target.host, target.port);

        let client = HttpClient::new(base_url, config.timeout)
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Primary probe path; fall back to /Adam/index.html if the option is set.
        let path = target
            .options
            .get("path")
            .map(String::as_str)
            .unwrap_or("/");

        debug!("Adam6500 GET {} as {}", path, cred.username);

        let start = Instant::now();
        let (status, body) = client
            .get_basic_auth(path, &cred.username, &cred.password)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        debug!("Adam6500 status={} body_len={}", status, body.len());

        match status {
            200 => {
                // The device page contains recognisable Advantech / Adam strings.
                let body_lc = body.to_ascii_lowercase();
                let device_hint = body_lc.contains("adam")
                    || body_lc.contains("advantech")
                    || body_lc.contains("i/o module")
                    || body_lc.contains("digital output")
                    || body_lc.contains("analog input");

                if device_hint {
                    Ok(AttackResult::Success {
                        credential: cred.clone(),
                        elapsed: start.elapsed(),
                    })
                } else {
                    // 200 but no device fingerprint — treat as ambiguous failure.
                    debug!("Adam6500: 200 but no device strings in body — treating as failure");
                    Ok(AttackResult::Failure)
                }
            }
            401 => Ok(AttackResult::Failure),
            429 => Ok(AttackResult::RateLimit),
            other => Ok(AttackResult::Error(format!(
                "Adam6500: unexpected HTTP status {}",
                other
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adam6500_meta() {
        assert_eq!(Adam6500Protocol.name(), "adam6500");
        assert_eq!(Adam6500Protocol.default_port(), 80);
    }

    #[test]
    fn adam6500_description_not_empty() {
        assert!(!Adam6500Protocol.description().is_empty());
    }
}
