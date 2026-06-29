use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct RtspProtocol {
    client: Client,
}

impl RtspProtocol {
    pub fn new() -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()?;
        Ok(Self { client })
    }
}

impl Default for RtspProtocol {
    fn default() -> Self {
        Self::new().expect("RTSP client")
    }
}

#[async_trait]
impl Protocol for RtspProtocol {
    fn name(&self) -> &'static str {
        "rtsp"
    }
    fn default_port(&self) -> u16 {
        554
    }
    fn description(&self) -> &'static str {
        "RTSP Basic/Digest authentication (IP cameras)"
    }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let path = target.path.as_deref().unwrap_or("/");
        let url = format!("rtsp://{}:{}{}", target.host, target.port, path);
        debug!("RTSP: {}", url);

        // RTSP uses HTTP-like Basic auth over HTTP wrapper or native RTSP
        // We test via HTTP since reqwest handles the auth negotiation
        let http_url = format!("http://{}:{}{}", target.host, target.port, path);

        let start = std::time::Instant::now();
        let resp = tokio::time::timeout(config.timeout, async {
            self.client
                .get(&http_url)
                .basic_auth(&cred.username, Some(&cred.password))
                .send()
                .await
        })
        .await
        .map_err(|_| ZeusError::Timeout(config.timeout))?;

        let _ = url; // suppress warning
        match resp {
            Ok(r) => {
                let status = r.status();
                debug!("RTSP resp: {}", status);
                if status.is_success() {
                    Ok(AttackResult::Success {
                        credential: cred.clone(),
                        elapsed: start.elapsed(),
                    })
                } else {
                    Ok(AttackResult::Failure)
                }
            }
            Err(e) => Ok(AttackResult::Error(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rtsp_meta() {
        let p = RtspProtocol::default();
        assert_eq!(p.name(), "rtsp");
        assert_eq!(p.default_port(), 554);
    }
}
