use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct SvnProtocol {
    client: Client,
}

impl Default for SvnProtocol {
    fn default() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .expect("SVN client");
        Self { client }
    }
}

#[async_trait]
impl Protocol for SvnProtocol {
    fn name(&self) -> &'static str { "svn" }
    fn default_port(&self) -> u16 { 3690 }
    fn description(&self) -> &'static str { "Subversion HTTP authentication (port 3690 or 80/443 via mod_dav_svn)" }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let scheme = if target.tls { "https" } else { "http" };
        let path = target.path.as_deref().unwrap_or("/svn");
        let url = format!("{}://{}:{}{}", scheme, target.host, target.port, path);
        debug!("SVN: {} as {}", url, cred.username);

        let start = std::time::Instant::now();
        let resp = tokio::time::timeout(config.timeout, async {
            self.client
                .get(&url)
                .basic_auth(&cred.username, Some(&cred.password))
                .send()
                .await
        })
        .await
        .map_err(|_| ZeusError::Timeout(config.timeout))?
        .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let status = resp.status();
        debug!("SVN resp: {}", status);

        if status.is_success() || status.as_u16() == 301 {
            Ok(AttackResult::Success { credential: cred.clone(), elapsed: start.elapsed() })
        } else {
            Ok(AttackResult::Failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn svn_meta() {
        assert_eq!(SvnProtocol::default().name(), "svn");
    }
}
