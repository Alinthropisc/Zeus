//! Telnet password authentication.

use crate::net::TcpConnection;
use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct TelnetProtocol;

#[async_trait]
impl Protocol for TelnetProtocol {
    fn name(&self) -> &'static str {
        "telnet"
    }
    fn default_port(&self) -> u16 {
        23
    }
    fn description(&self) -> &'static str {
        "Telnet login prompt"
    }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let addr_str = format!("{}:{}", target.host, target.port);
        let addr = addr_str
            .to_socket_addrs()
            .map_err(|e| ZeusError::Network(e))?
            .next()
            .ok_or_else(|| ZeusError::Protocol("DNS failed".into()))?;

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read login prompt
        let prompt = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("Telnet prompt: {:?}", String::from_utf8_lossy(&prompt));

        // Send username
        conn.write_all(format!("{}\r\n", cred.username).as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read password prompt
        conn.read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Send password
        conn.write_all(format!("{}\r\n", cred.password).as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read response
        let resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp_str = String::from_utf8_lossy(&resp).to_lowercase();

        let _ = conn.shutdown().await;

        if resp_str.contains("login incorrect") || resp_str.contains("failed") {
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
    fn telnet_meta() {
        assert_eq!(TelnetProtocol.name(), "telnet");
    }
}
