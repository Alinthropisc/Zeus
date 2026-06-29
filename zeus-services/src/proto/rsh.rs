use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct RshProtocol;

#[async_trait]
impl Protocol for RshProtocol {
    fn name(&self) -> &'static str { "rsh" }
    fn default_port(&self) -> u16 { 514 }
    fn description(&self) -> &'static str { "RSH remote shell authentication" }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let addr_str = format!("{}:{}", target.host, target.port);
        let addr = addr_str.to_socket_addrs().map_err(ZeusError::Network)?
            .next().ok_or_else(|| ZeusError::Protocol("DNS failed".into()))?;

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // RSH handshake: null-byte, local_user\0, remote_user\0, command\0
        let mut packet = Vec::new();
        packet.push(0u8);  // null byte for stderr port (0 = no stderr)
        packet.extend_from_slice(cred.username.as_bytes());
        packet.push(0);
        packet.extend_from_slice(cred.username.as_bytes());
        packet.push(0);
        packet.extend_from_slice(b"id");  // command to run
        packet.push(0);

        conn.write_all(&packet).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let resp = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp_str = String::from_utf8_lossy(&resp);
        debug!("RSH resp: {:?}", resp_str);

        let _ = conn.shutdown().await;

        // RSH returns empty byte on success, error message otherwise
        if resp.is_empty() || resp[0] == 0 {
            Ok(AttackResult::Success { credential: cred.clone(), elapsed: start.elapsed() })
        } else if resp_str.contains("Permission denied") || resp_str.contains("denied") {
            Ok(AttackResult::Failure)
        } else {
            // Got a response (could be command output = success)
            Ok(AttackResult::Success { credential: cred.clone(), elapsed: start.elapsed() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rsh_meta() {
        assert_eq!(RshProtocol.name(), "rsh");
        assert_eq!(RshProtocol.default_port(), 514);
    }
}
