use crate::net::TcpConnection;
use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct RexecProtocol;

#[async_trait]
impl Protocol for RexecProtocol {
    fn name(&self) -> &'static str {
        "rexec"
    }
    fn default_port(&self) -> u16 {
        512
    }
    fn description(&self) -> &'static str {
        "REXEC remote execution authentication"
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
            .map_err(ZeusError::Network)?
            .next()
            .ok_or_else(|| ZeusError::Protocol("DNS failed".into()))?;

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // REXEC: send 0\0 (no stderr port), user\0, password\0, command\0
        let mut packet = Vec::new();
        packet.push(0u8);
        packet.extend_from_slice(cred.username.as_bytes());
        packet.push(0);
        packet.extend_from_slice(cred.password.as_bytes());
        packet.push(0);
        packet.extend_from_slice(b"id");
        packet.push(0);

        conn.write_all(&packet)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp_str = String::from_utf8_lossy(&resp);
        debug!("REXEC resp: {:?}", resp_str);

        let _ = conn.shutdown().await;

        if resp.is_empty() || resp[0] == 0 {
            Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            })
        } else if resp_str.contains("Login incorrect") || resp_str.contains("permission") {
            Ok(AttackResult::Failure)
        } else if resp_str.len() > 1 {
            // Got command output = authenticated
            Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            })
        } else {
            Ok(AttackResult::Failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rexec_meta() {
        assert_eq!(RexecProtocol.name(), "rexec");
        assert_eq!(RexecProtocol.default_port(), 512);
    }
}
