//! FTP protocol — raw TCP banner + USER/PASS commands.

use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct FtpProtocol;

#[async_trait]
impl Protocol for FtpProtocol {
    fn name(&self) -> &'static str { "ftp" }
    fn default_port(&self) -> u16 { 21 }
    fn description(&self) -> &'static str { "FTP authentication" }

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
            .ok_or_else(|| ZeusError::Protocol("DNS resolution failed".into()))?;

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read banner (220 ...)
        let banner = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("FTP banner: {:?}", String::from_utf8_lossy(&banner));

        // Send USER
        let user_cmd = format!("USER {}\r\n", cred.username);
        conn.write_all(user_cmd.as_bytes()).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let user_resp = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("FTP USER resp: {:?}", String::from_utf8_lossy(&user_resp));

        // Send PASS
        let pass_cmd = format!("PASS {}\r\n", cred.password);
        conn.write_all(pass_cmd.as_bytes()).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let pass_resp = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp_str = String::from_utf8_lossy(&pass_resp);
        debug!("FTP PASS resp: {:?}", resp_str);

        let _ = conn.shutdown().await;

        if resp_str.starts_with("230") {
            Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            })
        } else if resp_str.starts_with("421") || resp_str.starts_with("530") {
            Ok(AttackResult::Failure)
        } else {
            Ok(AttackResult::Failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ftp_meta() {
        let p = FtpProtocol;
        assert_eq!(p.name(), "ftp");
        assert_eq!(p.default_port(), 21);
    }
}
