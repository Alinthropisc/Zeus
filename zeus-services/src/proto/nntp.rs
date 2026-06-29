use crate::net::TcpConnection;
use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct NntpProtocol;

#[async_trait]
impl Protocol for NntpProtocol {
    fn name(&self) -> &'static str {
        "nntp"
    }
    fn default_port(&self) -> u16 {
        119
    }
    fn description(&self) -> &'static str {
        "NNTP AUTHINFO USER/PASS authentication"
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

        // Read greeting "200 ..." or "201 ..."
        let greeting = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("NNTP greeting: {:?}", String::from_utf8_lossy(&greeting));

        // AUTHINFO USER
        conn.write_all(format!("AUTHINFO USER {}\r\n", cred.username).as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let user_resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let user_str = String::from_utf8_lossy(&user_resp);
        debug!("NNTP USER resp: {:?}", user_str);

        // 381 = need password, anything else = failure
        if !user_str.starts_with("381") {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Failure);
        }

        // AUTHINFO PASS
        conn.write_all(format!("AUTHINFO PASS {}\r\n", cred.password).as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let pass_resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let pass_str = String::from_utf8_lossy(&pass_resp);
        debug!("NNTP PASS resp: {:?}", pass_str);

        let _ = conn.write_all(b"QUIT\r\n").await;
        let _ = conn.shutdown().await;

        // 281 = authenticated
        if pass_str.starts_with("281") {
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
    fn nntp_meta() {
        assert_eq!(NntpProtocol.name(), "nntp");
        assert_eq!(NntpProtocol.default_port(), 119);
    }

    #[test]
    fn nntp_description_not_empty() {
        assert!(!NntpProtocol.description().is_empty());
    }
}
