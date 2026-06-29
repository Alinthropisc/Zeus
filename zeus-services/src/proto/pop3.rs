use crate::net::TcpConnection;
use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct Pop3Protocol;

#[async_trait]
impl Protocol for Pop3Protocol {
    fn name(&self) -> &'static str {
        "pop3"
    }
    fn default_port(&self) -> u16 {
        110
    }
    fn description(&self) -> &'static str {
        "POP3 USER/PASS authentication"
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

        // Read greeting "+OK ..."
        let greeting = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let greeting_str = String::from_utf8_lossy(&greeting);
        debug!("POP3 greeting: {:?}", greeting_str);

        if !greeting_str.starts_with("+OK") {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("Not a POP3 server".into()));
        }

        // USER command
        conn.write_all(format!("USER {}\r\n", cred.username).as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let user_resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let user_str = String::from_utf8_lossy(&user_resp);
        debug!("POP3 USER resp: {:?}", user_str);

        if !user_str.starts_with("+OK") {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Failure);
        }

        // PASS command
        conn.write_all(format!("PASS {}\r\n", cred.password).as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let pass_resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let pass_str = String::from_utf8_lossy(&pass_resp);
        debug!("POP3 PASS resp: {:?}", pass_str);

        // Quit cleanly
        let _ = conn.write_all(b"QUIT\r\n").await;
        let _ = conn.shutdown().await;

        if pass_str.starts_with("+OK") {
            Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            })
        } else if pass_str.contains("-ERR") && pass_str.to_lowercase().contains("lock") {
            Ok(AttackResult::Error("Mailbox locked".into()))
        } else {
            Ok(AttackResult::Failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pop3_meta() {
        assert_eq!(Pop3Protocol.name(), "pop3");
        assert_eq!(Pop3Protocol.default_port(), 110);
    }

    #[test]
    fn pop3_description_not_empty() {
        assert!(!Pop3Protocol.description().is_empty());
    }
}
