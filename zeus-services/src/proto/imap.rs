use crate::net::TcpConnection;
use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

static TAG_COUNTER: AtomicU32 = AtomicU32::new(1);

pub struct ImapProtocol;

#[async_trait]
impl Protocol for ImapProtocol {
    fn name(&self) -> &'static str {
        "imap"
    }
    fn default_port(&self) -> u16 {
        143
    }
    fn description(&self) -> &'static str {
        "IMAP LOGIN authentication"
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

        let tag = TAG_COUNTER.fetch_add(1, Ordering::Relaxed);
        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read server greeting "* OK ..."
        let greeting = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let g = String::from_utf8_lossy(&greeting);
        debug!("IMAP greeting: {:?}", g);

        if !g.contains("OK") {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("Not an IMAP server".into()));
        }

        // LOGIN command: A001 LOGIN "user" "pass"
        let login_cmd = format!(
            "A{:04} LOGIN \"{}\" \"{}\"\r\n",
            tag, cred.username, cred.password
        );
        conn.write_all(login_cmd.as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp_str = String::from_utf8_lossy(&resp);
        debug!("IMAP LOGIN resp: {:?}", resp_str);

        // Logout
        let logout_cmd = format!("A{:04} LOGOUT\r\n", tag + 1);
        let _ = conn.write_all(logout_cmd.as_bytes()).await;
        let _ = conn.shutdown().await;

        if resp_str.contains("OK") {
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
    fn imap_meta() {
        assert_eq!(ImapProtocol.name(), "imap");
        assert_eq!(ImapProtocol.default_port(), 143);
    }

    #[test]
    fn imap_description_not_empty() {
        assert!(!ImapProtocol.description().is_empty());
    }
}
