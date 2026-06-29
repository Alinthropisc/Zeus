use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct IrcProtocol;

#[async_trait]
impl Protocol for IrcProtocol {
    fn name(&self) -> &'static str { "irc" }
    fn default_port(&self) -> u16 { 6667 }
    fn description(&self) -> &'static str { "IRC OPER password authentication (RFC 1459)" }

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

        // Send NICK and USER handshake
        let nick = format!("zeus{}", std::process::id() % 9999);
        conn.write_all(format!("NICK {}\r\nUSER {} 0 * :zeus\r\n", nick, nick).as_bytes()).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read server responses (skip multiple lines until 001 welcome or ERROR)
        let mut welcomed = false;
        for _ in 0..20 {
            let line = match conn.read_until_crlf().await {
                Ok(l) => l,
                Err(_) => break,
            };
            let s = String::from_utf8_lossy(&line);
            debug!("IRC: {:?}", s);
            if s.contains(" 001 ") { welcomed = true; break; }
            if s.starts_with("ERROR") { break; }
        }

        if !welcomed {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("IRC registration failed".into()));
        }

        // OPER login pass
        conn.write_all(format!("OPER {} {}\r\n", cred.username, cred.password).as_bytes()).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read OPER response: 381 = success, 464 = invalid password
        let resp = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp_str = String::from_utf8_lossy(&resp);
        debug!("IRC OPER resp: {:?}", resp_str);

        let _ = conn.write_all(b"QUIT\r\n").await;
        let _ = conn.shutdown().await;

        if resp_str.contains(" 381 ") {
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
    fn irc_meta() {
        assert_eq!(IrcProtocol.name(), "irc");
        assert_eq!(IrcProtocol.default_port(), 6667);
    }
}
