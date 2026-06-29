//! Cisco IOS Telnet password authentication (port 23).

use async_trait::async_trait;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

use crate::resolve_addr;

pub struct CiscoProtocol;

#[async_trait]
impl Protocol for CiscoProtocol {
    fn name(&self) -> &'static str { "cisco" }
    fn default_port(&self) -> u16 { 23 }
    fn description(&self) -> &'static str { "Cisco IOS Telnet password authentication" }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let addr = resolve_addr(&target.host, target.port)?;
        let start = Instant::now();

        let mut conn = TcpConnection::connect(addr, config.timeout).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read until we see a Password: prompt
        let prompt = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let prompt_str = String::from_utf8_lossy(&strip_iac(&prompt)).to_lowercase();
        debug!("Cisco prompt: {:?}", prompt_str);

        // Some devices send IAC negotiation before the password prompt; keep reading
        // until we actually see "password"
        let mut prompt_str = prompt_str;
        let mut attempts = 0;
        while !prompt_str.contains("password") && attempts < 8 {
            let next = conn.read_until_crlf().await
                .map_err(|e| ZeusError::Protocol(e.to_string()))?;
            prompt_str = String::from_utf8_lossy(&strip_iac(&next)).to_lowercase();
            debug!("Cisco prompt read: {:?}", prompt_str);
            attempts += 1;
        }

        conn.write_all(format!("{}\r\n", cred.password).as_bytes()).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let resp = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp_str = String::from_utf8_lossy(&strip_iac(&resp)).to_lowercase();
        debug!("Cisco resp: {:?}", resp_str);

        let _ = conn.shutdown().await;

        if resp_str.contains("% authentication failed")
            || resp_str.contains("password:")
            || resp_str.contains("incorrect")
        {
            Ok(AttackResult::Failure)
        } else if resp_str.contains('>') || resp_str.contains('#') {
            Ok(AttackResult::Success { credential: cred.clone(), elapsed: start.elapsed() })
        } else {
            Ok(AttackResult::Failure)
        }
    }
}

fn strip_iac(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == 0xFF {
            // IAC — skip command byte + option byte (3 bytes total)
            i += 3;
        } else {
            out.push(buf[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cisco_name() {
        assert_eq!(CiscoProtocol.name(), "cisco");
    }

    #[test]
    fn cisco_default_port() {
        assert_eq!(CiscoProtocol.default_port(), 23);
    }

    #[test]
    fn strip_iac_removes_sequences() {
        // IAC WILL ECHO = [0xFF, 0xFB, 0x01]
        let input = vec![0xFF, 0xFB, 0x01, b'P', b'a', b's', b's'];
        assert_eq!(strip_iac(&input), b"Pass");
    }

    #[test]
    fn strip_iac_passthrough_plain() {
        let input = b"Password: ".to_vec();
        assert_eq!(strip_iac(&input), input);
    }

    #[test]
    fn failure_detection_percentage() {
        let resp = "% Authentication failed".to_lowercase();
        assert!(resp.contains("% authentication failed"));
    }
}
