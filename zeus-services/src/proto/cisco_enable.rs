//! Cisco "enable" privileged-mode password authentication via Telnet/TCP (port 23).
//!
//! This module targets the `enable` password prompt specifically, which grants
//! privileged (EXEC) mode on a Cisco device.  It is distinct from `cisco.rs`,
//! which handles the initial login password.
//!
//! Wire flow:
//!   1. Connect.
//!   2. Read until a "Password:" prompt appears (skip IAC negotiation bytes).
//!   3. Send `password\r\n`.
//!   4. Read response:
//!      - Contains "#"       → success (enable prompt received).
//!      - Contains "Password:" again, "bad", "fail", "denied", "attempt" → failure.

use crate::net::TcpConnection;
use async_trait::async_trait;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

use crate::resolve_addr;

pub struct CiscoEnableProtocol;

/// Strip Telnet IAC command sequences (0xFF cmd opt — 3 bytes each).
fn strip_iac(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == 0xFF && i + 2 < buf.len() {
            i += 3; // skip IAC + command + option
        } else {
            out.push(buf[i]);
            i += 1;
        }
    }
    out
}

#[async_trait]
impl Protocol for CiscoEnableProtocol {
    fn name(&self) -> &'static str {
        "cisco-enable"
    }
    fn default_port(&self) -> u16 {
        23
    }
    fn description(&self) -> &'static str {
        "Cisco IOS enable password authentication (privileged EXEC mode)"
    }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let addr = resolve_addr(&target.host, target.port)?;
        let start = Instant::now();

        let mut conn = TcpConnection::connect(addr, config.timeout)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read lines until we see the "Password:" prompt; skip IAC bytes.
        let mut prompt_str = String::new();
        for _ in 0..16 {
            let raw = conn
                .read_until_crlf()
                .await
                .map_err(|e| ZeusError::Protocol(e.to_string()))?;
            let cleaned = String::from_utf8_lossy(&strip_iac(&raw)).to_lowercase();
            debug!("cisco-enable prompt read: {:?}", cleaned);
            if cleaned.contains("assword") {
                prompt_str = cleaned;
                break;
            }
        }

        if !prompt_str.contains("assword") {
            return Err(ZeusError::Protocol(
                "cisco-enable: did not receive a Password: prompt".into(),
            ));
        }

        // Send the enable password.
        conn.write_all(format!("{}\r\n", cred.password).as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let resp_raw = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp_str = String::from_utf8_lossy(&strip_iac(&resp_raw)).to_lowercase();
        debug!("cisco-enable resp: {:?}", resp_str);

        // Send a clean exit regardless of outcome.
        let _ = conn.write_all(b"exit\r\n").await;
        let _ = conn.shutdown().await;

        if resp_str.contains('#') {
            Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            })
        } else if resp_str.contains("assword")
            || resp_str.contains("bad")
            || resp_str.contains("fail")
            || resp_str.contains("denied")
            || resp_str.contains("attempt")
        {
            Ok(AttackResult::Failure)
        } else {
            // Ambiguous response — conservative: treat as failure.
            Ok(AttackResult::Failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cisco_enable_meta() {
        let p = CiscoEnableProtocol;
        assert_eq!(p.name(), "cisco-enable");
        assert_eq!(p.default_port(), 23);
    }

    #[test]
    fn cisco_enable_description_not_empty() {
        assert!(!CiscoEnableProtocol.description().is_empty());
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
}
