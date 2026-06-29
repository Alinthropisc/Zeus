//! WinPcap/Npcap Remote Capture Protocol (RPCAP) — port 2002/TCP.
//!
//! RPCAP is used by WinPcap and Npcap for remote packet capture with optional
//! password authentication.
//!
//! Wire flow:
//!   1. Connect to port 2002.
//!   2. Send RPCAP_MSG_AUTH_REQ with username + password.
//!   3. Read response:
//!      - RPCAP_MSG_AUTH_REPLY (0x09) → credentials accepted.
//!      - RPCAP_MSG_ERROR      (0xFE) → credentials rejected.

use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

// ── RPCAP constants ───────────────────────────────────────────────────────────

const RPCAP_VERSION: u8 = 0;
const RPCAP_MSG_AUTH_REQ: u8 = 8;
const RPCAP_MSG_AUTH_REPLY: u8 = 9;
const RPCAP_MSG_ERROR: u8 = 0xFE;
const RPCAP_RMTAUTH_PWD: u16 = 1;

// ── Packet builder ────────────────────────────────────────────────────────────

/// Build an RPCAP authentication request packet.
///
/// Header (7 bytes):
/// ```text
/// version(1) | type(1) | value(2 LE) | payload_len(4 LE)
/// ```
/// Payload:
/// ```text
/// auth_type(2 LE) | dummy(2 LE) | username_len(2 LE) | password_len(2 LE)
/// | username_bytes | password_bytes
/// ```
fn build_rpcap_auth(username: &str, password: &str) -> Vec<u8> {
    let ulen = username.len() as u16;
    let plen = password.len() as u16;
    let payload_len: u32 = 2 + 2 + 2 + 2 + ulen as u32 + plen as u32;

    let mut pkt = Vec::with_capacity(8 + payload_len as usize);
    // Header
    pkt.push(RPCAP_VERSION);
    pkt.push(RPCAP_MSG_AUTH_REQ);
    pkt.extend_from_slice(&0u16.to_le_bytes()); // value
    pkt.extend_from_slice(&payload_len.to_le_bytes());
    // Payload
    pkt.extend_from_slice(&RPCAP_RMTAUTH_PWD.to_le_bytes());
    pkt.extend_from_slice(&0u16.to_le_bytes()); // dummy
    pkt.extend_from_slice(&ulen.to_le_bytes());
    pkt.extend_from_slice(&plen.to_le_bytes());
    pkt.extend_from_slice(username.as_bytes());
    pkt.extend_from_slice(password.as_bytes());
    pkt
}

// ── Protocol ─────────────────────────────────────────────────────────────────

pub struct RpcapProtocol;

#[async_trait]
impl Protocol for RpcapProtocol {
    fn name(&self) -> &'static str { "rpcap" }
    fn default_port(&self) -> u16 { 2002 }
    fn description(&self) -> &'static str {
        "WinPcap/Npcap Remote Capture Protocol (RPCAP) password authentication"
    }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let addr = format!("{}:{}", target.host, target.port)
            .to_socket_addrs()
            .map_err(ZeusError::Network)?
            .next()
            .ok_or_else(|| ZeusError::Protocol("DNS resolution failed".into()))?;

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let pkt = build_rpcap_auth(&cred.username, &cred.password);
        conn.write_all(&pkt)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        debug!("RPCAP: sent AUTH_REQ for {}", cred.username);

        // Read at least the 8-byte response header.
        let resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let _ = conn.shutdown().await;

        debug!("RPCAP: response len={}", resp.len());

        if resp.len() < 2 {
            return Ok(AttackResult::Error("RPCAP: response too short".into()));
        }

        // Response type is at byte index 1.
        match resp[1] {
            RPCAP_MSG_AUTH_REPLY => Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            }),
            RPCAP_MSG_ERROR => Ok(AttackResult::Failure),
            other => Ok(AttackResult::Error(format!(
                "RPCAP: unexpected message type {:#04x}",
                other
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpcap_meta() {
        assert_eq!(RpcapProtocol.name(), "rpcap");
        assert_eq!(RpcapProtocol.default_port(), 2002);
    }

    #[test]
    fn rpcap_auth_packet_structure() {
        let pkt = build_rpcap_auth("admin", "secret");
        // Header: version(1) + type(1) + value(2) + payload_len(4) = 8 bytes
        // Payload: auth_type(2) + dummy(2) + ulen(2) + plen(2) + 5 + 6 = 19
        // Total = 8 + 19 = 27
        assert_eq!(pkt[0], RPCAP_VERSION);
        assert_eq!(pkt[1], RPCAP_MSG_AUTH_REQ);
        // value = 0 LE
        assert_eq!(&pkt[2..4], &[0, 0]);
        // payload_len = 2+2+2+2+5+6 = 19, LE
        let payload_len = u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
        assert_eq!(payload_len, 19);
        // auth_type = RPCAP_RMTAUTH_PWD = 1, LE
        let auth_type = u16::from_le_bytes([pkt[8], pkt[9]]);
        assert_eq!(auth_type, RPCAP_RMTAUTH_PWD);
        // username_len = 5 LE
        let ulen = u16::from_le_bytes([pkt[12], pkt[13]]);
        assert_eq!(ulen, 5);
        // password_len = 6 LE
        let plen = u16::from_le_bytes([pkt[14], pkt[15]]);
        assert_eq!(plen, 6);
        assert_eq!(&pkt[16..21], b"admin");
        assert_eq!(&pkt[21..27], b"secret");
    }

    #[test]
    fn rpcap_empty_creds() {
        let pkt = build_rpcap_auth("", "");
        // payload = 2+2+2+2 = 8 bytes, total = 16
        assert_eq!(pkt.len(), 16);
        let payload_len = u32::from_le_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
        assert_eq!(payload_len, 8);
    }
}
