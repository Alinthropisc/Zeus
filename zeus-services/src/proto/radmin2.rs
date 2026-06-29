//! Radmin v2 remote administration authentication, port 4899.

use async_trait::async_trait;
use md5::{Digest, Md5};
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct Radmin2Protocol;

// ── crypto helpers ────────────────────────────────────────────────────────────

fn md5(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}

/// Checksum covers the type byte + data, zero-padded to a 4-byte boundary.
fn radmin_checksum(type_byte: u8, data: &[u8]) -> u32 {
    let mut buf = vec![type_byte];
    buf.extend_from_slice(data);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    let mut sum: u32 = 0;
    for chunk in buf.chunks_exact(4) {
        sum = sum.wrapping_add(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    sum
}

/// Build a Radmin wire message.
///
/// `length` is the payload byte count (type byte + data bytes sent after the
/// header).  For the challenge request only the type byte is meaningful so
/// `length = 1`; for the challenge response `length = 1 + 32 = 33 (0x21)`.
fn build_radmin_msg(type_byte: u8, data: &[u8; 32], length: u32) -> Vec<u8> {
    let checksum = radmin_checksum(type_byte, data);
    let mut msg = Vec::with_capacity(10 + 32);
    msg.push(0x01); // magic
    msg.extend_from_slice(&length.to_le_bytes());
    msg.extend_from_slice(&checksum.to_le_bytes());
    msg.push(type_byte);
    msg.extend_from_slice(data);
    msg
}

// ── protocol impl ─────────────────────────────────────────────────────────────

#[async_trait]
impl Protocol for Radmin2Protocol {
    fn name(&self) -> &'static str { "radmin2" }
    fn default_port(&self) -> u16 { 4899 }
    fn description(&self) -> &'static str { "Radmin v2 remote administration" }

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

        // Step 1 – read server banner
        let banner = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("Radmin2 banner: {:?}", banner);

        // Step 2 – send challenge request (type=0x1B, length=1, no data)
        let empty_data = [0u8; 32];
        let req = build_radmin_msg(0x1B, &empty_data, 1);
        conn.write_all(&req)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Step 3 – read 32-byte challenge from server response
        let challenge_msg = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("Radmin2 challenge msg len={}", challenge_msg.len());

        // Extract challenge: last 32 bytes of the message body
        let challenge: [u8; 32] = if challenge_msg.len() >= 32 {
            let offset = challenge_msg.len() - 32;
            let mut c = [0u8; 32];
            c.copy_from_slice(&challenge_msg[offset..]);
            c
        } else {
            return Ok(AttackResult::Error("short challenge from server".into()));
        };

        // Step 4 – compute response: MD5(challenge + password), pad to 32 bytes
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&challenge);
        preimage.extend_from_slice(cred.password.as_bytes());
        let digest = md5(&preimage);
        let mut solution = [0u8; 32];
        solution[..16].copy_from_slice(&digest);
        // upper 16 bytes remain zero (padding)

        // Step 5 – send challenge response (type=0x09, length=0x21=33)
        let resp_msg = build_radmin_msg(0x09, &solution, 0x21);
        conn.write_all(&resp_msg)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Step 6 – read auth result
        let result = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let _ = conn.shutdown().await;

        // Success: magic=0x01, length=0x01000000 (LE), type=0x00
        if result.len() >= 10 && result[0] == 0x01 && result[9] == 0x00 {
            Ok(AttackResult::Success { credential: cred.clone(), elapsed: start.elapsed() })
        } else {
            Ok(AttackResult::Failure)
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radmin2_meta() {
        let p = Radmin2Protocol;
        assert_eq!(p.name(), "radmin2");
        assert_eq!(p.default_port(), 4899);
    }

    #[test]
    fn radmin2_checksum_nonzero() {
        // A non-trivial type byte + data should produce a non-zero checksum
        // (zero is astronomically unlikely for random-ish data).
        let checksum = radmin_checksum(0x1B, &[0u8; 32]);
        // type byte 0x1B padded to 4 bytes = [0x1B, 0, 0, 0] → LE u32 = 0x0000001B
        assert_eq!(checksum, 0x0000_001B);
    }

    #[test]
    fn radmin2_msg_length() {
        let data = [0u8; 32];
        // Challenge request: length field = 1
        let msg = build_radmin_msg(0x1B, &data, 1);
        // Header(9) + type(1) + data(32) = 42
        assert_eq!(msg.len(), 42);
        assert_eq!(msg[0], 0x01); // magic

        // Challenge response: length field = 0x21 = 33
        let msg2 = build_radmin_msg(0x09, &data, 0x21);
        assert_eq!(msg2.len(), 42);
    }
}
