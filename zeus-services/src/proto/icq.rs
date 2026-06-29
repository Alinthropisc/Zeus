//! ICQ / OSCAR legacy authentication — port 5190/TCP.
//!
//! OSCAR (Open System for Communication in Realtime) uses FLAP framing over
//! TCP.  Login sequence:
//!
//!   1. Client connects and reads the server's FLAP SIGNON frame.
//!   2. Client sends its own FLAP SIGNON (protocol version 1).
//!   3. Client sends SNAC (0x0017, 0x0002) — MD5-based auth request carrying
//!      the screen-name and an MD5 key request.
//!   4. Server replies with SNAC (0x0017, 0x0007) carrying an MD5 key (TLV 0x0135).
//!   5. Client computes: MD5(key || MD5(password) || "AOL Instant Messenger (SM)")
//!      and sends SNAC (0x0017, 0x0002) with the result as TLV 0x0025.
//!   6. Server replies:
//!      - SNAC (0x0017, 0x0003) with TLV 0x0005 (BOS address) → success.
//!      - SNAC (0x0017, 0x0003) with TLV 0x0008 (error code) → failure.

use async_trait::async_trait;
use md5::{Digest, Md5};
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

// ── FLAP / SNAC framing ───────────────────────────────────────────────────────

/// Wrap `data` in a FLAP frame.
///
/// ```text
/// 0x2a | channel(1) | sequence(2 BE) | data_len(2 BE) | data
/// ```
fn build_flap(channel: u8, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(6 + data.len());
    pkt.push(0x2a);
    pkt.push(channel);
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&(data.len() as u16).to_be_bytes());
    pkt.extend_from_slice(data);
    pkt
}

/// Build a SNAC payload (family, subtype, flags, request-id, data).
fn build_snac(family: u16, subtype: u16, flags: u16, req_id: u32, data: &[u8]) -> Vec<u8> {
    let mut snac = Vec::with_capacity(10 + data.len());
    snac.extend_from_slice(&family.to_be_bytes());
    snac.extend_from_slice(&subtype.to_be_bytes());
    snac.extend_from_slice(&flags.to_be_bytes());
    snac.extend_from_slice(&req_id.to_be_bytes());
    snac.extend_from_slice(data);
    snac
}

/// Encode a TLV (type + length + value).
fn tlv(t: u16, v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + v.len());
    out.extend_from_slice(&t.to_be_bytes());
    out.extend_from_slice(&(v.len() as u16).to_be_bytes());
    out.extend_from_slice(v);
    out
}

// ── MD5 auth helpers ──────────────────────────────────────────────────────────

/// AOL OSCAR MD5 auth salt appended after the password hash.
const OSCAR_MD5_SALT: &[u8] = b"AOL Instant Messenger (SM)";

/// Compute the OSCAR MD5 login hash:
/// `MD5(key || MD5(password) || OSCAR_MD5_SALT)`
fn oscar_md5_hash(key: &[u8], password: &str) -> [u8; 16] {
    let pw_hash: [u8; 16] = Md5::digest(password.as_bytes()).into();
    let mut h = Md5::new();
    h.update(key);
    h.update(pw_hash);
    h.update(OSCAR_MD5_SALT);
    h.finalize().into()
}

// ── Protocol ─────────────────────────────────────────────────────────────────

pub struct IcqProtocol;

#[async_trait]
impl Protocol for IcqProtocol {
    fn name(&self) -> &'static str { "icq" }
    fn default_port(&self) -> u16 { 5190 }
    fn description(&self) -> &'static str { "ICQ/OSCAR legacy authentication" }

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

        // ── Step 1: read server FLAP SIGNON ──────────────────────────────────
        let greeting = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        if greeting.is_empty() || greeting[0] != 0x2a {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("ICQ: no FLAP greeting".into()));
        }
        debug!("ICQ: received FLAP greeting ({} bytes)", greeting.len());

        // ── Step 2: send FLAP SIGNON with protocol version 1 ─────────────────
        let signon_data: &[u8] = &[0x00, 0x00, 0x00, 0x01]; // protocol version = 1
        let signon = build_flap(0x01, 0x0001, signon_data);
        conn.write_all(&signon)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // ── Step 3: send SNAC (0x17, 0x06) — MD5 key request ─────────────────
        // TLV 0x0001 = screen name
        let mut key_req_data = tlv(0x0001, cred.username.as_bytes());
        key_req_data.extend(tlv(0x004B, &[])); // client MD5 flag
        let snac_key_req = build_snac(0x0017, 0x0006, 0x0000, 0x00000001, &key_req_data);
        let flap_key_req = build_flap(0x02, 0x0002, &snac_key_req);
        conn.write_all(&flap_key_req)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        debug!("ICQ: sent MD5 key request for {}", cred.username);

        // ── Step 4: read server MD5 key reply (SNAC 0x17, 0x07) ──────────────
        let key_reply = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        debug!("ICQ: received key reply ({} bytes)", key_reply.len());

        // Extract MD5 key from TLV 0x0135 within the SNAC payload.
        // FLAP header = 6 bytes, SNAC header = 10 bytes → payload at offset 16.
        let md5_key: Vec<u8> = if key_reply.len() > 16 {
            extract_tlv(&key_reply[16..], 0x0135).unwrap_or_else(|| b"OSCR".to_vec())
        } else {
            b"OSCR".to_vec()
        };

        // ── Step 5: send SNAC (0x17, 0x02) — full login with MD5 hash ────────
        let hash = oscar_md5_hash(&md5_key, &cred.password);

        let mut login_data = tlv(0x0001, cred.username.as_bytes());
        login_data.extend(tlv(0x0025, &hash));
        login_data.extend(tlv(0x004C, &[])); // use MD5 login flag
        let snac_login = build_snac(0x0017, 0x0002, 0x0000, 0x00000002, &login_data);
        let flap_login = build_flap(0x02, 0x0003, &snac_login);
        conn.write_all(&flap_login)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        debug!("ICQ: sent login SNAC");

        // ── Step 6: read login reply ──────────────────────────────────────────
        let reply = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let _ = conn.shutdown().await;

        debug!("ICQ: login reply {} bytes", reply.len());

        // SNAC payload starts at byte 16 (FLAP 6 + SNAC header 10).
        if reply.len() > 16 {
            let payload = &reply[16..];
            // TLV 0x0005 = BOS address → success
            if extract_tlv(payload, 0x0005).is_some() {
                return Ok(AttackResult::Success {
                    credential: cred.clone(),
                    elapsed: start.elapsed(),
                });
            }
            // TLV 0x0008 = error code → failure
            if extract_tlv(payload, 0x0008).is_some() {
                return Ok(AttackResult::Failure);
            }
        }

        Ok(AttackResult::Failure)
    }
}

/// Scan a TLV stream for the first TLV with the given type and return its value.
fn extract_tlv(data: &[u8], target_type: u16) -> Option<Vec<u8>> {
    let mut i = 0;
    while i + 4 <= data.len() {
        let t = u16::from_be_bytes([data[i], data[i + 1]]);
        let l = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        i += 4;
        if i + l > data.len() { break; }
        if t == target_type {
            return Some(data[i..i + l].to_vec());
        }
        i += l;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icq_meta() {
        assert_eq!(IcqProtocol.name(), "icq");
        assert_eq!(IcqProtocol.default_port(), 5190);
    }

    #[test]
    fn flap_packet_header() {
        let data = b"hello";
        let pkt = build_flap(0x01, 0x0042, data);
        assert_eq!(pkt[0], 0x2a);           // FLAP marker
        assert_eq!(pkt[1], 0x01);           // channel
        assert_eq!(&pkt[2..4], &[0x00, 0x42]); // sequence BE
        assert_eq!(&pkt[4..6], &[0x00, 0x05]); // length BE
        assert_eq!(&pkt[6..], b"hello");
    }

    #[test]
    fn snac_packet_structure() {
        let snac = build_snac(0x0017, 0x0002, 0x0000, 0xDEADBEEF, b"payload");
        assert_eq!(&snac[0..2], &[0x00, 0x17]); // family
        assert_eq!(&snac[2..4], &[0x00, 0x02]); // subtype
        assert_eq!(&snac[4..6], &[0x00, 0x00]); // flags
        assert_eq!(&snac[6..10], &0xDEADBEEFu32.to_be_bytes()); // req-id
        assert_eq!(&snac[10..], b"payload");
    }

    #[test]
    fn extract_tlv_finds_value() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&[0x00, 0x01, 0x00, 0x03, b'f', b'o', b'o']); // TLV 1
        stream.extend_from_slice(&[0x00, 0x05, 0x00, 0x02, 0xAA, 0xBB]);        // TLV 5
        assert_eq!(extract_tlv(&stream, 0x0005), Some(vec![0xAA, 0xBB]));
        assert!(extract_tlv(&stream, 0x0009).is_none());
    }
}
