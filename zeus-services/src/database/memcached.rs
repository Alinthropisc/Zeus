//! Memcached authentication probe.
//!
//! Two paths:
//!
//! **ASCII probe**: Send `version\r\n`.
//!   - `VERSION x.y.z` → server is open (no auth required).
//!   - `ERROR` or connection closed → server may require SASL binary auth.
//!
//! **SASL binary protocol** (RFC 4616 PLAIN mechanism):
//!   1. Send SASL LIST MECHS (opcode 0x20) — optional discovery step.
//!   2. Send SASL AUTH (opcode 0x21) with mechanism "PLAIN" and payload
//!      `"\x00<username>\x00<password>"`.
//!   3. Read binary response header; status 0x0000 = success, 0x0020 = failure.
//!
//! The binary protocol header is always 24 bytes.

use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct MemcachedProtocol;

// ── Binary protocol constants ─────────────────────────────────────────────────

const BINARY_MAGIC_REQUEST:  u8 = 0x80;
const BINARY_MAGIC_RESPONSE: u8 = 0x81;

const OPCODE_SASL_LIST_MECHS: u8 = 0x20;
const OPCODE_SASL_AUTH:       u8 = 0x21;

/// Size of the binary protocol header in bytes (fixed at 24).
pub const BINARY_HEADER_SIZE: usize = 24;

const STATUS_SUCCESS:      u16 = 0x0000;
const STATUS_AUTH_ERROR:   u16 = 0x0020;
#[allow(dead_code)]
const STATUS_AUTH_CONTINUE: u16 = 0x0021;

// ── Binary packet builders ────────────────────────────────────────────────────

/// Build a Memcached binary protocol request header.
///
/// Layout (24 bytes):
/// ```text
/// magic(1) + opcode(1) + key_len(2 BE) + extras_len(1) + data_type(1)
/// + vbucket(2 BE) + total_body(4 BE) + opaque(4 BE) + cas(8 BE)
/// ```
pub fn binary_header(
    opcode: u8,
    key_len: u16,
    extras_len: u8,
    total_body: u32,
    opaque: u32,
) -> [u8; BINARY_HEADER_SIZE] {
    let mut hdr = [0u8; BINARY_HEADER_SIZE];
    hdr[0] = BINARY_MAGIC_REQUEST;
    hdr[1] = opcode;
    hdr[2..4].copy_from_slice(&key_len.to_be_bytes());
    hdr[4] = extras_len;
    hdr[5] = 0x00; // data_type
    hdr[6..8].copy_from_slice(&0u16.to_be_bytes()); // vbucket
    hdr[8..12].copy_from_slice(&total_body.to_be_bytes());
    hdr[12..16].copy_from_slice(&opaque.to_be_bytes());
    // CAS = 0 (bytes 16..24 already zero)
    hdr
}

/// Build the SASL LIST MECHS request (24-byte header, no body).
pub fn build_sasl_list_mechs() -> Vec<u8> {
    binary_header(OPCODE_SASL_LIST_MECHS, 0, 0, 0, 0).to_vec()
}

/// Build the PLAIN SASL payload: `"\x00<username>\x00<password>"`.
pub fn sasl_plain_payload(username: &str, password: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + username.len() + password.len());
    payload.push(0x00); // authzid (empty)
    payload.extend_from_slice(username.as_bytes());
    payload.push(0x00); // separator
    payload.extend_from_slice(password.as_bytes());
    payload
}

/// Build the SASL AUTH request for the PLAIN mechanism.
///
/// - key = b"PLAIN"
/// - value = SASL PLAIN payload
pub fn build_sasl_auth(username: &str, password: &str) -> Vec<u8> {
    let key = b"PLAIN";
    let value = sasl_plain_payload(username, password);
    let key_len = key.len() as u16;
    let total_body = (key.len() + value.len()) as u32;

    let hdr = binary_header(OPCODE_SASL_AUTH, key_len, 0, total_body, 0);
    let mut pkt = Vec::with_capacity(BINARY_HEADER_SIZE + total_body as usize);
    pkt.extend_from_slice(&hdr);
    pkt.extend_from_slice(key);
    pkt.extend_from_slice(&value);
    pkt
}

// ── Response parsing ──────────────────────────────────────────────────────────

/// Read and validate a binary protocol response header.
/// Returns the 24-byte header on success.
async fn read_binary_header(conn: &mut TcpConnection) -> Result<[u8; BINARY_HEADER_SIZE], ZeusError> {
    let raw = conn.read_bytes(BINARY_HEADER_SIZE).await
        .map_err(|e| ZeusError::Protocol(format!("Memcached: header read: {e}")))?;
    if raw.len() < BINARY_HEADER_SIZE {
        return Err(ZeusError::Protocol("Memcached: response header truncated".into()));
    }
    if raw[0] != BINARY_MAGIC_RESPONSE {
        return Err(ZeusError::Protocol(
            format!("Memcached: unexpected response magic 0x{:02X}", raw[0]),
        ));
    }
    let mut hdr = [0u8; BINARY_HEADER_SIZE];
    hdr.copy_from_slice(&raw);
    Ok(hdr)
}

/// Extract the status code from a binary response header (bytes 6–7, big-endian).
fn response_status(hdr: &[u8; BINARY_HEADER_SIZE]) -> u16 {
    u16::from_be_bytes([hdr[6], hdr[7]])
}

/// Drain the body of a binary response (total_body_length at bytes 8–11).
async fn drain_binary_body(conn: &mut TcpConnection, hdr: &[u8; BINARY_HEADER_SIZE]) -> Result<Vec<u8>, ZeusError> {
    let body_len = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
    if body_len == 0 {
        return Ok(vec![]);
    }
    conn.read_bytes(body_len).await
        .map_err(|e| ZeusError::Protocol(format!("Memcached: body read: {e}")))
}

// ── Protocol ─────────────────────────────────────────────────────────────────

#[async_trait]
impl Protocol for MemcachedProtocol {
    fn name(&self) -> &'static str { "memcached" }
    fn default_port(&self) -> u16 { 11211 }
    fn description(&self) -> &'static str {
        "Memcached SASL binary PLAIN authentication (with ASCII version probe)"
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
        let mut conn = TcpConnection::connect(addr, config.timeout).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // ── Step 1: ASCII VERSION probe ───────────────────────────────────
        // This tells us if the server is in open (no-auth) mode.
        conn.write_all(b"version\r\n").await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let resp = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp_str = String::from_utf8_lossy(&resp);
        debug!("Memcached version resp: {:?}", resp_str);

        if resp_str.starts_with("VERSION") {
            // Open server — no authentication required.
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error(
                "Memcached: no authentication required (open server)".into(),
            ));
        }

        // Server returned ERROR or something else — try SASL binary auth.
        // We need a fresh connection because the ASCII command may have put
        // the server in an error state.
        let _ = conn.shutdown().await;

        let mut conn2 = TcpConnection::connect(addr, config.timeout).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // ── Step 2: SASL AUTH with PLAIN mechanism ────────────────────────
        let auth_pkt = build_sasl_auth(&cred.username, &cred.password);
        conn2.write_all(&auth_pkt).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("Memcached: sent SASL AUTH PLAIN for user '{}'", cred.username);

        let hdr = read_binary_header(&mut conn2).await?;
        let _body = drain_binary_body(&mut conn2, &hdr).await?;
        let _ = conn2.shutdown().await;

        let status = response_status(&hdr);
        debug!("Memcached: SASL AUTH response status=0x{:04X}", status);

        match status {
            STATUS_SUCCESS => Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            }),
            STATUS_AUTH_ERROR => Ok(AttackResult::Failure),
            other => Ok(AttackResult::Error(
                format!("Memcached: unexpected SASL status 0x{:04X}", other),
            )),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memcached_meta() {
        let p = MemcachedProtocol;
        assert_eq!(p.name(), "memcached");
        assert_eq!(p.default_port(), 11211);
    }

    #[test]
    fn memcached_description_not_empty() {
        assert!(!MemcachedProtocol.description().is_empty());
    }

    #[test]
    fn binary_header_size_is_24() {
        assert_eq!(BINARY_HEADER_SIZE, 24);
    }

    #[test]
    fn binary_header_magic_byte() {
        let hdr = binary_header(OPCODE_SASL_AUTH, 5, 0, 10, 0);
        assert_eq!(hdr[0], BINARY_MAGIC_REQUEST);
    }

    #[test]
    fn binary_header_opcode_set() {
        let hdr = binary_header(OPCODE_SASL_AUTH, 5, 0, 10, 0);
        assert_eq!(hdr[1], OPCODE_SASL_AUTH);
    }

    #[test]
    fn binary_header_key_len_big_endian() {
        let hdr = binary_header(OPCODE_SASL_AUTH, 0x0102, 0, 0, 0);
        assert_eq!(hdr[2], 0x01);
        assert_eq!(hdr[3], 0x02);
    }

    #[test]
    fn binary_header_total_body_big_endian() {
        let hdr = binary_header(OPCODE_SASL_AUTH, 0, 0, 0x0102_0304, 0);
        assert_eq!(&hdr[8..12], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn binary_header_cas_is_zero() {
        let hdr = binary_header(OPCODE_SASL_AUTH, 0, 0, 0, 42);
        assert_eq!(&hdr[16..24], &[0u8; 8]);
    }

    #[test]
    fn sasl_plain_payload_format() {
        let payload = sasl_plain_payload("user", "pass");
        // Must be: \x00 + "user" + \x00 + "pass"
        assert_eq!(payload[0], 0x00);
        assert_eq!(&payload[1..5], b"user");
        assert_eq!(payload[5], 0x00);
        assert_eq!(&payload[6..10], b"pass");
        assert_eq!(payload.len(), 10);
    }

    #[test]
    fn sasl_plain_payload_empty_credentials() {
        let payload = sasl_plain_payload("", "");
        assert_eq!(payload, &[0x00, 0x00]);
    }

    #[test]
    fn sasl_auth_packet_structure() {
        let pkt = build_sasl_auth("user", "pass");
        // Header
        assert_eq!(pkt[0], BINARY_MAGIC_REQUEST);
        assert_eq!(pkt[1], OPCODE_SASL_AUTH);
        // Key length = 5 ("PLAIN")
        let key_len = u16::from_be_bytes([pkt[2], pkt[3]]);
        assert_eq!(key_len, 5);
        // Total body = 5 ("PLAIN") + 10 (\x00user\x00pass)
        let total_body = u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]);
        assert_eq!(total_body, 15);
        // Body starts at offset 24
        assert_eq!(&pkt[24..29], b"PLAIN");
        assert_eq!(pkt[29], 0x00);         // authzid separator
        assert_eq!(&pkt[30..34], b"user");
        assert_eq!(pkt[34], 0x00);         // username/password separator
        assert_eq!(&pkt[35..39], b"pass");
    }

    #[test]
    fn sasl_list_mechs_is_pure_header() {
        let pkt = build_sasl_list_mechs();
        assert_eq!(pkt.len(), BINARY_HEADER_SIZE);
        assert_eq!(pkt[0], BINARY_MAGIC_REQUEST);
        assert_eq!(pkt[1], OPCODE_SASL_LIST_MECHS);
        // total_body = 0
        assert_eq!(&pkt[8..12], &[0, 0, 0, 0]);
    }

    #[test]
    fn response_status_extraction() {
        let mut hdr = [0u8; BINARY_HEADER_SIZE];
        hdr[0] = BINARY_MAGIC_RESPONSE;
        hdr[6] = 0x00;
        hdr[7] = 0x20; // STATUS_AUTH_ERROR
        assert_eq!(response_status(&hdr), STATUS_AUTH_ERROR);
    }
}
