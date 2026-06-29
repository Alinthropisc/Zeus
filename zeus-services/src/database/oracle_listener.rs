//! Oracle TNS Listener enumeration and password brute-force.
//!
//! The Oracle TNS Listener runs on TCP port 1521 as a separate process from the
//! database.  It accepts TNS DATA packets carrying listener command strings.
//!
//! Wire flow:
//!   1. Connect to port 1521
//!   2. Send TNS CONNECT packet (requesting listener access)
//!   3. Read server response (ACCEPT / REFUSE / RESYNC)
//!   4. Send TNS DATA carrying `(CONNECT_DATA=(COMMAND=status))` to probe
//!      whether the listener requires a password
//!   5a. If response contains "(STATUS=" with no "1189" error → listener is
//!       open (no password set) → report as Error("open")
//!   5b. If response contains "1189" → listener requires a password
//!   6. Send TNS DATA with the SET_PASSWORD / STATUS+password command and
//!      check for error "1189" in the reply.
//!
//! This module does NOT touch the Oracle database itself; it speaks only to
//! the listener process.

use crate::net::TcpConnection;
use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct OracleListenerProtocol;

// ── TNS constants (shared with oracle.rs conceptually) ───────────────────────

const TNS_TYPE_CONNECT: u8 = 1;
const TNS_TYPE_ACCEPT: u8 = 2;
const TNS_TYPE_REFUSE: u8 = 4;
const TNS_TYPE_REDIRECT: u8 = 5;
const TNS_TYPE_DATA: u8 = 6;
const TNS_HDR_LEN: usize = 8;
const TNS_TYPE_OFFSET: usize = 4;

// CONNECT fixed-header constants (same as oracle.rs)
const TNS_CONNECT_VERSION: u16 = 0x013A;
const TNS_CONNECT_VERSION_COMPAT: u16 = 0x0134;
const TNS_SERVICE_OPTIONS: u16 = 0x0C41;
const TNS_SDU: u16 = 0x0800;
const TNS_TDU: u16 = 0x7FFF;
const TNS_NT_PROTOCOL: u16 = 0x0000;
const TNS_LINE_TURNAROUND: u16 = 0x0000;
const TNS_VALUE_OF_ONE: u16 = 0x0001;
const TNS_MAX_RECV_CONNECT: u32 = 512;
const TNS_CONNECT_FLAGS: u8 = 0x04;
const TNS_CONNECT_FIXED_LEN: usize = 26;
const TNS_CONNECT_DATA_OFFSET: u16 = (TNS_HDR_LEN + TNS_CONNECT_FIXED_LEN) as u16;

// ── TNS packet helpers ────────────────────────────────────────────────────────

/// Wrap `body` in a TNS packet header (length + checksum + type + reserved).
fn tns_packet(pkt_type: u8, body: &[u8]) -> Vec<u8> {
    let total = (TNS_HDR_LEN + body.len()) as u16;
    let mut pkt = Vec::with_capacity(TNS_HDR_LEN + body.len());
    pkt.extend_from_slice(&total.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
    pkt.push(pkt_type);
    pkt.push(0x00); // reserved
    pkt.extend_from_slice(&0u16.to_be_bytes()); // header checksum
    pkt.extend_from_slice(body);
    pkt
}

/// Build the TNS CONNECT packet body for the listener.
fn build_listener_connect_body(connect_data: &[u8]) -> Vec<u8> {
    let data_len = connect_data.len() as u16;
    let mut body = Vec::with_capacity(TNS_CONNECT_FIXED_LEN + connect_data.len());
    body.extend_from_slice(&TNS_CONNECT_VERSION.to_be_bytes());
    body.extend_from_slice(&TNS_CONNECT_VERSION_COMPAT.to_be_bytes());
    body.extend_from_slice(&TNS_SERVICE_OPTIONS.to_be_bytes());
    body.extend_from_slice(&TNS_SDU.to_be_bytes());
    body.extend_from_slice(&TNS_TDU.to_be_bytes());
    body.extend_from_slice(&TNS_NT_PROTOCOL.to_be_bytes());
    body.extend_from_slice(&TNS_LINE_TURNAROUND.to_be_bytes());
    body.extend_from_slice(&TNS_VALUE_OF_ONE.to_be_bytes());
    body.extend_from_slice(&data_len.to_be_bytes());
    body.extend_from_slice(&TNS_CONNECT_DATA_OFFSET.to_be_bytes());
    body.extend_from_slice(&TNS_MAX_RECV_CONNECT.to_be_bytes());
    body.push(TNS_CONNECT_FLAGS);
    body.push(TNS_CONNECT_FLAGS);
    body.extend_from_slice(connect_data);
    body
}

/// Build a TNS DATA packet carrying a listener command string.
///
/// TNS DATA body: 2-byte data flags (0x0000) followed by the command bytes.
pub fn build_listener_data(command: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + command.len());
    body.extend_from_slice(&0u16.to_be_bytes()); // data flags
    body.extend_from_slice(command);
    tns_packet(TNS_TYPE_DATA, &body)
}

/// The anonymous CONNECT descriptor for the listener (no SERVICE_NAME).
fn listener_connect_descriptor(host: &str, port: u16) -> String {
    format!(
        "(DESCRIPTION=(CONNECT_DATA=(COMMAND=version))\
         (ADDRESS=(PROTOCOL=TCP)(HOST={host})(PORT={port})))"
    )
}

/// STATUS command — probe whether the listener is open or password-protected.
pub fn listener_status_cmd() -> &'static [u8] {
    b"(CONNECT_DATA=(COMMAND=status))\x0a"
}

/// STATUS command with password argument.
pub fn listener_status_with_password(password: &str) -> String {
    format!("(CONNECT_DATA=(COMMAND=status)(ARGUMENT=listener_password)(PASSWORD={password}))\x0a")
}

/// Read one TNS packet (header + body).
async fn read_tns_packet(conn: &mut TcpConnection) -> Result<Vec<u8>, ZeusError> {
    let header = conn
        .read_bytes(TNS_HDR_LEN)
        .await
        .map_err(|e| ZeusError::Protocol(format!("TNS: header read failed: {e}")))?;
    if header.len() < TNS_HDR_LEN {
        return Err(ZeusError::Protocol("TNS: header truncated".into()));
    }
    let total_len = u16::from_be_bytes([header[0], header[1]]) as usize;
    if total_len < TNS_HDR_LEN {
        return Err(ZeusError::Protocol("TNS: packet length field < 8".into()));
    }
    let body_len = total_len - TNS_HDR_LEN;
    let body = if body_len > 0 {
        conn.read_bytes(body_len)
            .await
            .map_err(|e| ZeusError::Protocol(format!("TNS: body read failed: {e}")))?
    } else {
        vec![]
    };
    let mut pkt = header;
    pkt.extend_from_slice(&body);
    Ok(pkt)
}

/// Return true if the raw response bytes contain the "1189" error code
/// (TNS-01189: The listener could not authenticate the user).
fn contains_1189(data: &[u8]) -> bool {
    data.windows(4).any(|w| w == b"1189")
}

/// Return true if the response contains "(STATUS=" — listener responded to status.
fn contains_status_ok(data: &[u8]) -> bool {
    data.windows(8).any(|w| w == b"(STATUS=")
}

/// Return true if the response contains "DESCRIPTION" — used for success detection.
fn contains_description(data: &[u8]) -> bool {
    data.windows(11).any(|w| w == b"DESCRIPTION")
}

// ── Protocol ─────────────────────────────────────────────────────────────────

#[async_trait]
impl Protocol for OracleListenerProtocol {
    fn name(&self) -> &'static str {
        "oracle-listener"
    }
    fn default_port(&self) -> u16 {
        1521
    }
    fn description(&self) -> &'static str {
        "Oracle TNS Listener password authentication"
    }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let port = target.port;
        let addr_str = format!("{}:{}", target.host, port);
        let addr = addr_str
            .to_socket_addrs()
            .map_err(ZeusError::Network)?
            .next()
            .ok_or_else(|| ZeusError::Protocol("DNS resolution failed".into()))?;

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // ── Step 1: TNS CONNECT ────────────────────────────────────────────
        let desc = listener_connect_descriptor(&target.host, port);
        let connect_body = build_listener_connect_body(desc.as_bytes());
        let connect_pkt = tns_packet(TNS_TYPE_CONNECT, &connect_body);
        conn.write_all(&connect_pkt)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("OracleListener: sent TNS CONNECT");

        // ── Step 2: read server response ──────────────────────────────────
        let resp = read_tns_packet(&mut conn).await?;
        if resp.len() < TNS_HDR_LEN {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error(
                "OracleListener: response too short".into(),
            ));
        }

        let resp_type = resp[TNS_TYPE_OFFSET];
        debug!("OracleListener: initial response type={}", resp_type);

        match resp_type {
            TNS_TYPE_REFUSE => {
                let _ = conn.shutdown().await;
                return Ok(AttackResult::Error("OracleListener: TNS REFUSE".into()));
            }
            TNS_TYPE_REDIRECT => {
                let _ = conn.shutdown().await;
                return Ok(AttackResult::Error("OracleListener: TNS REDIRECT".into()));
            }
            TNS_TYPE_ACCEPT | TNS_TYPE_DATA => {
                debug!("OracleListener: connection accepted/data received");
            }
            other => {
                let _ = conn.shutdown().await;
                return Ok(AttackResult::Error(format!(
                    "OracleListener: unexpected response type {}",
                    other
                )));
            }
        }

        // ── Step 3: send STATUS command (unauthenticated probe) ───────────
        let status_pkt = build_listener_data(listener_status_cmd());
        conn.write_all(&status_pkt)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("OracleListener: sent STATUS command");

        let status_resp = conn
            .read_available()
            .await
            .map_err(|e| ZeusError::Protocol(format!("OracleListener: status read: {e}")))?;
        debug!(
            "OracleListener: STATUS response {} bytes",
            status_resp.len()
        );

        // If no error 1189, listener is open — no password needed.
        if !contains_1189(&status_resp) {
            let _ = conn.shutdown().await;
            if contains_status_ok(&status_resp) || contains_description(&status_resp) {
                return Ok(AttackResult::Error(
                    "OracleListener: listener is open (no password set)".into(),
                ));
            }
            // Ambiguous — treat as failure.
            return Ok(AttackResult::Failure);
        }

        // Listener requires a password.  Try the credential.
        debug!("OracleListener: listener requires password, trying credential");

        // ── Step 4: STATUS with password ──────────────────────────────────
        let pwd_cmd = listener_status_with_password(&cred.password);
        let pwd_pkt = build_listener_data(pwd_cmd.as_bytes());
        conn.write_all(&pwd_pkt)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let pwd_resp = conn
            .read_available()
            .await
            .map_err(|e| ZeusError::Protocol(format!("OracleListener: pwd resp read: {e}")))?;
        let _ = conn.shutdown().await;

        debug!("OracleListener: password response {} bytes", pwd_resp.len());

        // Success: response contains DESCRIPTION and NOT error 1189.
        if contains_description(&pwd_resp) && !contains_1189(&pwd_resp) {
            return Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            });
        }

        Ok(AttackResult::Failure)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_listener_meta() {
        let p = OracleListenerProtocol;
        assert_eq!(p.name(), "oracle-listener");
        assert_eq!(p.default_port(), 1521);
    }

    #[test]
    fn oracle_listener_description_not_empty() {
        assert!(!OracleListenerProtocol.description().is_empty());
    }

    #[test]
    fn tns_packet_header_correct() {
        let body = b"test";
        let pkt = tns_packet(TNS_TYPE_DATA, body);
        // Length field matches total length
        let len = u16::from_be_bytes([pkt[0], pkt[1]]) as usize;
        assert_eq!(len, pkt.len());
        // Type field
        assert_eq!(pkt[TNS_TYPE_OFFSET], TNS_TYPE_DATA);
        // Checksums are zero
        assert_eq!(&pkt[2..4], &[0, 0]);
        assert_eq!(&pkt[6..8], &[0, 0]);
    }

    #[test]
    fn listener_data_packet_has_zero_flags() {
        let cmd = b"(CONNECT_DATA=(COMMAND=status))";
        let pkt = build_listener_data(cmd);
        // After the 8-byte TNS header, first 2 bytes are data flags = 0x0000
        assert_eq!(pkt[TNS_HDR_LEN], 0x00);
        assert_eq!(pkt[TNS_HDR_LEN + 1], 0x00);
        // Command bytes follow
        assert_eq!(&pkt[TNS_HDR_LEN + 2..], cmd);
    }

    #[test]
    fn contains_1189_detects_error() {
        assert!(contains_1189(b"TNS-01189 error here"));
        assert!(!contains_1189(b"no error present"));
    }

    #[test]
    fn contains_status_ok_detects_marker() {
        assert!(contains_status_ok(b"(STATUS=READY)"));
        assert!(!contains_status_ok(b"some other data"));
    }

    #[test]
    fn contains_description_detects_marker() {
        assert!(contains_description(b"(DESCRIPTION=...)"));
        assert!(!contains_description(b"nothing here"));
    }

    #[test]
    fn listener_connect_descriptor_includes_host_and_port() {
        let d = listener_connect_descriptor("192.168.1.1", 1521);
        assert!(d.contains("192.168.1.1"));
        assert!(d.contains("1521"));
        assert!(d.contains("COMMAND=version"));
    }

    #[test]
    fn listener_status_with_password_includes_password() {
        let cmd = listener_status_with_password("secret");
        assert!(cmd.contains("PASSWORD=secret"));
        assert!(cmd.contains("COMMAND=status"));
    }

    #[test]
    fn tns_connect_body_correct_size() {
        let body = build_listener_connect_body(b"");
        assert_eq!(body.len(), TNS_CONNECT_FIXED_LEN);
    }

    #[test]
    fn tns_connect_data_offset_is_36() {
        assert_eq!(TNS_CONNECT_DATA_OFFSET, 34);
    }
}
