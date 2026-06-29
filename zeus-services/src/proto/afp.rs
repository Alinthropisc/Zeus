//! Apple Filing Protocol (AFP) over DSI (Data Stream Interface).
//!
//! AFP uses DSI framing over TCP on port 548.
//!
//! DSI header (16 bytes):
//!   flags(1) + command(1) + requestID(2 BE) + errorCode/writeOffset(4 BE)
//!   + totalDataLength(4 BE) + reserved(4 BE)
//!
//! Wire flow:
//!   1. Connect to port 548
//!   2. Send DSI OpenSession (command=4) — open AFP session
//!   3. Read DSI response — server acknowledges session
//!   4. Send DSI Command wrapping AFP FPLogin (AFP command 18)
//!      with UAM "Cleartxt Passwrd", username, and password
//!   5. Read DSI response; check errorCode (bytes 4–7 of header, big-endian i32)
//!      0 = success, -5023 = kFPAuthContinue (bad credential), other negative = error

use crate::net::TcpConnection;
use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct AfpProtocol;

// ── DSI constants ─────────────────────────────────────────────────────────────

/// Size of the DSI header in bytes.
pub const DSI_HEADER_SIZE: usize = 16;

const DSI_FLAGS_REQUEST: u8 = 0x00;
const DSI_FLAGS_REPLY: u8 = 0x01;

const DSI_CMD_CLOSE_SESSION: u8 = 1;
const DSI_CMD_COMMAND: u8 = 6;
const DSI_CMD_OPEN_SESSION: u8 = 4;
#[allow(dead_code)]
const DSI_CMD_WRITE: u8 = 8;

// AFP FPLogin command ID
const AFP_CMD_LOGIN: u8 = 18;

// AFP error codes
const AFP_NO_ERR: i32 = 0;
const AFP_AUTH_CONT: i32 = -5023; // kFPAuthContinue — wrong credentials
#[allow(dead_code)]
const AFP_USER_NOT_AUTH: i32 = -5019; // kFPUserNotAuth

// ── DSI packet builders ───────────────────────────────────────────────────────

/// Build a DSI header.
pub fn dsi_header(
    flags: u8,
    command: u8,
    request_id: u16,
    error_or_offset: i32,
    total_data_length: u32,
) -> [u8; DSI_HEADER_SIZE] {
    let mut hdr = [0u8; DSI_HEADER_SIZE];
    hdr[0] = flags;
    hdr[1] = command;
    hdr[2..4].copy_from_slice(&request_id.to_be_bytes());
    hdr[4..8].copy_from_slice(&error_or_offset.to_be_bytes());
    hdr[8..12].copy_from_slice(&total_data_length.to_be_bytes());
    // reserved bytes 12..16 remain zero
    hdr
}

/// Build a DSI OpenSession request (no body).
pub fn dsi_open_session(request_id: u16) -> Vec<u8> {
    dsi_header(DSI_FLAGS_REQUEST, DSI_CMD_OPEN_SESSION, request_id, 0, 0).to_vec()
}

/// Build a DSI Command request wrapping AFP data.
pub fn dsi_command(request_id: u16, afp_data: &[u8]) -> Vec<u8> {
    let total = afp_data.len() as u32;
    let hdr = dsi_header(DSI_FLAGS_REQUEST, DSI_CMD_COMMAND, request_id, 0, total);
    let mut pkt = Vec::with_capacity(DSI_HEADER_SIZE + afp_data.len());
    pkt.extend_from_slice(&hdr);
    pkt.extend_from_slice(afp_data);
    pkt
}

/// Build a DSI CloseSession request.
#[allow(dead_code)]
pub fn dsi_close_session(request_id: u16) -> Vec<u8> {
    dsi_header(DSI_FLAGS_REQUEST, DSI_CMD_CLOSE_SESSION, request_id, 0, 0).to_vec()
}

// ── AFP command builder ───────────────────────────────────────────────────────

/// Build an AFP FPLogin command with "Cleartxt Passwrd" UAM.
///
/// Wire format:
/// ```text
/// command(1=18) + afpVersion(Pascal string) + UAMString(Pascal string)
/// + userName(Pascal string, padded to even total length)
/// + password(8 bytes, null-padded)
/// ```
///
/// Pascal string: 1-byte length prefix + characters (no null terminator).
pub fn afp_login(username: &str, password: &str) -> Vec<u8> {
    let afp_version = b"AFPVersion 3.1";
    let uam = b"Cleartxt Passwrd";

    let mut data: Vec<u8> = Vec::new();

    // AFP command byte
    data.push(AFP_CMD_LOGIN);

    // AFP version — Pascal string
    data.push(afp_version.len() as u8);
    data.extend_from_slice(afp_version);

    // UAM string — Pascal string
    data.push(uam.len() as u8);
    data.extend_from_slice(uam);

    // Username — Pascal string; total (length byte + chars) must be odd length
    // so that the whole block stays word-aligned.  Pad with a zero byte if even.
    let uname_bytes = username.as_bytes();
    data.push(uname_bytes.len() as u8);
    data.extend_from_slice(uname_bytes);
    // After adding length(1) + chars(n), if total is even add a pad byte.
    if (1 + uname_bytes.len()).is_multiple_of(2) {
        data.push(0x00);
    }

    // Password — fixed 8 bytes, null-padded
    let mut pass_buf = [0u8; 8];
    for (i, b) in password.bytes().take(8).enumerate() {
        pass_buf[i] = b;
    }
    data.extend_from_slice(&pass_buf);

    data
}

// ── Response parsing ──────────────────────────────────────────────────────────

/// Read a DSI response header (16 bytes).
async fn read_dsi_header(conn: &mut TcpConnection) -> Result<[u8; DSI_HEADER_SIZE], ZeusError> {
    let raw = conn
        .read_bytes(DSI_HEADER_SIZE)
        .await
        .map_err(|e| ZeusError::Protocol(format!("AFP: DSI header read: {e}")))?;
    if raw.len() < DSI_HEADER_SIZE {
        return Err(ZeusError::Protocol("AFP: DSI header truncated".into()));
    }
    let mut hdr = [0u8; DSI_HEADER_SIZE];
    hdr.copy_from_slice(&raw);
    Ok(hdr)
}

/// Extract the error code from a DSI response header (bytes 4–7, big-endian i32).
pub fn dsi_error_code(hdr: &[u8; DSI_HEADER_SIZE]) -> i32 {
    i32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]])
}

/// Drain the DSI response body (totalDataLength at bytes 8–11).
async fn drain_dsi_body(
    conn: &mut TcpConnection,
    hdr: &[u8; DSI_HEADER_SIZE],
) -> Result<Vec<u8>, ZeusError> {
    let body_len = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
    if body_len == 0 {
        return Ok(vec![]);
    }
    conn.read_bytes(body_len)
        .await
        .map_err(|e| ZeusError::Protocol(format!("AFP: DSI body read: {e}")))
}

// ── Protocol ─────────────────────────────────────────────────────────────────

#[async_trait]
impl Protocol for AfpProtocol {
    fn name(&self) -> &'static str {
        "afp"
    }
    fn default_port(&self) -> u16 {
        548
    }
    fn description(&self) -> &'static str {
        "Apple Filing Protocol (AFP) cleartext password authentication over DSI/TCP"
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
            .ok_or_else(|| ZeusError::Protocol("DNS resolution failed".into()))?;

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // ── Step 1: DSI OpenSession ────────────────────────────────────────
        let open = dsi_open_session(1);
        conn.write_all(&open)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("AFP: sent DSI OpenSession");

        let open_hdr = read_dsi_header(&mut conn).await?;
        let _open_body = drain_dsi_body(&mut conn, &open_hdr).await?;

        if open_hdr[1] != DSI_CMD_OPEN_SESSION || open_hdr[0] != DSI_FLAGS_REPLY {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error(format!(
                "AFP: unexpected OpenSession response flags=0x{:02X} cmd=0x{:02X}",
                open_hdr[0], open_hdr[1]
            )));
        }

        let open_err = dsi_error_code(&open_hdr);
        if open_err != AFP_NO_ERR {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error(format!(
                "AFP: OpenSession error code {}",
                open_err
            )));
        }
        debug!("AFP: DSI session opened");

        // ── Step 2: AFP FPLogin ────────────────────────────────────────────
        let login_data = afp_login(&cred.username, &cred.password);
        let login_pkt = dsi_command(2, &login_data);
        conn.write_all(&login_pkt)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("AFP: sent FPLogin for user '{}'", cred.username);

        let login_hdr = read_dsi_header(&mut conn).await?;
        let _login_body = drain_dsi_body(&mut conn, &login_hdr).await?;
        let _ = conn.shutdown().await;

        let error_code = dsi_error_code(&login_hdr);
        debug!("AFP: FPLogin error code {}", error_code);

        match error_code {
            AFP_NO_ERR => Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            }),
            AFP_AUTH_CONT => Ok(AttackResult::Failure),
            other if other < 0 => Ok(AttackResult::Failure),
            other => Ok(AttackResult::Error(format!(
                "AFP: unexpected error code {}",
                other
            ))),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn afp_meta() {
        let p = AfpProtocol;
        assert_eq!(p.name(), "afp");
        assert_eq!(p.default_port(), 548);
    }

    #[test]
    fn afp_description_not_empty() {
        assert!(!AfpProtocol.description().is_empty());
    }

    #[test]
    fn dsi_header_size_is_16() {
        assert_eq!(DSI_HEADER_SIZE, 16);
    }

    #[test]
    fn dsi_header_fields_correct() {
        let hdr = dsi_header(DSI_FLAGS_REQUEST, DSI_CMD_COMMAND, 0x0102, -5023, 128);
        assert_eq!(hdr[0], DSI_FLAGS_REQUEST);
        assert_eq!(hdr[1], DSI_CMD_COMMAND);
        assert_eq!(&hdr[2..4], &[0x01, 0x02]);
        let err = i32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        assert_eq!(err, -5023);
        let len = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
        assert_eq!(len, 128);
        assert_eq!(&hdr[12..16], &[0, 0, 0, 0]); // reserved
    }

    #[test]
    fn dsi_open_session_is_pure_header() {
        let pkt = dsi_open_session(1);
        assert_eq!(pkt.len(), DSI_HEADER_SIZE);
        assert_eq!(pkt[0], DSI_FLAGS_REQUEST);
        assert_eq!(pkt[1], DSI_CMD_OPEN_SESSION);
        // totalDataLength = 0
        assert_eq!(&pkt[8..12], &[0, 0, 0, 0]);
    }

    #[test]
    fn dsi_command_wraps_afp_data() {
        let afp = b"hello AFP";
        let pkt = dsi_command(3, afp);
        assert_eq!(pkt.len(), DSI_HEADER_SIZE + afp.len());
        assert_eq!(pkt[1], DSI_CMD_COMMAND);
        let total = u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]) as usize;
        assert_eq!(total, afp.len());
        assert_eq!(&pkt[DSI_HEADER_SIZE..], afp);
    }

    #[test]
    fn afp_login_starts_with_fpcommand_18() {
        let data = afp_login("user", "pass");
        assert_eq!(data[0], AFP_CMD_LOGIN);
    }

    #[test]
    fn afp_login_contains_uam() {
        let data = afp_login("user", "pass");
        // UAM "Cleartxt Passwrd" must appear somewhere in the data
        let uam = b"Cleartxt Passwrd";
        assert!(
            data.windows(uam.len()).any(|w| w == uam),
            "login data must contain UAM string"
        );
    }

    #[test]
    fn afp_login_contains_afp_version() {
        let data = afp_login("user", "pass");
        let ver = b"AFPVersion 3.1";
        assert!(
            data.windows(ver.len()).any(|w| w == ver),
            "login data must contain AFP version"
        );
    }

    #[test]
    fn afp_login_password_padded_to_8_bytes() {
        // password "abc" (3 bytes) → last 8 bytes should be b"abc\0\0\0\0\0"
        let data = afp_login("user", "abc");
        let pass_start = data.len() - 8;
        assert_eq!(&data[pass_start..pass_start + 3], b"abc");
        assert_eq!(&data[pass_start + 3..], &[0u8; 5]);
    }

    #[test]
    fn afp_login_long_password_truncated_to_8() {
        let data = afp_login("user", "12345678EXTRA");
        let pass_start = data.len() - 8;
        assert_eq!(&data[pass_start..], b"12345678");
    }

    #[test]
    fn dsi_error_code_zero() {
        let hdr = dsi_header(DSI_FLAGS_REPLY, DSI_CMD_COMMAND, 2, 0, 0);
        assert_eq!(dsi_error_code(&hdr), 0);
    }

    #[test]
    fn dsi_error_code_negative() {
        let hdr = dsi_header(DSI_FLAGS_REPLY, DSI_CMD_COMMAND, 2, -5023, 0);
        assert_eq!(dsi_error_code(&hdr), -5023);
    }

    #[test]
    fn dsi_command_request_id_in_header() {
        let pkt = dsi_command(0xABCD, b"data");
        assert_eq!(&pkt[2..4], &[0xAB, 0xCD]);
    }
}
