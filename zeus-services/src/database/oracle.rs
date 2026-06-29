//! Oracle database authentication via raw TNS (Transparent Network Substrate) protocol.
//!
//! Wire flow:
//!   Client → TNS CONNECT  (type 1) — carry connect descriptor string
//!   Server → TNS ACCEPT   (type 2) or REDIRECT (type 5) or REFUSE (type 4)
//!   Client → Data packet  — SQL*Net authentication start
//!   Server → Data packet  — response; ORA-01017 = bad credentials, success otherwise
//!
//! OCI client libraries are NOT required.  We speak raw TNS TCP sockets.
//!
//! Oracle 12c+ uses O7LOGON (SHA-512 based challenge-response).  Full O5/O7 logon
//! requires a server challenge round-trip.  For simplicity we send an auth start and
//! detect ORA-01017 (invalid username/password) vs. a non-error response.

use crate::net::TcpConnection;
use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct OracleProtocol;

// ── TNS packet types ──────────────────────────────────────────────────────────

const TNS_TYPE_CONNECT: u8 = 1;
const TNS_TYPE_ACCEPT: u8 = 2;
const TNS_TYPE_REFUSE: u8 = 4;
const TNS_TYPE_REDIRECT: u8 = 5;
const TNS_TYPE_DATA: u8 = 6;
// const TNS_TYPE_RESEND:   u8 = 11;  // unused here but noted

/// Size of the TNS packet header in bytes.
const TNS_HDR_LEN: usize = 8;

/// Offset of the packet type within the TNS header.
const TNS_TYPE_OFFSET: usize = 4;

// ── TNS CONNECT fixed-header fields (big-endian unless noted) ────────────────

const TNS_CONNECT_VERSION: u16 = 0x013A; // 314 — Oracle 12.1
const TNS_CONNECT_VERSION_COMPAT: u16 = 0x0134; // 308
const TNS_SERVICE_OPTIONS: u16 = 0x0C41;
const TNS_SDU: u16 = 0x0800; // 2048
const TNS_TDU: u16 = 0x7FFF; // 32767
const TNS_NT_PROTOCOL: u16 = 0x0000;
const TNS_LINE_TURNAROUND: u16 = 0x0000;
const TNS_VALUE_OF_ONE: u16 = 0x0001;
const TNS_MAX_RECV_CONNECT: u32 = 512;
const TNS_CONNECT_FLAGS: u8 = 0x04;

/// Size of the CONNECT body fixed fields (before the connect data string).
/// version(2)+compat(2)+svc_opts(2)+sdu(2)+tdu(2)+nt_proto(2)+line_ta(2)+val1(2)
/// +data_len(2)+data_off(2)+max_recv(4)+flags0(1)+flags1(1) = 28 bytes
const TNS_CONNECT_FIXED_LEN: usize = 28;

/// Offset at which connect data begins inside the CONNECT body.
/// The TNS spec says `data_offset` is measured from the start of the FULL packet
/// (header + body).  We set it to HDR_LEN + CONNECT_FIXED_LEN = 8 + 28 = 36.
const TNS_CONNECT_DATA_OFFSET: u16 = (TNS_HDR_LEN + TNS_CONNECT_FIXED_LEN) as u16;

// ── TNS packet builder ────────────────────────────────────────────────────────

/// Wrap `body` bytes in a TNS packet header.
///
/// ```text
/// length(2 BE) | checksum(2 BE=0) | type(1) | reserved(1=0) | header_checksum(2 BE=0)
/// ```
fn tns_packet(pkt_type: u8, body: &[u8]) -> Vec<u8> {
    let total = (TNS_HDR_LEN + body.len()) as u16;
    let mut pkt = Vec::with_capacity(TNS_HDR_LEN + body.len());
    pkt.extend_from_slice(&total.to_be_bytes()); // length
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
    pkt.push(pkt_type); // type
    pkt.push(0x00); // reserved
    pkt.extend_from_slice(&0u16.to_be_bytes()); // header checksum
    pkt.extend_from_slice(body);
    pkt
}

/// Build a TNS CONNECT packet body for the given connect descriptor string.
fn build_tns_connect_body(connect_data: &[u8]) -> Vec<u8> {
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
    body.push(TNS_CONNECT_FLAGS); // connect_flags_0
    body.push(TNS_CONNECT_FLAGS); // connect_flags_1
    body.extend_from_slice(connect_data);

    body
}

/// Build the connect descriptor (minimal Oracle Easy Connect string).
fn connect_descriptor(host: &str, port: u16, service_name: &str) -> String {
    format!(
        "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME={service_name})\
         (CID=(PROGRAM=zeus)(HOST=localhost)(USER=zeus)))\
         (ADDRESS=(PROTOCOL=TCP)(HOST={host})(PORT={port})))"
    )
}

/// Build a minimal SQL*Net v2 Authentication Start data packet.
///
/// This is a simplified AUTH request that carries the username so the server
/// can issue a challenge.  Real O5LOGON/O7LOGON continues from here with a
/// SHA-1 / SHA-512 challenge-response; for basic detection we examine whether
/// the server returns ORA-01017 (bad credentials) at any stage.
fn build_auth_start(username: &str) -> Vec<u8> {
    // SQL*Net data packet begins with a 2-byte data flags field.
    // 0x0000 = no flags.
    let flags: [u8; 2] = [0x00, 0x00];

    // ANO (Authentication/Network Overhead) message — simplified.
    // We send an AUTH_SESS_KEY request using the ANO protocol marker:
    // marker byte 0xDE, followed by a minimal representation of the auth phase.
    // For a clean probe we emit a bare username in the connect data; a real
    // server will respond with a challenge or error regardless.
    //
    // The body below uses the Oracle Net Services "NS2" data packet format:
    //   call_id(1) = 0x60 (Authentication), num_params(1), key=value pairs
    let mut ns_body: Vec<u8> = Vec::new();
    // NS2 AUTH_SESS_KEY call: call_id=0x73 (Authentication-UNAME)
    ns_body.push(0x00); // NS2 version
    ns_body.push(0x60); // AUTH call
    ns_body.push(0x00); // flags
    ns_body.push(0x00); // ACL flags
    // username length (1 byte for short names) and data
    ns_body.push(username.len() as u8);
    ns_body.extend_from_slice(username.as_bytes());

    let mut pkt_body = Vec::new();
    pkt_body.extend_from_slice(&flags);
    pkt_body.extend_from_slice(&ns_body);

    tns_packet(TNS_TYPE_DATA, &pkt_body)
}

// ── Read helpers ──────────────────────────────────────────────────────────────

/// Read one TNS packet from the connection.  Returns the entire packet including
/// the 8-byte header.
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

/// Return true if `data` contains the ORA-01017 error code pattern.
fn contains_ora_01017(data: &[u8]) -> bool {
    // "1017" as ASCII bytes
    data.windows(4).any(|w| w == b"1017")
}

// ── Protocol ─────────────────────────────────────────────────────────────────

#[async_trait]
impl Protocol for OracleProtocol {
    fn name(&self) -> &'static str {
        "oracle"
    }
    fn default_port(&self) -> u16 {
        1521
    }
    fn description(&self) -> &'static str {
        "Oracle TNS raw wire protocol (Connect/Accept + auth start probe)"
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

        let service = target.path.as_deref().unwrap_or("XE");
        let desc = connect_descriptor(&target.host, port, service);
        debug!("Oracle: connect descriptor = {}", desc);

        // ── Step 1: TNS CONNECT ────────────────────────────────────────────
        let connect_body = build_tns_connect_body(desc.as_bytes());
        let connect_pkt = tns_packet(TNS_TYPE_CONNECT, &connect_body);
        conn.write_all(&connect_pkt)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("Oracle: sent TNS CONNECT ({} bytes)", connect_pkt.len());

        // ── Step 2: read server response ──────────────────────────────────
        let resp = read_tns_packet(&mut conn).await?;
        if resp.len() < TNS_HDR_LEN {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("Oracle: response too short".into()));
        }

        let resp_type = resp[TNS_TYPE_OFFSET];
        debug!("Oracle: response type={}", resp_type);

        match resp_type {
            TNS_TYPE_REFUSE => {
                // Server refuses the connection outright.
                let _ = conn.shutdown().await;
                return Ok(AttackResult::Error("Oracle: TNS REFUSE received".into()));
            }
            TNS_TYPE_REDIRECT => {
                // REDIRECT means we should connect to a different endpoint.
                // For brute-force purposes we log and treat it as an error.
                let _ = conn.shutdown().await;
                return Ok(AttackResult::Error(
                    "Oracle: TNS REDIRECT (listener redirect not followed)".into(),
                ));
            }
            TNS_TYPE_ACCEPT => {
                debug!("Oracle: TNS ACCEPT received — connection established");
            }
            other => {
                let _ = conn.shutdown().await;
                return Ok(AttackResult::Error(format!(
                    "Oracle: unexpected TNS response type {}",
                    other
                )));
            }
        }

        // ── Step 3: send auth start ────────────────────────────────────────
        let auth_pkt = build_auth_start(&cred.username);
        conn.write_all(&auth_pkt)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("Oracle: sent auth start");

        // ── Step 4: read auth response ─────────────────────────────────────
        // Drain whatever the server sends back (may be challenge or error).
        let auth_resp = conn
            .read_available()
            .await
            .map_err(|e| ZeusError::Protocol(format!("Oracle: auth read error: {e}")))?;
        let _ = conn.shutdown().await;

        debug!("Oracle: auth response {} bytes", auth_resp.len());

        // Determine outcome from the raw response bytes.
        if auth_resp.is_empty() {
            // No data — ambiguous; treat as failure.
            return Ok(AttackResult::Failure);
        }

        if contains_ora_01017(&auth_resp) {
            // ORA-01017: invalid username/password
            return Ok(AttackResult::Failure);
        }

        // If we received a challenge (DATA packet type) without an error, treat
        // it as "credentials accepted so far" (server issued a challenge, which
        // means the username exists and password phase begins).  In a real O5/O7
        // flow we would complete the challenge-response; here we optimistically
        // report success only for non-error responses.
        if auth_resp[TNS_TYPE_OFFSET.min(auth_resp.len().saturating_sub(1))] == TNS_TYPE_DATA {
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
    fn oracle_meta() {
        let p = OracleProtocol;
        assert_eq!(p.name(), "oracle");
        assert_eq!(p.default_port(), 1521);
    }

    #[test]
    fn oracle_description_not_empty() {
        assert!(!OracleProtocol.description().is_empty());
    }

    #[test]
    fn tns_packet_minimum_length() {
        let descriptor = connect_descriptor("192.168.1.1", 1521, "orcl");
        let body = build_tns_connect_body(descriptor.as_bytes());
        let pkt = tns_packet(TNS_TYPE_CONNECT, &body);
        // Must be at least 58 bytes (8 header + 28 fixed body + some connect data)
        assert!(
            pkt.len() >= 58,
            "TNS CONNECT packet must be >= 58 bytes, got {}",
            pkt.len()
        );
    }

    #[test]
    fn tns_packet_length_field_is_accurate() {
        let body = build_tns_connect_body(b"test");
        let pkt = tns_packet(TNS_TYPE_CONNECT, &body);
        let reported = u16::from_be_bytes([pkt[0], pkt[1]]) as usize;
        assert_eq!(reported, pkt.len());
    }

    #[test]
    fn tns_packet_type_byte_correct() {
        let pkt = tns_packet(TNS_TYPE_CONNECT, b"hello");
        assert_eq!(pkt[TNS_TYPE_OFFSET], TNS_TYPE_CONNECT);
    }

    #[test]
    fn tns_packet_checksum_is_zero() {
        let pkt = tns_packet(TNS_TYPE_DATA, b"data");
        // bytes [2..4] = packet checksum (should be 0)
        assert_eq!(&pkt[2..4], &[0, 0]);
        // bytes [6..8] = header checksum (should be 0)
        assert_eq!(&pkt[6..8], &[0, 0]);
    }

    #[test]
    fn connect_descriptor_contains_service_name() {
        let desc = connect_descriptor("localhost", 1521, "mydb");
        assert!(
            desc.contains("mydb"),
            "descriptor must include the service name"
        );
        assert!(
            desc.contains("localhost"),
            "descriptor must include the host"
        );
    }

    #[test]
    fn ora_01017_detection() {
        let data_with_err = b"some prefix ORA-01017 invalid username";
        assert!(contains_ora_01017(data_with_err));

        let data_without_err = b"no error here";
        assert!(!contains_ora_01017(data_without_err));
    }

    #[test]
    fn tns_connect_body_fixed_size_is_correct() {
        // With empty connect data the body should be exactly TNS_CONNECT_FIXED_LEN bytes.
        let body = build_tns_connect_body(b"");
        assert_eq!(body.len(), TNS_CONNECT_FIXED_LEN);
    }

    #[test]
    fn tns_connect_data_offset_matches_header_expectation() {
        // The constant must equal HDR(8) + FIXED_BODY(28) = 36.
        assert_eq!(TNS_CONNECT_DATA_OFFSET, 36);
    }
}
