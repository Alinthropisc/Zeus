//! Oracle SID enumeration via raw TNS protocol.
//!
//! Sends a TNS CONNECT packet with a specific SID in the connect descriptor
//! and checks whether the TNS Listener accepts (SID exists) or refuses
//! (SID unknown).
//!
//! Wire flow:
//!   1. Connect to port 1521
//!   2. Send TNS CONNECT with `(SID=<sid_to_test>)` in connect descriptor
//!   3. TNS ACCEPT (type 2) → SID exists
//!      TNS REFUSE (type 4) → SID does not exist (also check for ORA-12514/12505)
//!
//! `cred.username` is treated as the SID to probe.
//! `cred.password` is ignored during enumeration.

use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct OracleSidProtocol;

// ── TNS constants ─────────────────────────────────────────────────────────────

const TNS_TYPE_CONNECT:  u8 = 1;
const TNS_TYPE_ACCEPT:   u8 = 2;
const TNS_TYPE_REFUSE:   u8 = 4;
const TNS_TYPE_REDIRECT: u8 = 5;
const TNS_TYPE_DATA:     u8 = 6;
const TNS_HDR_LEN:       usize = 8;
const TNS_TYPE_OFFSET:   usize = 4;

const TNS_CONNECT_VERSION:        u16 = 0x013A;
const TNS_CONNECT_VERSION_COMPAT: u16 = 0x0134;
const TNS_SERVICE_OPTIONS:        u16 = 0x0C41;
const TNS_SDU:                    u16 = 0x0800;
const TNS_TDU:                    u16 = 0x7FFF;
const TNS_NT_PROTOCOL:            u16 = 0x0000;
const TNS_LINE_TURNAROUND:        u16 = 0x0000;
const TNS_VALUE_OF_ONE:           u16 = 0x0001;
const TNS_MAX_RECV_CONNECT:       u32 = 512;
const TNS_CONNECT_FLAGS:          u8  = 0x04;
const TNS_CONNECT_FIXED_LEN:      usize = 28;
const TNS_CONNECT_DATA_OFFSET:    u16 = (TNS_HDR_LEN + TNS_CONNECT_FIXED_LEN) as u16;

// Oracle error codes that indicate the SID/service does not exist.
// 12514 = TNS: listener does not know of service requested
// 12505 = TNS: listener does not currently know of SID given in connect descriptor
const ORA_SID_NOT_FOUND_CODES: &[&[u8]] = &[b"12514", b"12505"];

// ── Packet builders ───────────────────────────────────────────────────────────

fn tns_packet(pkt_type: u8, body: &[u8]) -> Vec<u8> {
    let total = (TNS_HDR_LEN + body.len()) as u16;
    let mut pkt = Vec::with_capacity(TNS_HDR_LEN + body.len());
    pkt.extend_from_slice(&total.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.push(pkt_type);
    pkt.push(0x00);
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(body);
    pkt
}

fn build_connect_body(connect_data: &[u8]) -> Vec<u8> {
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

/// Build the connect descriptor for SID enumeration.
pub fn sid_connect_descriptor(host: &str, port: u16, sid: &str) -> String {
    format!(
        "(DESCRIPTION=(CONNECT_DATA=(SID={sid}))\
         (ADDRESS=(PROTOCOL=TCP)(HOST={host})(PORT={port})))"
    )
}

// ── Read helpers ──────────────────────────────────────────────────────────────

async fn read_tns_packet(conn: &mut TcpConnection) -> Result<Vec<u8>, ZeusError> {
    let header = conn.read_bytes(TNS_HDR_LEN).await
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
        conn.read_bytes(body_len).await
            .map_err(|e| ZeusError::Protocol(format!("TNS: body read failed: {e}")))?
    } else {
        vec![]
    };
    let mut pkt = header;
    pkt.extend_from_slice(&body);
    Ok(pkt)
}

/// Return true if the REFUSE payload contains a known "SID not found" error code.
pub fn sid_not_found(data: &[u8]) -> bool {
    ORA_SID_NOT_FOUND_CODES
        .iter()
        .any(|code| data.windows(code.len()).any(|w| w == *code))
}

// ── Protocol ─────────────────────────────────────────────────────────────────

#[async_trait]
impl Protocol for OracleSidProtocol {
    fn name(&self) -> &'static str { "oracle-sid" }
    fn default_port(&self) -> u16 { 1521 }
    fn description(&self) -> &'static str {
        "Oracle SID enumeration via TNS"
    }

    /// `cred.username` = SID to probe; `cred.password` is ignored.
    ///
    /// Returns `AttackResult::Success` when the SID exists on the target
    /// listener, `AttackResult::Failure` when the listener reports the SID
    /// is unknown, and `AttackResult::Error` for transport-level problems.
    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let sid = &cred.username;
        let port = target.port;
        let addr_str = format!("{}:{}", target.host, port);
        let addr = addr_str
            .to_socket_addrs()
            .map_err(ZeusError::Network)?
            .next()
            .ok_or_else(|| ZeusError::Protocol("DNS resolution failed".into()))?;

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // ── Send TNS CONNECT with the SID ──────────────────────────────────
        let desc = sid_connect_descriptor(&target.host, port, sid);
        debug!("OracleSid: probing SID='{}' descriptor={}", sid, desc);

        let connect_body = build_connect_body(desc.as_bytes());
        let connect_pkt  = tns_packet(TNS_TYPE_CONNECT, &connect_body);
        conn.write_all(&connect_pkt).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // ── Read listener response ─────────────────────────────────────────
        let resp = read_tns_packet(&mut conn).await?;
        let _ = conn.shutdown().await;

        if resp.len() < TNS_HDR_LEN {
            return Ok(AttackResult::Error("OracleSid: response too short".into()));
        }

        let resp_type = resp[TNS_TYPE_OFFSET];
        debug!("OracleSid: SID='{}' response type={}", sid, resp_type);

        match resp_type {
            TNS_TYPE_ACCEPT | TNS_TYPE_DATA => {
                // Listener accepted the connect descriptor → SID exists.
                Ok(AttackResult::Success {
                    credential: cred.clone(),
                    elapsed: start.elapsed(),
                })
            }
            TNS_TYPE_REDIRECT => {
                // Redirect indicates the listener knows of the SID but redirects
                // to a dedicated handler — treat as "found".
                Ok(AttackResult::Success {
                    credential: cred.clone(),
                    elapsed: start.elapsed(),
                })
            }
            TNS_TYPE_REFUSE => {
                // Check whether the REFUSE body contains an explicit "not found"
                // error code vs. a different error (e.g. access control).
                if sid_not_found(&resp) {
                    debug!("OracleSid: SID='{}' not found (12514/12505)", sid);
                    Ok(AttackResult::Failure)
                } else {
                    // REFUSE without a "not found" code may mean the SID exists
                    // but access is restricted — report as found.
                    Ok(AttackResult::Success {
                        credential: cred.clone(),
                        elapsed: start.elapsed(),
                    })
                }
            }
            other => {
                Ok(AttackResult::Error(
                    format!("OracleSid: unexpected TNS response type {}", other),
                ))
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_sid_meta() {
        let p = OracleSidProtocol;
        assert_eq!(p.name(), "oracle-sid");
        assert_eq!(p.default_port(), 1521);
    }

    #[test]
    fn oracle_sid_description_not_empty() {
        assert!(!OracleSidProtocol.description().is_empty());
    }

    #[test]
    fn sid_connect_descriptor_contains_sid() {
        let d = sid_connect_descriptor("localhost", 1521, "ORCL");
        assert!(d.contains("SID=ORCL"), "must contain SID=ORCL");
        assert!(d.contains("localhost"), "must contain host");
        assert!(d.contains("1521"), "must contain port");
    }

    #[test]
    fn sid_not_found_detects_12514() {
        assert!(sid_not_found(b"ORA-12514: TNS no service"));
        assert!(!sid_not_found(b"some other error"));
    }

    #[test]
    fn sid_not_found_detects_12505() {
        assert!(sid_not_found(b"ORA-12505 SID not known"));
        assert!(!sid_not_found(b"no error"));
    }

    #[test]
    fn tns_connect_packet_length_accurate() {
        let desc = sid_connect_descriptor("192.168.1.1", 1521, "TEST");
        let body  = build_connect_body(desc.as_bytes());
        let pkt   = tns_packet(TNS_TYPE_CONNECT, &body);
        let reported = u16::from_be_bytes([pkt[0], pkt[1]]) as usize;
        assert_eq!(reported, pkt.len());
    }

    #[test]
    fn tns_connect_type_byte_correct() {
        let pkt = tns_packet(TNS_TYPE_CONNECT, b"data");
        assert_eq!(pkt[TNS_TYPE_OFFSET], TNS_TYPE_CONNECT);
    }

    #[test]
    fn tns_connect_data_offset_is_36() {
        assert_eq!(TNS_CONNECT_DATA_OFFSET, 36);
    }

    #[test]
    fn connect_body_empty_sid_minimal_size() {
        let body = build_connect_body(b"");
        assert_eq!(body.len(), TNS_CONNECT_FIXED_LEN);
    }
}
