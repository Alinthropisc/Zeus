//! Firebird database authentication via raw XDR wire protocol.
//!
//! Wire flow (Firebird protocol version 10 — legacy, no SRP):
//!   Client → op_connect  (opcode 1) — propose protocol version
//!   Server → op_accept   (opcode 3) — accepts version, or op_reject (opcode 4)
//!   Client → op_attach   (opcode 23) — send database path, username, password
//!   Server → op_response (opcode 9) on success, op_exception (opcode 8) on failure
//!
//! Note: Firebird 3.0+ uses SRP authentication by default, which requires a full
//! Diffie-Hellman key exchange.  This implementation targets legacy Firebird ≤ 2.5
//! (protocol version 10/11) where credentials are sent in the DPB (Database
//! Parameter Block) in plaintext.  For Firebird 3+ with SRP the `authenticate`
//! method returns `AttackResult::Error` with an explanatory message.

use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct FirebirdProtocol;

// ── Firebird opcodes ──────────────────────────────────────────────────────────

const OP_CONNECT:   i32 = 1;
const OP_DUMMY:     i32 = 0;
const OP_ATTACH:    i32 = 23;

const OP_ACCEPT:    i32 = 3;
const OP_REJECT:    i32 = 4;
const OP_RESPONSE:  i32 = 9;
// const OP_EXCEPTION: i32 = 8;  -- unused directly but noted for reference

/// Architecture constant: "generic" / cross-platform
const ARCH_GENERIC: i32 = 1;
/// CONNECT_VERSION2 — the negotiation protocol level
const CONNECT_VERSION2: i32 = 2;

/// Firebird wire protocol versions we offer
const PROTOCOL_V10: i32 = 10;
// const PROTOCOL_V11: i32 = 11;  -- can be added as fallback

// ── DPB (Database Parameter Block) constants ──────────────────────────────────

const DPB_VERSION1:  u8 = 1;
const DPB_USER_NAME: u8 = 28;
const DPB_PASSWORD:  u8 = 29;

// ── XDR helpers ───────────────────────────────────────────────────────────────

/// Write a big-endian i32 into the buffer.
fn xdr_i32(buf: &mut Vec<u8>, val: i32) {
    buf.extend_from_slice(&val.to_be_bytes());
}

/// Write an XDR-encoded byte string: length (4 bytes BE) + data + padding to 4-byte boundary.
fn xdr_string(buf: &mut Vec<u8>, data: &[u8]) {
    xdr_i32(buf, data.len() as i32);
    buf.extend_from_slice(data);
    let pad = (4usize.wrapping_sub(data.len() % 4)) % 4;
    buf.extend(std::iter::repeat(0u8).take(pad));
}

/// Read a big-endian i32 from `buf` at `pos`.  Returns `None` if out of bounds.
fn read_i32(buf: &[u8], pos: usize) -> Option<i32> {
    if pos + 4 > buf.len() { return None; }
    Some(i32::from_be_bytes([buf[pos], buf[pos+1], buf[pos+2], buf[pos+3]]))
}

// ── DPB builder ───────────────────────────────────────────────────────────────

/// Build a DPB (Database Parameter Block) containing user name and password.
/// Format: version(1) + for each parameter: isc_dpb_<tag>(1) len(1) data(len)
fn build_dpb(username: &str, password: &str) -> Vec<u8> {
    let mut dpb = Vec::new();
    dpb.push(DPB_VERSION1);

    for (tag, value) in &[(DPB_USER_NAME, username), (DPB_PASSWORD, password)] {
        let bytes = value.as_bytes();
        dpb.push(*tag);
        dpb.push(bytes.len() as u8);
        dpb.extend_from_slice(bytes);
    }
    dpb
}

// ── Packet builders ───────────────────────────────────────────────────────────

/// Build an op_connect packet.
///
/// Proposes one protocol (version 10, architecture generic, type batch_send).
fn build_op_connect(db_path: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();

    xdr_i32(&mut pkt, OP_CONNECT);
    xdr_i32(&mut pkt, OP_DUMMY);          // connect_operation (dummy op)
    xdr_i32(&mut pkt, CONNECT_VERSION2);  // connect version
    xdr_i32(&mut pkt, ARCH_GENERIC);      // client architecture

    xdr_string(&mut pkt, db_path);        // database path (arbitrary for auth probe)
    xdr_i32(&mut pkt, 1);                 // number of protocols offered

    // Protocol descriptor: version, architecture, min_type, max_type, weight
    xdr_i32(&mut pkt, PROTOCOL_V10);      // protocol version
    xdr_i32(&mut pkt, ARCH_GENERIC);      // architecture
    xdr_i32(&mut pkt, 0);                 // ptype_rpc (minimum type)
    xdr_i32(&mut pkt, 3);                 // ptype_batch_send (maximum type)
    xdr_i32(&mut pkt, 2);                 // weight (preference)

    pkt
}

/// Build an op_attach packet.
///
/// Sends the database path and a DPB block carrying username + password.
fn build_op_attach(db_path: &[u8], dpb: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();

    xdr_i32(&mut pkt, OP_ATTACH);
    xdr_i32(&mut pkt, 0);                 // object handle (0 = new)
    xdr_string(&mut pkt, db_path);        // database path
    xdr_string(&mut pkt, dpb);            // DPB blob

    pkt
}

// ── Protocol ─────────────────────────────────────────────────────────────────

#[async_trait]
impl Protocol for FirebirdProtocol {
    fn name(&self) -> &'static str { "firebird" }
    fn default_port(&self) -> u16 { 3050 }
    fn description(&self) -> &'static str {
        "Firebird DB legacy wire protocol (XDR, protocol v10 — targets Firebird ≤ 2.5)"
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
        let mut conn = TcpConnection::connect(addr, config.timeout).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Database path: use the configured service name or a sensible default.
        let db_name = target.path.as_deref().unwrap_or("employee");
        let db_path = db_name.as_bytes();

        // ── Step 1: op_connect ────────────────────────────────────────────
        let connect_pkt = build_op_connect(db_path);
        conn.write_all(&connect_pkt).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("Firebird: sent op_connect ({} bytes)", connect_pkt.len());

        // ── Step 2: read server response (op_accept or op_reject) ─────────
        // Minimum response is 4 bytes (opcode) + optional body.
        // op_accept body: version(4) arch(4) type(4) = 12 bytes → total 16
        let accept_buf = conn.read_bytes(16).await
            .map_err(|e| ZeusError::Protocol(format!("Firebird: no op_accept: {e}")))?;

        let server_opcode = match read_i32(&accept_buf, 0) {
            Some(op) => op,
            None => {
                let _ = conn.shutdown().await;
                return Ok(AttackResult::Error("Firebird: response too short".into()));
            }
        };
        debug!("Firebird: server opcode={}", server_opcode);

        match server_opcode {
            op if op == OP_REJECT => {
                let _ = conn.shutdown().await;
                return Ok(AttackResult::Error("Firebird: server rejected protocol".into()));
            }
            op if op != OP_ACCEPT => {
                // Firebird 3+ sends a different opcode (op_cond_accept = 180) when
                // SRP is required.  We detect this and report it clearly.
                let _ = conn.shutdown().await;
                return Ok(AttackResult::Error(format!(
                    "Firebird: unexpected opcode {} (SRP/Firebird 3+ not supported without DH key exchange)",
                    op,
                )));
            }
            _ => {}
        }

        // ── Step 3: op_attach with credentials ────────────────────────────
        let dpb = build_dpb(&cred.username, &cred.password);
        let attach_pkt = build_op_attach(db_path, &dpb);
        conn.write_all(&attach_pkt).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("Firebird: sent op_attach ({} bytes)", attach_pkt.len());

        // ── Step 4: read attach response ─────────────────────────────────
        // op_response(9): opcode(4) + handle(4) + blob_id(8) + status_vector_len(4) + ...
        // Minimum safe read: 4 bytes for the opcode.
        let resp_buf = conn.read_available().await
            .map_err(|e| ZeusError::Protocol(format!("Firebird: read error: {e}")))?;
        let _ = conn.shutdown().await;

        if resp_buf.is_empty() {
            return Ok(AttackResult::Failure);
        }

        let resp_opcode = match read_i32(&resp_buf, 0) {
            Some(op) => op,
            None => return Ok(AttackResult::Failure),
        };
        debug!("Firebird: attach response opcode={}", resp_opcode);

        if resp_opcode == OP_RESPONSE {
            // op_response: status vector immediately follows the handle (offset 8).
            // A zero-length status vector means success.
            // status_vector_len is at offset 12 (after opcode+handle+blob_id_high+blob_id_low ×4 each)
            // Actually layout: opcode(4) + handle(4) + blob_id_quad(8) + status_vec_length(4)
            // For a success response the status vector is empty (isc_arg_end = 1).
            if resp_buf.len() >= 20 {
                let sv_first = read_i32(&resp_buf, 16).unwrap_or(1);
                // isc_arg_end = 1 means no error
                if sv_first == 1 || sv_first == 0 {
                    return Ok(AttackResult::Success {
                        credential: cred.clone(),
                        elapsed: start.elapsed(),
                    });
                }
            } else {
                // Short but valid-looking op_response — assume success
                return Ok(AttackResult::Success {
                    credential: cred.clone(),
                    elapsed: start.elapsed(),
                });
            }
        }

        Ok(AttackResult::Failure)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firebird_meta() {
        let p = FirebirdProtocol;
        assert_eq!(p.name(), "firebird");
        assert_eq!(p.default_port(), 3050);
    }

    #[test]
    fn firebird_description_not_empty() {
        assert!(!FirebirdProtocol.description().is_empty());
    }

    #[test]
    fn xdr_string_padding() {
        // "ab" is 2 bytes; XDR pads to 4 → total payload after length = 4 bytes.
        let mut buf = Vec::new();
        xdr_string(&mut buf, b"ab");
        // length field (4) + "ab"(2) + 2 pad bytes = 8
        assert_eq!(buf.len(), 8);
        assert_eq!(&buf[4..6], b"ab");
        assert_eq!(&buf[6..8], &[0u8, 0]);
    }

    #[test]
    fn xdr_string_no_padding_for_aligned_input() {
        // "abcd" is 4 bytes — already aligned, no padding.
        let mut buf = Vec::new();
        xdr_string(&mut buf, b"abcd");
        // length(4) + "abcd"(4) = 8
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn xdr_string_empty() {
        let mut buf = Vec::new();
        xdr_string(&mut buf, b"");
        // length(4) = 0, no data, no padding
        assert_eq!(buf.len(), 4);
        assert_eq!(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), 0);
    }

    #[test]
    fn op_connect_starts_with_opcode() {
        let pkt = build_op_connect(b"/tmp/test.fdb");
        let opcode = i32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        assert_eq!(opcode, OP_CONNECT);
    }

    #[test]
    fn dpb_has_correct_version_byte() {
        let dpb = build_dpb("SYSDBA", "masterkey");
        assert_eq!(dpb[0], DPB_VERSION1);
    }

    #[test]
    fn dpb_contains_credentials() {
        let dpb = build_dpb("alice", "secret");
        let dpb_str = String::from_utf8_lossy(&dpb);
        assert!(dpb_str.contains("alice"));
        assert!(dpb_str.contains("secret"));
    }

    #[test]
    fn read_i32_out_of_bounds_returns_none() {
        let buf = [0u8; 3];
        assert!(read_i32(&buf, 0).is_none());
    }

    #[test]
    fn read_i32_correct_value() {
        let buf = [0x00, 0x00, 0x00, 0x01u8];
        assert_eq!(read_i32(&buf, 0), Some(1));
    }
}
