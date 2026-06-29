//! PC-NFS authentication daemon — port 640/UDP, SunRPC program 150001 (pcnfsd).
//!
//! PC-NFS uses UDP datagrams carrying SunRPC/XDR-encoded calls.
//! Procedure 1 of program 150001 version 1 is the AUTH procedure: the client
//! sends (username, password, client-id) and the server replies with a status
//! word at bytes [24..28] of the RPC reply body (0 = success).
//!
//! Because `authenticate` receives a TCP-oriented `Target`, we bind a local
//! UDP socket and connect it to `target.host:target.port` directly.

use async_trait::async_trait;
use std::time::Instant;
use tokio::net::UdpSocket;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

// ── XDR helpers ───────────────────────────────────────────────────────────────

/// Encode a string as an XDR opaque (4-byte big-endian length + data + padding
/// to the next 4-byte boundary).
fn xdr_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let len = bytes.len() as u32;
    let pad = (4 - (bytes.len() % 4)) % 4;
    let mut out = Vec::with_capacity(4 + bytes.len() + pad);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    out.extend(std::iter::repeat(0u8).take(pad));
    out
}

// ── Packet builder ────────────────────────────────────────────────────────────

/// Build a complete pcnfsd AUTH RPC call datagram.
///
/// Layout:
/// ```text
/// XID(4)           — transaction id
/// type=0 CALL(4)
/// RPC version=2(4)
/// program=150001(4)
/// version=1(4)
/// procedure=1(4)   — AUTH
/// credentials AUTH_NULL(8)
/// verifier    AUTH_NULL(8)
/// XDR username
/// XDR password
/// XDR client-id
/// ```
fn build_pcnfs_auth_rpc(xid: u32, username: &str, password: &str) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&xid.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes());       // CALL
    pkt.extend_from_slice(&2u32.to_be_bytes());       // RPC v2
    pkt.extend_from_slice(&150001u32.to_be_bytes());  // pcnfsd program
    pkt.extend_from_slice(&1u32.to_be_bytes());       // version 1
    pkt.extend_from_slice(&1u32.to_be_bytes());       // AUTH procedure
    pkt.extend_from_slice(&[0u8; 8]);                 // credentials (AUTH_NULL)
    pkt.extend_from_slice(&[0u8; 8]);                 // verifier   (AUTH_NULL)
    pkt.extend_from_slice(&xdr_string(username));
    pkt.extend_from_slice(&xdr_string(password));
    pkt.extend_from_slice(&xdr_string("zeus"));       // client-id
    pkt
}

// ── Protocol ─────────────────────────────────────────────────────────────────

pub struct PcNfsProtocol;

#[async_trait]
impl Protocol for PcNfsProtocol {
    fn name(&self) -> &'static str { "pcnfs" }
    fn default_port(&self) -> u16 { 640 }
    fn description(&self) -> &'static str {
        "PC-NFS authentication daemon (UDP/RPC, program 150001)"
    }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        // Use a random XID so concurrent probes don't collide.
        let xid: u32 = rand_xid();

        let pkt = build_pcnfs_auth_rpc(xid, &cred.username, &cred.password);

        // Bind to any local port, then "connect" the UDP socket so that
        // send/recv operate against the target address.
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| ZeusError::Protocol(format!("UDP bind: {e}")))?;

        sock.connect(format!("{}:{}", target.host, target.port))
            .await
            .map_err(|e| ZeusError::Protocol(format!("UDP connect: {e}")))?;

        let start = Instant::now();

        // Send the RPC call.
        sock.send(&pkt)
            .await
            .map_err(|e| ZeusError::Protocol(format!("UDP send: {e}")))?;

        debug!("PcNFS: sent AUTH RPC xid={:#x} for {}", xid, cred.username);

        // Wait for a reply, respecting the configured timeout.
        let mut buf = vec![0u8; 512];
        let n = tokio::time::timeout(config.timeout, sock.recv(&mut buf))
            .await
            .map_err(|_| ZeusError::Timeout(config.timeout))?
            .map_err(|e| ZeusError::Protocol(format!("UDP recv: {e}")))?;

        let reply = &buf[..n];
        debug!("PcNFS: received {} bytes", n);

        // Validate XID matches (bytes 0..4 of the RPC reply).
        if n < 4 {
            return Ok(AttackResult::Error("PcNFS: reply too short".into()));
        }
        let reply_xid = u32::from_be_bytes([reply[0], reply[1], reply[2], reply[3]]);
        if reply_xid != xid {
            return Ok(AttackResult::Error(format!(
                "PcNFS: XID mismatch (sent {:#x}, got {:#x})",
                xid, reply_xid
            )));
        }

        // RPC reply type must be 1 (REPLY) at bytes [4..8].
        if n < 8 {
            return Ok(AttackResult::Error("PcNFS: reply too short for type field".into()));
        }
        let reply_type = u32::from_be_bytes([reply[4], reply[5], reply[6], reply[7]]);
        if reply_type != 1 {
            return Ok(AttackResult::Failure);
        }

        // accept_state at bytes [8..12]: 0 = MSG_ACCEPTED.
        // reply_state  at bytes [12..16]: 0 = SUCCESS.
        // pcnfsd auth status at bytes [24..28]: 0 = AUTH_RES_OK.
        if n >= 28 {
            let status = u32::from_be_bytes([reply[24], reply[25], reply[26], reply[27]]);
            debug!("PcNFS: auth status={}", status);
            if status == 0 {
                return Ok(AttackResult::Success {
                    credential: cred.clone(),
                    elapsed: start.elapsed(),
                });
            }
        }

        Ok(AttackResult::Failure)
    }
}

/// Simple pseudo-random XID based on current time nanos.
fn rand_xid() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0xDEAD_BEEF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcnfs_meta() {
        assert_eq!(PcNfsProtocol.name(), "pcnfs");
        assert_eq!(PcNfsProtocol.default_port(), 640);
    }

    #[test]
    fn xdr_string_alignment() {
        // Empty string → 4-byte length word only.
        assert_eq!(xdr_string(""), vec![0, 0, 0, 0]);

        // "abc" (3 bytes) → length(4) + "abc"(3) + pad(1) = 8 bytes.
        let enc = xdr_string("abc");
        assert_eq!(enc.len(), 8);
        assert_eq!(&enc[0..4], &[0, 0, 0, 3]);
        assert_eq!(&enc[4..7], b"abc");
        assert_eq!(enc[7], 0); // padding

        // "abcd" (4 bytes) → length(4) + "abcd"(4) = 8 bytes, no padding.
        let enc4 = xdr_string("abcd");
        assert_eq!(enc4.len(), 8);
    }

    #[test]
    fn pcnfs_rpc_packet_min_length() {
        // Fixed header (6 fields × 4 bytes) + 2 × AUTH_NULL (8 bytes each)
        // + at least the 3 XDR strings (each at least 4 bytes for empty).
        let pkt = build_pcnfs_auth_rpc(0x12345678, "user", "pass");
        // 6×4 + 8 + 8 + xdr("user")=8 + xdr("pass")=8 + xdr("zeus")=8 = 24+8+8+8+8+8 = 64
        assert!(pkt.len() >= 64, "packet too short: {}", pkt.len());
        // XID matches
        assert_eq!(&pkt[0..4], &0x12345678u32.to_be_bytes());
    }
}
