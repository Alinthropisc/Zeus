//! Novell NetWare Core Protocol (NCP) — port 524/TCP.
//!
//! NCP is a proprietary Novell protocol used by NetWare file servers.
//! Full authentication requires the WDOG (watchdog) timer, connection
//! maintenance, and the NDS/bindery challenge-response handshake, which is
//! extremely complex to replicate without a dedicated library.
//!
//! This implementation performs the initial TCP connection and sends a minimal
//! NCP connection request to verify the server is reachable and speaking NCP.
//! It then returns a descriptive error explaining what further work is needed
//! rather than silently producing wrong results.
//!
//! # NCP packet layout (simplified)
//!
//! ```text
//! Offset  Size  Field
//! ------  ----  -----
//! 0       2     Request type  (0x1111 = general request, 0x1234 = reply marker)
//! 2       1     Sequence number
//! 3       1     Connection number low
//! 4       1     Task number
//! 5       1     Connection number high
//! 6       1     Function code
//! 7       1     Subfunction length (for variable-length subfunctions)
//! ```
//!
//! Login uses function 23, subfunction 20 ("Login to File Server").

use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

// ── NCP constants ─────────────────────────────────────────────────────────────

/// NCP request marker — sent by the client.
const NCP_REQUEST_MARKER: [u8; 2] = [0x11, 0x11];

/// NCP reply marker — present in server responses.
const NCP_REPLY_MARKER: [u8; 2] = [0x12, 0x34];

/// NCP function 23: "File Server Environment Services".
#[allow(dead_code)]
const NCP_FUNC_SERVER_ENV: u8 = 23;

/// NCP subfunction 20: "Login to File Server".
#[allow(dead_code)]
const NCP_SUBFUNC_LOGIN: u8 = 20;

// ── Packet builder ────────────────────────────────────────────────────────────

/// Build a minimal NCP connection request (24-byte header, no payload).
///
/// This is enough to probe whether the server is speaking NCP without
/// attempting a full bindery login.
fn build_ncp_connect_request(sequence: u8) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(24);
    pkt.extend_from_slice(&NCP_REQUEST_MARKER); // request type
    pkt.push(sequence);                          // sequence number
    pkt.push(0xFF);                              // connection low (0xFF = create)
    pkt.push(0x00);                              // task number
    pkt.push(0xFF);                              // connection high (0xFF = create)
    pkt.push(0x00);                              // function code (0 = connect)
    pkt.push(0x00);                              // reserved
    // Pad to 24 bytes
    pkt.resize(24, 0x00);
    pkt
}

// ── Protocol ─────────────────────────────────────────────────────────────────

pub struct NcpProtocol;

#[async_trait]
impl Protocol for NcpProtocol {
    fn name(&self) -> &'static str { "ncp" }
    fn default_port(&self) -> u16 { 524 }
    fn description(&self) -> &'static str {
        "Novell NetWare NCP file server authentication (partial — handshake probe only)"
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

        let _start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // ── Step 1: send NCP connection request ───────────────────────────────
        let pkt = build_ncp_connect_request(0x01);
        conn.write_all(&pkt)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        debug!("NCP: sent connect request for {}", cred.username);

        // ── Step 2: read server response ──────────────────────────────────────
        let resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let _ = conn.shutdown().await;

        // Check for the NCP reply marker (bytes 0-1 = 0x12 0x34).
        let has_ncp_reply = resp.len() >= 2 && resp[0..2] == NCP_REPLY_MARKER;
        debug!("NCP: response len={} ncp_reply={}", resp.len(), has_ncp_reply);

        // ── Step 3: report partial implementation ─────────────────────────────
        // Full NCP authentication requires:
        //  1. Maintaining the connection number returned in the reply.
        //  2. Starting the WDOG (watchdog) timer loop.
        //  3. Sending NCP func=23, subfunc=20 with the username.
        //  4. Receiving an 8-byte NDS/bindery challenge.
        //  5. Computing the response with the proprietary DES-based algorithm.
        //  6. Sending the response and checking the completion code.
        //
        // This complexity requires a dedicated NetWare client library.
        Err(ZeusError::Protocol(
            "NCP full auth requires WDOG timer and connection maintenance; \
             partial handshake probe completed — integrate a NetWare client \
             library for full credential testing"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ncp_meta() {
        assert_eq!(NcpProtocol.name(), "ncp");
        assert_eq!(NcpProtocol.default_port(), 524);
    }

    #[test]
    fn ncp_description_not_empty() {
        assert!(!NcpProtocol.description().is_empty());
    }

    #[test]
    fn connect_request_is_24_bytes() {
        let pkt = build_ncp_connect_request(1);
        assert_eq!(pkt.len(), 24);
        assert_eq!(&pkt[0..2], &NCP_REQUEST_MARKER);
    }
}
