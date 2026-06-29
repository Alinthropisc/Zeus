//! Siemens S7-300 PLC SCADA authentication, port 102 (ISO-TSAP/COTP).

use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct S7300Protocol;

// ── wire constants ────────────────────────────────────────────────────────────

const P_COTP: &[u8] = &[
    0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00,
    0x00, 0x17, 0x00, 0xc1, 0x02, 0x01, 0x00, 0xc2,
    0x02, 0x01, 0x02, 0xc0, 0x01, 0x0a,
];

const P_S7_NEGOTIATE: &[u8] = &[
    0x03, 0x00, 0x00, 0x19, 0x02, 0xf0, 0x80, 0x32,
    0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x08, 0x00,
    0x00, 0xf0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xe0,
];

const P_S7_READ_SZL: &[u8] = &[
    0x03, 0x00, 0x00, 0x21, 0x02, 0xf0, 0x80, 0x32,
    0x07, 0x00, 0x00, 0x03, 0x00, 0x00, 0x08, 0x00,
    0x08, 0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01,
    0x00, 0xff, 0x09, 0x00, 0x04, 0x01, 0x32, 0x00, 0x04,
];

const P_S7_PASSWORD_REQUEST_HDR: &[u8] = &[
    0x03, 0x00, 0x00, 0x25, 0x02, 0xf0, 0x80, 0x32,
    0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
    0x0c, 0x00, 0x01, 0x12, 0x04, 0x11, 0x45, 0x01,
    0x00, 0xff, 0x09, 0x00, 0x08,
];

// ── password encoding ─────────────────────────────────────────────────────────

/// Right-pad `password` with spaces to 8 bytes, then apply the S7-300 rolling
/// XOR encoding used by Siemens for PLC access protection.
fn encode_s7_password(password: &str) -> [u8; 8] {
    let mut context = [b' '; 8];
    for (i, b) in password.bytes().take(8).enumerate() {
        context[i] = b;
    }
    let mut encoded = [0u8; 8];
    encoded[0] = context[0] ^ 0x55;
    encoded[1] = context[1] ^ 0x55;
    for i in 2..8 {
        encoded[i] = context[i] ^ encoded[i - 2] ^ 0x55;
    }
    encoded
}

// ── protocol impl ─────────────────────────────────────────────────────────────

#[async_trait]
impl Protocol for S7300Protocol {
    fn name(&self) -> &'static str { "s7-300" }
    fn default_port(&self) -> u16 { 102 }
    fn description(&self) -> &'static str { "Siemens S7-300 PLC SCADA authentication" }

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

        // Step 1 – COTP connect
        conn.write_all(P_COTP)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let r1 = conn.read_until_crlf().await.map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("S7-300 COTP resp: {:02x?}", r1);
        if r1.len() < 2 || r1[0] != 0x03 || r1[1] != 0x00 {
            return Ok(AttackResult::Error("unexpected COTP response".into()));
        }

        // Step 2 – S7 negotiate PDU
        conn.write_all(P_S7_NEGOTIATE)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let r2 = conn.read_until_crlf().await.map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("S7-300 negotiate resp: {:02x?}", r2);
        if r2.len() < 2 || r2[0] != 0x03 || r2[1] != 0x00 {
            return Ok(AttackResult::Error("unexpected negotiate response".into()));
        }

        // Step 3 – read SZL (protection level)
        conn.write_all(P_S7_READ_SZL)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let r3 = conn.read_until_crlf().await.map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("S7-300 SZL resp: {:02x?}", r3);
        // Bytes 27-28 indicate protection level; 0x00 0x00 = no password needed
        if r3.len() > 28 && r3[27] == 0x00 && r3[28] == 0x00 {
            return Ok(AttackResult::Success { credential: cred.clone(), elapsed: start.elapsed() });
        }

        // Step 4 – send password request
        let encoded = encode_s7_password(&cred.password);
        let mut pwd_req = P_S7_PASSWORD_REQUEST_HDR.to_vec();
        pwd_req.extend_from_slice(&encoded);
        conn.write_all(&pwd_req)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let r4 = conn.read_until_crlf().await.map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("S7-300 auth resp: {:02x?}", r4);
        let _ = conn.shutdown().await;

        // response[17] == 0x00 → S7 function returned OK
        if r4.len() > 17 && r4[17] == 0x00 {
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
    fn s7_meta() {
        let p = S7300Protocol;
        assert_eq!(p.name(), "s7-300");
        assert_eq!(p.default_port(), 102);
    }

    #[test]
    fn s7_password_encoding_known() {
        // "12345678" should produce a deterministic encoded sequence.
        let encoded = encode_s7_password("12345678");
        // Verify the encoding is deterministic (calling twice gives same result)
        assert_eq!(encoded, encode_s7_password("12345678"));
        // Manually verify first two bytes: '1'^0x55 = 0x31^0x55 = 0x64, '2'^0x55 = 0x32^0x55 = 0x67
        assert_eq!(encoded[0], b'1' ^ 0x55);
        assert_eq!(encoded[1], b'2' ^ 0x55);
        // Byte 2: '3' ^ encoded[0] ^ 0x55
        assert_eq!(encoded[2], b'3' ^ encoded[0] ^ 0x55);
    }

    #[test]
    fn s7_password_empty_pads_spaces() {
        let encoded = encode_s7_password("");
        // All context bytes are 0x20 (space), so:
        // encoded[0] = 0x20 ^ 0x55 = 0x75
        // encoded[1] = 0x20 ^ 0x55 = 0x75
        // encoded[2] = 0x20 ^ encoded[0] ^ 0x55 = 0x20 ^ 0x75 ^ 0x55 = 0x20
        assert_eq!(encoded[0], b' ' ^ 0x55);
        assert_eq!(encoded[1], b' ' ^ 0x55);
        assert_eq!(encoded[2], b' ' ^ encoded[0] ^ 0x55);
    }
}
