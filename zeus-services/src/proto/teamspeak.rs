//! TeamSpeak 2 TCP authentication, port 8767.

use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::sync::OnceLock;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct TeamSpeakProtocol;

// ── CRC32 (IEEE 802.3 / zlib) ────────────────────────────────────────────────

fn crc32(data: &[u8]) -> u32 {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for i in 0..256 {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            t[i] = c;
        }
        t
    });
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc = table[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

// ── packet builder ────────────────────────────────────────────────────────────

/// Copy `src` into the first `src.len()` bytes of `dst[..29]`.
/// Remaining bytes in `dst` are left as zero (already zeroed by default).
fn copy_field(dst: &mut [u8; 29], src: &[u8]) {
    let n = src.len().min(29);
    dst[..n].copy_from_slice(&src[..n]);
}

/// Build a 180-byte TeamSpeak 2 login packet.
///
/// Layout (total = 16 + 4 + 1+29 + 1+29 + 10 + 1+29 + 1+29 + 1+29 = 180 bytes):
/// - header   : 16 bytes  (\xf4\xbe\x03\x00 + 12 zeros)
/// - crc      : 4 bytes   (CRC32 of whole struct with crc=0)
/// - client   : 1+29 = 30 bytes
/// - os       : 1+29 = 30 bytes
/// - misc     : 10 bytes
/// - user     : 1+29 = 30 bytes
/// - pass     : 1+29 = 30 bytes
/// - login    : 1+29 = 30 bytes
fn build_ts2_packet(username: &str, password: &str) -> [u8; 180] {
    let mut pkt = [0u8; 180];

    // header: \xf4\xbe\x03\x00 followed by 12 zeros
    pkt[0] = 0xf4;
    pkt[1] = 0xbe;
    pkt[2] = 0x03;
    pkt[3] = 0x00;
    // bytes 4-15 remain zero

    // crc at bytes 16-19 — computed after, leave as zero for now

    // client_len + client  (offset 20)
    let client_str = b"TeamSpeak";
    pkt[20] = 9; // client_len
    let mut client_field = [0u8; 29];
    copy_field(&mut client_field, client_str);
    pkt[21..50].copy_from_slice(&client_field);

    // os_len + os  (offset 50)
    let os_str = b"Linux 2.6.9";
    pkt[50] = 11; // os_len
    let mut os_field = [0u8; 29];
    copy_field(&mut os_field, os_str);
    pkt[51..80].copy_from_slice(&os_field);

    // misc  (offset 80, 10 bytes)
    let misc: [u8; 10] = [0x02, 0x00, 0x00, 0x00, 0x20, 0x00, 0x3c, 0x00, 0x01, 0x02];
    pkt[80..90].copy_from_slice(&misc);

    // user_len + user  (offset 90)
    let uname = username.as_bytes();
    pkt[90] = uname.len().min(29) as u8;
    let mut user_field = [0u8; 29];
    copy_field(&mut user_field, uname);
    pkt[91..120].copy_from_slice(&user_field);

    // pass_len + pass  (offset 120)
    let pword = password.as_bytes();
    pkt[120] = pword.len().min(29) as u8;
    let mut pass_field = [0u8; 29];
    copy_field(&mut pass_field, pword);
    pkt[121..150].copy_from_slice(&pass_field);

    // login_len + login  (offset 150) — empty login token
    pkt[150] = 0;
    // pkt[151..180] remain zero

    // compute and embed CRC32
    let checksum = crc32(&pkt);
    pkt[16..20].copy_from_slice(&checksum.to_le_bytes());

    pkt
}

// ── protocol impl ─────────────────────────────────────────────────────────────

#[async_trait]
impl Protocol for TeamSpeakProtocol {
    fn name(&self) -> &'static str { "teamspeak" }
    fn default_port(&self) -> u16 { 8767 }
    fn description(&self) -> &'static str { "TeamSpeak 2 authentication" }

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

        let pkt = build_ts2_packet(&cred.username, &cred.password);
        conn.write_all(&pkt)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("TeamSpeak2 resp: {:02x?}", resp);
        let _ = conn.shutdown().await;

        if resp.len() < 3 {
            return Ok(AttackResult::Error("short response".into()));
        }

        // Banned → rate-limit back-off
        if resp.contains(&0x06) {
            return Ok(AttackResult::RateLimit);
        }

        // Success indicator at byte 2
        if resp[2] == 0x01 {
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
    fn teamspeak_meta() {
        let p = TeamSpeakProtocol;
        assert_eq!(p.name(), "teamspeak");
        assert_eq!(p.default_port(), 8767);
    }

    #[test]
    fn teamspeak_packet_size() {
        let pkt = build_ts2_packet("admin", "secret");
        assert_eq!(pkt.len(), 180);
    }

    #[test]
    fn crc32_known() {
        // Standard CRC32 check value for b"123456789" is 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        // Empty input
        assert_eq!(crc32(b""), 0x0000_0000);
    }
}
