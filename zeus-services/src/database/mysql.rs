//! MySQL authentication via the native password handshake (mysql_native_password).
//!
//! Wire flow:
//!   Server → HandshakeV10  (greeting with auth-plugin-data / salt)
//!   Client → HandshakeResponse41 (capabilities, charset, username, auth-response)
//!   Server → OK_Packet or ERR_Packet

use crate::net::TcpConnection;
use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use zeus_crypto::{sha1, to_hex};

pub struct MySqlProtocol;

// ── Crypto ────────────────────────────────────────────────────────────────────

/// mysql_native_password: SHA1(pass) XOR SHA1(salt || SHA1(SHA1(pass)))
fn mysql_native_password(password: &str, salt: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return vec![];
    }
    let h1 = sha1(password.as_bytes()); // SHA1(pass)
    let h2 = sha1(&h1); // SHA1(SHA1(pass))
    let mut combined = salt.to_vec();
    combined.extend_from_slice(&h2);
    let h3 = sha1(&combined); // SHA1(salt || SHA1(SHA1(pass)))
    h1.iter().zip(h3.iter()).map(|(a, b)| a ^ b).collect()
}

// ── Packet helpers ────────────────────────────────────────────────────────────

/// Read a MySQL packet: 3-byte length + 1-byte sequence, then payload.
async fn read_packet(conn: &mut TcpConnection) -> Result<Vec<u8>, ZeusError> {
    // We reuse read_until_crlf but need raw bytes.  We read the 4-byte header
    // first, then the body.  Since TcpConnection only exposes read_until_crlf
    // we collect enough bytes by reading multiple times if needed.
    //
    // Approach: send nothing, then call read_until_crlf which keeps reading
    // until \r\n or EOF.  MySQL packets never contain bare \r\n in the header,
    // but the *greeting* body may not end with \r\n.  We rely on the fact that
    // `read_until_crlf` breaks on EOF (n==0) too, so for the greeting we get
    // the whole buffer.
    let buf = conn
        .read_until_crlf()
        .await
        .map_err(|e| ZeusError::Protocol(e.to_string()))?;
    if buf.len() < 4 {
        return Err(ZeusError::Protocol("MySQL: packet too short".into()));
    }
    Ok(buf.to_vec())
}

/// Build a 3-byte-length + seq MySQL packet wrapper.
fn make_packet(seq: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut pkt = Vec::with_capacity(4 + payload.len());
    pkt.push((len & 0xFF) as u8);
    pkt.push(((len >> 8) & 0xFF) as u8);
    pkt.push(((len >> 16) & 0xFF) as u8);
    pkt.push(seq);
    pkt.extend_from_slice(payload);
    pkt
}

/// Build HandshakeResponse41 (client auth packet).
fn build_handshake_response(username: &str, auth_response: &[u8], database: &str) -> Vec<u8> {
    // Capability flags: CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 |
    //                   CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB
    let caps: u32 = 0x0000_0001   // CLIENT_LONG_PASSWORD
        | 0x0000_0200              // CLIENT_FOUND_ROWS (harmless)
        | 0x0000_0008              // CLIENT_NO_SCHEMA — omit DB prefix
        | 0x0002_0000              // CLIENT_PROTOCOL_41
        | 0x0008_0000              // CLIENT_SECURE_CONNECTION
        | 0x0000_0008; // CLIENT_CONNECT_WITH_DB re-added below
    let caps: u32 = if !database.is_empty() {
        caps | 0x0000_0008
    } else {
        caps & !0x0000_0008
    };

    let mut payload = Vec::new();
    payload.extend_from_slice(&caps.to_le_bytes());
    payload.extend_from_slice(&(0x00FF_FFFFu32).to_le_bytes()); // max_packet_size
    payload.push(0x21); // utf8 charset
    payload.extend_from_slice(&[0u8; 23]); // filler
    // username (null-terminated)
    payload.extend_from_slice(username.as_bytes());
    payload.push(0x00);
    // auth-response length-encoded (1 byte length prefix for ≤255 bytes)
    payload.push(auth_response.len() as u8);
    payload.extend_from_slice(auth_response);
    // database (null-terminated) if present
    if !database.is_empty() {
        payload.extend_from_slice(database.as_bytes());
        payload.push(0x00);
    }
    payload
}

// ── Protocol ─────────────────────────────────────────────────────────────────

#[async_trait]
impl Protocol for MySqlProtocol {
    fn name(&self) -> &'static str {
        "mysql"
    }
    fn default_port(&self) -> u16 {
        3306
    }
    fn description(&self) -> &'static str {
        "MySQL native-password handshake (Protocol 41)"
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

        // ── Step 1: receive HandshakeV10 greeting ──────────────────────────
        let greeting = read_packet(&mut conn).await?;
        debug!("MySQL greeting {} bytes", greeting.len());

        // greeting[0..3] = payload length, [3] = seq (0)
        // greeting[4]    = protocol version (should be 10)
        if greeting.len() < 36 {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("MySQL: greeting too short".into()));
        }
        if greeting[4] == 0xFF {
            // ERR packet before auth — server refused connection
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error(
                "MySQL: server sent error before auth".into(),
            ));
        }
        if greeting[4] != 0x0A {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error(format!(
                "MySQL: unsupported protocol version {}",
                greeting[4]
            )));
        }

        // Skip protocol_version(1) + server_version(null-term string) to find auth-plugin-data
        let mut pos = 5usize; // after the 4-byte packet header
        // Find end of server_version string
        while pos < greeting.len() && greeting[pos] != 0x00 {
            pos += 1;
        }
        pos += 1; // skip null terminator

        // connection_id (4 bytes)
        pos += 4;

        // auth-plugin-data-part-1 (8 bytes)
        if pos + 8 > greeting.len() {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error(
                "MySQL: greeting truncated at salt1".into(),
            ));
        }
        let salt1 = greeting[pos..pos + 8].to_vec();
        pos += 8;
        pos += 1; // filler 0x00

        // capability flags lower 2 bytes
        pos += 2;
        // character set
        pos += 1;
        // status flags
        pos += 2;
        // capability flags upper 2 bytes
        pos += 2;
        // auth_plugin_data_len (1 byte)
        let plugin_data_len = if pos < greeting.len() {
            greeting[pos] as usize
        } else {
            0
        };
        pos += 1;
        // reserved (10 bytes)
        pos += 10;

        // auth-plugin-data-part-2: max(13, plugin_data_len - 8) bytes
        let part2_len = if plugin_data_len > 8 {
            plugin_data_len - 8
        } else {
            13
        };
        let salt2 = if pos + part2_len <= greeting.len() {
            greeting[pos..pos + part2_len].to_vec()
        } else {
            vec![0u8; 13]
        };

        // Combine: salt = salt1 || salt2[0..12]  (20-byte total, strip trailing 0x00)
        let mut salt = salt1;
        salt.extend_from_slice(&salt2[..salt2.len().min(12)]);

        debug!("MySQL salt (hex): {}", to_hex(&salt));

        // ── Step 2: send HandshakeResponse41 ──────────────────────────────
        let auth_resp = mysql_native_password(&cred.password, &salt);
        let db = target.path.as_deref().unwrap_or("");
        let payload = build_handshake_response(&cred.username, &auth_resp, db);
        let pkt = make_packet(1, &payload);

        conn.write_all(&pkt)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // ── Step 3: read auth result ───────────────────────────────────────
        let result_pkt = read_packet(&mut conn).await?;
        let _ = conn.shutdown().await;

        // payload starts at offset 4 (after the 3+1 byte header)
        let resp_type = if result_pkt.len() > 4 {
            result_pkt[4]
        } else {
            0xFF
        };
        debug!("MySQL auth result type=0x{:02X}", resp_type);

        match resp_type {
            0x00 => Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            }),
            0xFF => Ok(AttackResult::Failure),
            0xFE => {
                // Auth switch request — plugin other than mysql_native_password
                Ok(AttackResult::Error(
                    "MySQL: auth-switch required (non-native plugin)".into(),
                ))
            }
            _ => Ok(AttackResult::Failure),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mysql_meta() {
        let p = MySqlProtocol;
        assert_eq!(p.name(), "mysql");
        assert_eq!(p.default_port(), 3306);
    }

    #[test]
    fn password_hash_empty() {
        let h = mysql_native_password("", b"saltsalt12345678");
        assert!(h.is_empty());
    }

    #[test]
    fn password_hash_nonempty_length() {
        // sha1 output is 20 bytes
        let h = mysql_native_password("password", b"12345678901234567890");
        assert_eq!(h.len(), 20);
    }

    #[test]
    fn password_hash_deterministic() {
        let h1 = mysql_native_password("test", b"abcdefgh12345678____");
        let h2 = mysql_native_password("test", b"abcdefgh12345678____");
        assert_eq!(h1, h2);
    }

    #[test]
    fn password_hash_differs_by_salt() {
        let h1 = mysql_native_password("test", b"AAAAAAAAAAAAAAAAAAAA");
        let h2 = mysql_native_password("test", b"BBBBBBBBBBBBBBBBBBBB");
        assert_ne!(h1, h2);
    }

    #[test]
    fn packet_make_parses_length() {
        let payload = b"hello";
        let pkt = make_packet(1, payload);
        let len = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], 0]);
        assert_eq!(len as usize, payload.len());
        assert_eq!(pkt[3], 1); // sequence
        assert_eq!(&pkt[4..], payload);
    }
}
