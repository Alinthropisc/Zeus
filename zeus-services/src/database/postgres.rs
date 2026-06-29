//! PostgreSQL MD5 password authentication.
//!
//! Wire flow:
//!   Client → StartupMessage  (user, database)
//!   Server → AuthenticationMD5Password (4-byte salt)
//!   Client → PasswordMessage("md5" + md5(md5(pass+user) + hex_salt))
//!   Server → AuthenticationOk (R\x00\x00\x00\x08\x00\x00\x00\x00) or ErrorResponse

use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;
use zeus_crypto::{md5, to_hex};

pub struct PostgresProtocol;

// ── Crypto ────────────────────────────────────────────────────────────────────

/// PostgreSQL MD5 password:  "md5" + hex(md5(hex(md5(pass + user)) + salt))
pub fn pg_md5_password(username: &str, password: &str, salt: &[u8; 4]) -> String {
    // Inner hash: md5(password + username)
    let mut inner = Vec::with_capacity(password.len() + username.len());
    inner.extend_from_slice(password.as_bytes());
    inner.extend_from_slice(username.as_bytes());
    let inner_hex = to_hex(&md5(&inner));

    // Outer hash: md5(inner_hex + salt)
    let mut outer = Vec::with_capacity(inner_hex.len() + 4);
    outer.extend_from_slice(inner_hex.as_bytes());
    outer.extend_from_slice(salt);
    let outer_hex = to_hex(&md5(&outer));

    format!("md5{}", outer_hex)
}

// ── Packet builders ───────────────────────────────────────────────────────────

/// PostgreSQL StartupMessage (not a regular message — no leading type byte).
/// Format: Int32(total_len) + Int32(196608 = protocol 3.0) + key=value pairs + \0
fn build_startup(username: &str, database: &str) -> Vec<u8> {
    let mut params = Vec::new();
    for (k, v) in &[("user", username), ("database", database)] {
        params.extend_from_slice(k.as_bytes());
        params.push(0x00);
        params.extend_from_slice(v.as_bytes());
        params.push(0x00);
    }
    params.push(0x00); // terminating zero

    let protocol: u32 = 196608; // 3.0
    let total_len = (8 + params.len()) as u32;

    let mut msg = Vec::with_capacity(total_len as usize);
    msg.extend_from_slice(&total_len.to_be_bytes());
    msg.extend_from_slice(&protocol.to_be_bytes());
    msg.extend_from_slice(&params);
    msg
}

/// PostgreSQL PasswordMessage: 'p' + Int32(len including self) + string + \0
fn build_password_message(pw: &str) -> Vec<u8> {
    let body_len = (4 + pw.len() + 1) as u32; // 4 = length field itself, +1 null
    let mut msg = Vec::with_capacity(1 + body_len as usize);
    msg.push(b'p');
    msg.extend_from_slice(&body_len.to_be_bytes());
    msg.extend_from_slice(pw.as_bytes());
    msg.push(0x00);
    msg
}

// ── Protocol ─────────────────────────────────────────────────────────────────

#[async_trait]
impl Protocol for PostgresProtocol {
    fn name(&self) -> &'static str { "pgsql" }
    fn default_port(&self) -> u16 { 5432 }
    fn description(&self) -> &'static str { "PostgreSQL MD5 password authentication" }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let addr_str = format!("{}:{}", target.host, target.port);
        let addr = addr_str.to_socket_addrs().map_err(ZeusError::Network)?
            .next().ok_or_else(|| ZeusError::Protocol("DNS resolution failed".into()))?;

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // ── Step 1: send StartupMessage ────────────────────────────────────
        let db = target.path.as_deref().unwrap_or("postgres");
        let startup = build_startup(&cred.username, db);
        conn.write_all(&startup).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // ── Step 2: read authentication request ───────────────────────────
        // Format: Byte1(type) + Int32(len) + Int32(auth_type) + [data]
        let resp = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("PgSQL auth request {} bytes, type={:?}", resp.len(), resp.first());

        if resp.len() < 9 {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("PostgreSQL: auth response too short".into()));
        }

        let msg_type = resp[0];
        if msg_type == b'E' {
            // ErrorResponse
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("PostgreSQL: server error on connect".into()));
        }
        if msg_type != b'R' {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error(
                format!("PostgreSQL: unexpected message type 0x{:02X}", msg_type),
            ));
        }

        let auth_type = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]);
        debug!("PgSQL auth_type={}", auth_type);

        match auth_type {
            0 => {
                // AuthenticationOk — no password required
                let _ = conn.shutdown().await;
                return Ok(AttackResult::Success {
                    credential: cred.clone(),
                    elapsed: start.elapsed(),
                });
            }
            3 => {
                // AuthenticationCleartextPassword
                let pw_msg = build_password_message(&cred.password);
                conn.write_all(&pw_msg).await
                    .map_err(|e| ZeusError::Protocol(e.to_string()))?;
            }
            5 => {
                // AuthenticationMD5Password — salt is next 4 bytes
                if resp.len() < 13 {
                    let _ = conn.shutdown().await;
                    return Ok(AttackResult::Error("PostgreSQL: MD5 salt missing".into()));
                }
                let salt: [u8; 4] = [resp[9], resp[10], resp[11], resp[12]];
                let pw = pg_md5_password(&cred.username, &cred.password, &salt);
                debug!("PgSQL MD5 password: {}", pw);
                let pw_msg = build_password_message(&pw);
                conn.write_all(&pw_msg).await
                    .map_err(|e| ZeusError::Protocol(e.to_string()))?;
            }
            _ => {
                let _ = conn.shutdown().await;
                return Err(ZeusError::Protocol(
                    format!("PostgreSQL: unsupported auth type {}", auth_type),
                ));
            }
        }

        // ── Step 3: read auth result ───────────────────────────────────────
        let auth_result = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let _ = conn.shutdown().await;

        if auth_result.is_empty() {
            return Ok(AttackResult::Failure);
        }

        match auth_result[0] {
            b'R' => {
                // Should be AuthenticationOk (auth_type == 0)
                if auth_result.len() >= 9 {
                    let t = u32::from_be_bytes([
                        auth_result[5], auth_result[6], auth_result[7], auth_result[8],
                    ]);
                    if t == 0 {
                        return Ok(AttackResult::Success {
                            credential: cred.clone(),
                            elapsed: start.elapsed(),
                        });
                    }
                }
                Ok(AttackResult::Failure)
            }
            b'E' => Ok(AttackResult::Failure),
            _ => Ok(AttackResult::Failure),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_meta() {
        let p = PostgresProtocol;
        assert_eq!(p.name(), "pgsql");
        assert_eq!(p.default_port(), 5432);
    }

    #[test]
    fn md5_password_format() {
        // Result must start with "md5" and be 35 chars (3 + 32)
        let pw = pg_md5_password("bob", "secret", &[0x01, 0x02, 0x03, 0x04]);
        assert!(pw.starts_with("md5"), "must start with md5");
        assert_eq!(pw.len(), 35, "md5 + 32 hex chars");
    }

    #[test]
    fn md5_password_deterministic() {
        let salt = [0xDE, 0xAD, 0xBE, 0xEF];
        let a = pg_md5_password("user", "pass", &salt);
        let b = pg_md5_password("user", "pass", &salt);
        assert_eq!(a, b);
    }

    #[test]
    fn md5_password_salt_sensitive() {
        let a = pg_md5_password("user", "pass", &[0x00, 0x00, 0x00, 0x00]);
        let b = pg_md5_password("user", "pass", &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_ne!(a, b);
    }

    #[test]
    fn startup_message_format() {
        let msg = build_startup("alice", "mydb");
        // First 4 bytes = total length
        let total = u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize;
        assert_eq!(total, msg.len());
        // Protocol 3.0 = 196608
        let proto = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
        assert_eq!(proto, 196608);
    }
}
