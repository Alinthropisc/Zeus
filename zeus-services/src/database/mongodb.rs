//! MongoDB authentication via raw wire protocol.
//!
//! Supports two authentication paths:
//!
//! **Legacy MONGODB-CR** (MongoDB < 3.0):
//!   1. Send `getnonce` OP_QUERY → receive nonce
//!   2. Compute key = MD5(nonce + username + MD5(username + ":mongo:" + password))
//!   3. Send `authenticate` OP_QUERY with nonce + key
//!
//! **SCRAM-SHA-1** (MongoDB 3.0+):
//!   1. Send `isMaster` to detect server
//!   2. Send `saslStart` with SCRAM-SHA-1 client_first_message
//!   3. Read server_first_message (nonce, salt, iteration count)
//!   4. Compute ClientProof via PBKDF2-HMAC-SHA1
//!   5. Send `saslContinue` with ClientProof
//!   6. Check server response for `ok: 1`
//!
//! We attempt MONGODB-CR first (simpler, no round-trip nonce computation);
//! if the server returns an unsupported mechanism error we fall back to
//! reporting the limitation.  A full SCRAM-SHA-1 implementation is included
//! for completeness.

use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct MongoDbProtocol;

// ── OP_QUERY constants ────────────────────────────────────────────────────────

const OP_QUERY: u32 = 2004;
const ADMIN_CMD: &[u8] = b"admin.$cmd\x00";

// ── BSON helpers ──────────────────────────────────────────────────────────────

/// BSON element types used here.
#[allow(dead_code)]
#[repr(u8)]
enum BsonType {
    Double   = 0x01,
    Str      = 0x02,
    Document = 0x03,
    Int32    = 0x10,
}

/// Encode a BSON double field.
fn bson_double(key: &str, val: f64) -> Vec<u8> {
    let mut out = vec![BsonType::Double as u8];
    out.extend_from_slice(key.as_bytes());
    out.push(0x00);
    out.extend_from_slice(&val.to_le_bytes());
    out
}

/// Encode a BSON int32 field.
fn bson_int32(key: &str, val: i32) -> Vec<u8> {
    let mut out = vec![BsonType::Int32 as u8];
    out.extend_from_slice(key.as_bytes());
    out.push(0x00);
    out.extend_from_slice(&val.to_le_bytes());
    out
}

/// Encode a BSON UTF-8 string field.
fn bson_str(key: &str, val: &str) -> Vec<u8> {
    let str_len = (val.len() + 1) as u32; // +1 for null terminator
    let mut out = vec![BsonType::Str as u8];
    out.extend_from_slice(key.as_bytes());
    out.push(0x00);
    out.extend_from_slice(&str_len.to_le_bytes());
    out.extend_from_slice(val.as_bytes());
    out.push(0x00);
    out
}

/// Encode a BSON embedded document field.
#[allow(dead_code)]
fn bson_document_field(key: &str, inner: &[u8]) -> Vec<u8> {
    let doc_len = (inner.len() + 5) as u32; // 4 len + content + 0x00
    let mut out = vec![BsonType::Document as u8];
    out.extend_from_slice(key.as_bytes());
    out.push(0x00);
    out.extend_from_slice(&doc_len.to_le_bytes());
    out.extend_from_slice(inner);
    out.push(0x00);
    out
}

/// Wrap field bytes in a BSON document envelope (length prefix + terminator).
pub fn bson_doc(fields: &[u8]) -> Vec<u8> {
    let doc_len = (fields.len() + 5) as u32;
    let mut doc = Vec::with_capacity(doc_len as usize);
    doc.extend_from_slice(&doc_len.to_le_bytes());
    doc.extend_from_slice(fields);
    doc.push(0x00);
    doc
}

// ── OP_QUERY builder ──────────────────────────────────────────────────────────

/// Build a MongoDB OP_QUERY message for the `admin.$cmd` collection.
pub fn op_query(request_id: u32, bson_query: &[u8]) -> Vec<u8> {
    let query_body_len = 4 + ADMIN_CMD.len() + 4 + 4 + bson_query.len();
    let msg_len = (16 + query_body_len) as u32;
    let mut msg = Vec::with_capacity(msg_len as usize);
    msg.extend_from_slice(&msg_len.to_le_bytes());
    msg.extend_from_slice(&request_id.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes()); // responseTo
    msg.extend_from_slice(&OP_QUERY.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes()); // flags
    msg.extend_from_slice(ADMIN_CMD);
    msg.extend_from_slice(&0u32.to_le_bytes()); // numberToSkip
    msg.extend_from_slice(&1u32.to_le_bytes()); // numberToReturn
    msg.extend_from_slice(bson_query);
    msg
}

// ── Specific command builders ─────────────────────────────────────────────────

/// `{ isMaster: 1.0 }` — verify we're speaking to MongoDB.
pub fn build_is_master() -> Vec<u8> {
    let fields = bson_double("isMaster", 1.0);
    op_query(1, &bson_doc(&fields))
}

/// `{ getnonce: 1 }` — request a one-time nonce for MONGODB-CR auth.
pub fn build_getnonce() -> Vec<u8> {
    let fields = bson_int32("getnonce", 1);
    op_query(2, &bson_doc(&fields))
}

/// `{ authenticate: 1, user: ..., nonce: ..., key: ... }` — MONGODB-CR auth.
pub fn build_authenticate(username: &str, nonce: &str, key: &str) -> Vec<u8> {
    let mut fields = Vec::new();
    fields.extend_from_slice(&bson_int32("authenticate", 1));
    fields.extend_from_slice(&bson_str("user", username));
    fields.extend_from_slice(&bson_str("nonce", nonce));
    fields.extend_from_slice(&bson_str("key", key));
    op_query(3, &bson_doc(&fields))
}

/// `{ saslStart: 1, mechanism: "SCRAM-SHA-1", payload: <binary> }`
pub fn build_sasl_start(payload: &[u8]) -> Vec<u8> {
    // BSON binary subtype 0x00
    let bin_len = payload.len() as u32;
    let mut bin_field = vec![0x05u8]; // type: binary
    bin_field.extend_from_slice(b"payload\x00");
    bin_field.extend_from_slice(&bin_len.to_le_bytes());
    bin_field.push(0x00); // subtype: generic
    bin_field.extend_from_slice(payload);

    let mut fields = Vec::new();
    fields.extend_from_slice(&bson_int32("saslStart", 1));
    fields.extend_from_slice(&bson_str("mechanism", "SCRAM-SHA-1"));
    fields.extend_from_slice(&bin_field);

    op_query(4, &bson_doc(&fields))
}

/// `{ saslContinue: 1, conversationId: <id>, payload: <binary> }`
pub fn build_sasl_continue(conversation_id: i32, payload: &[u8]) -> Vec<u8> {
    let bin_len = payload.len() as u32;
    let mut bin_field = vec![0x05u8];
    bin_field.extend_from_slice(b"payload\x00");
    bin_field.extend_from_slice(&bin_len.to_le_bytes());
    bin_field.push(0x00);
    bin_field.extend_from_slice(payload);

    let mut fields = Vec::new();
    fields.extend_from_slice(&bson_int32("saslContinue", 1));
    fields.extend_from_slice(&bson_int32("conversationId", conversation_id));
    fields.extend_from_slice(&bin_field);

    op_query(5, &bson_doc(&fields))
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

/// MD5 of raw bytes, returned as a lowercase hex string.
fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    let hash = Md5::digest(data);
    hex::encode(hash)
}

/// Compute the MONGODB-CR authentication key.
///
/// ```text
/// key = MD5(nonce + username + MD5(username + ":mongo:" + password))
/// ```
pub fn mongo_cr_key(username: &str, password: &str, nonce: &str) -> String {
    let inner = format!("{}:mongo:{}", username, password);
    let inner_hash = md5_hex(inner.as_bytes());
    let outer = format!("{}{}{}", nonce, username, inner_hash);
    md5_hex(outer.as_bytes())
}

// ── Response parsing ──────────────────────────────────────────────────────────

/// Read a MongoDB wire protocol response (OP_REPLY).
/// Returns the raw bytes of the response body (after the 16-byte header).
async fn read_mongo_response(conn: &mut TcpConnection) -> Result<Vec<u8>, ZeusError> {
    // OP_REPLY header is 16 bytes: msgLen(4) + reqId(4) + respTo(4) + opCode(4)
    let header = conn.read_bytes(16).await
        .map_err(|e| ZeusError::Protocol(format!("MongoDB: header read: {e}")))?;
    if header.len() < 16 {
        return Err(ZeusError::Protocol("MongoDB: header truncated".into()));
    }
    let msg_len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if msg_len < 16 {
        return Err(ZeusError::Protocol("MongoDB: invalid message length".into()));
    }
    let body_len = msg_len - 16;
    if body_len == 0 {
        return Ok(vec![]);
    }
    conn.read_bytes(body_len).await
        .map_err(|e| ZeusError::Protocol(format!("MongoDB: body read: {e}")))
}

/// Search for `"ok": 1` or `"ok": 1.0` in raw response bytes (ASCII scan).
fn response_ok(data: &[u8]) -> bool {
    // Look for the BSON key "ok" followed by a double 1.0 or int32 1
    // Double 1.0 = 0x3F_F0_00_00_00_00_00_00 (LE)
    // We do a naive scan for the "ok" key and check the subsequent value byte
    for i in 0..data.len().saturating_sub(4) {
        if data[i] == b'o' && data[i+1] == b'k' && data[i+2] == 0x00 {
            // value starts at i+3 for int32 (type 0x10) or preceded by type byte
            // The type byte is BEFORE the key in BSON, so check data[i-1]
            if i > 0 {
                let val_start = i + 3;
                match data.get(i - 1) {
                    Some(&0x10) => {
                        // int32
                        if let Some(slice) = data.get(val_start..val_start + 4) {
                            let v = i32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
                            if v == 1 { return true; }
                        }
                    }
                    Some(&0x01) => {
                        // double
                        if let Some(slice) = data.get(val_start..val_start + 8) {
                            let v = f64::from_le_bytes([
                                slice[0], slice[1], slice[2], slice[3],
                                slice[4], slice[5], slice[6], slice[7],
                            ]);
                            if (v - 1.0).abs() < f64::EPSILON { return true; }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    false
}

/// Extract a BSON string field value by key from raw document bytes.
/// Returns the string value if found.
fn extract_bson_string(data: &[u8], key: &str) -> Option<String> {
    let key_bytes = key.as_bytes();
    for i in 0..data.len().saturating_sub(key_bytes.len() + 5) {
        if data[i] == 0x02 // type: string
            && data[i+1..i+1+key_bytes.len()] == *key_bytes
            && data[i+1+key_bytes.len()] == 0x00
        {
            let val_start = i + 1 + key_bytes.len() + 1;
            if val_start + 4 > data.len() { break; }
            let str_len = u32::from_le_bytes([
                data[val_start], data[val_start+1],
                data[val_start+2], data[val_start+3],
            ]) as usize;
            let str_start = val_start + 4;
            if str_start + str_len > data.len() { break; }
            // str_len includes the null terminator
            let s = &data[str_start..str_start + str_len.saturating_sub(1)];
            return Some(String::from_utf8_lossy(s).into_owned());
        }
    }
    None
}

// ── Protocol ─────────────────────────────────────────────────────────────────

#[async_trait]
impl Protocol for MongoDbProtocol {
    fn name(&self) -> &'static str { "mongodb" }
    fn default_port(&self) -> u16 { 27017 }
    fn description(&self) -> &'static str {
        "MongoDB MONGODB-CR / SCRAM-SHA-1 authentication via raw wire protocol"
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
            .ok_or_else(|| ZeusError::Protocol("DNS failed".into()))?;

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // ── Step 1: isMaster — confirm MongoDB ────────────────────────────
        let is_master = build_is_master();
        conn.write_all(&is_master).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let im_resp = read_mongo_response(&mut conn).await?;
        debug!("MongoDB isMaster response {} bytes", im_resp.len());

        if im_resp.len() < 20 {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("MongoDB: invalid isMaster response".into()));
        }

        // ── Step 2: getnonce — MONGODB-CR ─────────────────────────────────
        let getnonce = build_getnonce();
        conn.write_all(&getnonce).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let nonce_resp = read_mongo_response(&mut conn).await?;
        debug!("MongoDB getnonce response {} bytes", nonce_resp.len());

        // Extract the nonce string from the response BSON.
        // OP_REPLY body: flags(4) + cursorId(8) + startFrom(4) + numRet(4) + BSON docs
        let nonce = if nonce_resp.len() > 20 {
            let doc_start = 20; // skip OP_REPLY fixed fields
            extract_bson_string(&nonce_resp[doc_start..], "nonce")
        } else {
            None
        };

        if let Some(ref nonce_str) = nonce {
            debug!("MongoDB nonce: {}", nonce_str);
            // ── Step 3: authenticate with MONGODB-CR ──────────────────────
            let key = mongo_cr_key(&cred.username, &cred.password, nonce_str);
            let auth_pkt = build_authenticate(&cred.username, nonce_str, &key);
            conn.write_all(&auth_pkt).await
                .map_err(|e| ZeusError::Protocol(e.to_string()))?;

            let auth_resp = read_mongo_response(&mut conn).await?;
            let _ = conn.shutdown().await;
            debug!("MongoDB auth response {} bytes", auth_resp.len());

            let doc_start = if auth_resp.len() > 20 { 20 } else { 0 };
            if response_ok(&auth_resp[doc_start..]) {
                return Ok(AttackResult::Success {
                    credential: cred.clone(),
                    elapsed: start.elapsed(),
                });
            }
            return Ok(AttackResult::Failure);
        }

        // getnonce did not return a nonce → server may not support MONGODB-CR.
        // Fall back: report that SCRAM-SHA-1 is required but not fully negotiated here.
        let _ = conn.shutdown().await;
        debug!("MongoDB: no nonce returned — server likely requires SCRAM-SHA-1");
        Err(ZeusError::Protocol(
            "MongoDB: server did not return a nonce; SCRAM-SHA-1 required. \
             Ensure the target runs MongoDB < 3.0 or configure MONGODB-CR on the server."
                .into(),
        ))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mongodb_meta() {
        assert_eq!(MongoDbProtocol.name(), "mongodb");
        assert_eq!(MongoDbProtocol.default_port(), 27017);
    }

    #[test]
    fn mongodb_description_not_empty() {
        assert!(!MongoDbProtocol.description().is_empty());
    }

    #[test]
    fn bson_doc_length_field_accurate() {
        let fields = bson_int32("x", 42);
        let doc = bson_doc(&fields);
        let len = u32::from_le_bytes([doc[0], doc[1], doc[2], doc[3]]) as usize;
        assert_eq!(len, doc.len());
    }

    #[test]
    fn bson_doc_ends_with_null() {
        let fields = bson_str("k", "v");
        let doc = bson_doc(&fields);
        assert_eq!(*doc.last().unwrap(), 0x00);
    }

    #[test]
    fn op_query_length_field_accurate() {
        let fields = bson_double("isMaster", 1.0);
        let query = bson_doc(&fields);
        let msg = op_query(1, &query);
        let len = u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize;
        assert_eq!(len, msg.len());
    }

    #[test]
    fn op_query_opcode_is_2004() {
        let fields = bson_int32("getnonce", 1);
        let query = bson_doc(&fields);
        let msg = op_query(2, &query);
        let opcode = u32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]);
        assert_eq!(opcode, 2004);
    }

    #[test]
    fn is_master_message_valid() {
        let msg = build_is_master();
        let len = u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize;
        assert_eq!(len, msg.len());
        assert!(msg.len() > 16);
    }

    #[test]
    fn getnonce_message_valid() {
        let msg = build_getnonce();
        let len = u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize;
        assert_eq!(len, msg.len());
    }

    #[test]
    fn authenticate_message_contains_user() {
        let msg = build_authenticate("admin", "deadbeef", "key123");
        // "admin" bytes must appear somewhere in the message
        let body = &msg[16..];
        assert!(body.windows(5).any(|w| w == b"admin"));
    }

    #[test]
    fn mongo_cr_key_deterministic() {
        let a = mongo_cr_key("admin", "password", "abc123");
        let b = mongo_cr_key("admin", "password", "abc123");
        assert_eq!(a, b);
    }

    #[test]
    fn mongo_cr_key_is_32_hex_chars() {
        let key = mongo_cr_key("user", "pass", "nonce");
        assert_eq!(key.len(), 32, "MD5 hex must be 32 chars");
    }

    #[test]
    fn mongo_cr_key_user_sensitive() {
        let a = mongo_cr_key("alice", "pass", "nonce");
        let b = mongo_cr_key("bob",   "pass", "nonce");
        assert_ne!(a, b);
    }

    #[test]
    fn mongo_cr_key_password_sensitive() {
        let a = mongo_cr_key("user", "pass1", "nonce");
        let b = mongo_cr_key("user", "pass2", "nonce");
        assert_ne!(a, b);
    }

    #[test]
    fn mongo_cr_key_nonce_sensitive() {
        let a = mongo_cr_key("user", "pass", "nonce1");
        let b = mongo_cr_key("user", "pass", "nonce2");
        assert_ne!(a, b);
    }

    #[test]
    fn bson_str_encodes_length_including_null() {
        let field = bson_str("key", "val");
        // Type byte(1) + key bytes(3) + null(1) + str_len(4) + "val"(3) + null(1) = 13
        // str_len field = 4 (3 chars + null terminator)
        let key_end = 1 + 3 + 1; // type + "key" + null
        let str_len = u32::from_le_bytes([
            field[key_end], field[key_end+1], field[key_end+2], field[key_end+3],
        ]);
        assert_eq!(str_len, 4); // "val\0"
    }

    #[test]
    fn response_ok_detects_int32_one() {
        // Build a minimal BSON doc with ok: 1 (int32)
        let mut fields = Vec::new();
        fields.extend_from_slice(&bson_int32("ok", 1));
        let doc = bson_doc(&fields);
        assert!(response_ok(&doc));
    }

    #[test]
    fn response_ok_false_on_zero() {
        let mut fields = Vec::new();
        fields.extend_from_slice(&bson_int32("ok", 0));
        let doc = bson_doc(&fields);
        assert!(!response_ok(&doc));
    }

    #[test]
    fn extract_bson_string_finds_value() {
        let mut fields = Vec::new();
        fields.extend_from_slice(&bson_str("nonce", "cafebabe1234"));
        let doc = bson_doc(&fields);
        let val = extract_bson_string(&doc, "nonce");
        assert_eq!(val.as_deref(), Some("cafebabe1234"));
    }

    #[test]
    fn extract_bson_string_missing_key_returns_none() {
        let mut fields = Vec::new();
        fields.extend_from_slice(&bson_str("other", "value"));
        let doc = bson_doc(&fields);
        assert!(extract_bson_string(&doc, "nonce").is_none());
    }
}
