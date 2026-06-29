//! Microsoft SQL Server authentication via raw TDS 7.4 wire protocol.
//!
//! Wire flow:
//!   Client → PRELOGIN packet  (type 0x12)
//!   Server → PRELOGIN response
//!   Client → LOGIN7 packet    (type 0x10) — username + XOR/nibble-swap password
//!   Server → token stream containing LOGINACK (0xAD) on success or ERROR (0xAA)

use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct MssqlProtocol;

// ── TDS constants ─────────────────────────────────────────────────────────────

const TDS_PRELOGIN: u8 = 0x12;
const TDS_LOGIN7: u8   = 0x10;
const TDS_RESPONSE: u8 = 0x04;

/// PRELOGIN option types
const OPT_VERSION:    u8 = 0x00;
const OPT_ENCRYPTION: u8 = 0x01;
const OPT_INSTOPT:    u8 = 0x02;
const OPT_THREADID:   u8 = 0x03;
const OPT_MARS:       u8 = 0x04;
const OPT_TERMINATOR: u8 = 0xFF;

/// ENCRYPT_NOT_SUP — skip TLS for brute-force purposes
const ENCRYPT_NOT_SUP: u8 = 0x02;

/// TDS response token types
const TOKEN_LOGINACK: u8 = 0xAD;
const TOKEN_ERROR:    u8 = 0xAA;
const TOKEN_DONE:     u8 = 0xFD;

// ── Password encoding ────────────────────────────────────────────────────────

/// TDS quirk: XOR each byte with 0xA5, then swap the nibbles.
fn tds_encode_password(password: &str) -> Vec<u8> {
    password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .map(|b| {
            let xored = b ^ 0xA5;
            (xored >> 4) | (xored << 4)
        })
        .collect()
}

// ── TDS packet builder ───────────────────────────────────────────────────────

/// Wrap `body` in a TDS packet header.
///
/// ```text
/// type(1) | status(1) | length(2 BE) | spid(2 BE) | packet_id(1) | window(1)
/// ```
fn tds_packet(pkt_type: u8, status: u8, body: &[u8]) -> Vec<u8> {
    let total_len = (8 + body.len()) as u16;
    let mut pkt = Vec::with_capacity(8 + body.len());
    pkt.push(pkt_type);
    pkt.push(status);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // spid
    pkt.push(1);                                 // packet_id
    pkt.push(0);                                 // window
    pkt.extend_from_slice(body);
    pkt
}

// ── PRELOGIN ─────────────────────────────────────────────────────────────────

/// Build a minimal TDS PRELOGIN packet body.
///
/// Option list layout (offsets relative to start of option data area):
///
/// | type | offset (2 BE) | length (2 BE) |  …value…
///
/// Options: VERSION(6 bytes), ENCRYPTION(1 byte), INSTOPT(1 byte),
///          THREADID(4 bytes), MARS(1 byte), TERMINATOR
fn build_prelogin_body() -> Vec<u8> {
    // Compute option header area size: 5 options × 5 bytes each + 1 terminator = 26 bytes
    // Values immediately follow at offset 26 from the start of the body.
    const HDR: usize = 5 * 5 + 1; // 26

    // Value payloads
    let version: [u8; 6]  = [0x0E, 0x00, 0x06, 0x03, 0x00, 0x00]; // SQL Server 14.0.603
    let encryption: [u8; 1] = [ENCRYPT_NOT_SUP];
    let instopt: [u8; 1]  = [0x00];
    let threadid: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
    let mars: [u8; 1]     = [0x00];

    // Calculate absolute offsets of each value block
    let off_version    = HDR as u16;
    let off_encryption = off_version + version.len() as u16;
    let off_instopt    = off_encryption + encryption.len() as u16;
    let off_threadid   = off_instopt + instopt.len() as u16;
    let off_mars       = off_threadid + threadid.len() as u16;

    let mut body = Vec::with_capacity(HDR + version.len() + 7);

    // Option headers
    let write_opt = |buf: &mut Vec<u8>, t: u8, off: u16, len: u16| {
        buf.push(t);
        buf.extend_from_slice(&off.to_be_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
    };
    write_opt(&mut body, OPT_VERSION,    off_version,    version.len() as u16);
    write_opt(&mut body, OPT_ENCRYPTION, off_encryption, encryption.len() as u16);
    write_opt(&mut body, OPT_INSTOPT,    off_instopt,    instopt.len() as u16);
    write_opt(&mut body, OPT_THREADID,   off_threadid,   threadid.len() as u16);
    write_opt(&mut body, OPT_MARS,       off_mars,       mars.len() as u16);
    body.push(OPT_TERMINATOR);

    // Value data
    body.extend_from_slice(&version);
    body.extend_from_slice(&encryption);
    body.extend_from_slice(&instopt);
    body.extend_from_slice(&threadid);
    body.extend_from_slice(&mars);

    body
}

// ── LOGIN7 ───────────────────────────────────────────────────────────────────

/// Build a TDS LOGIN7 packet body.
///
/// Fixed header is 36 bytes of metadata, then offset/length pairs for all
/// variable-length fields (host, user, password, app, server, …), then the
/// string data itself.
fn build_login7_body(username: &str, password: &str, server: &str) -> Vec<u8> {
    // TDS 7.4
    const TDS_VERSION:    u32 = 0x0400_0074;
    const PACKET_SIZE:    u32 = 0x0000_1000; // 4096
    const CLIENT_PROG_VER: u32 = 0x0700_0000;
    const OPTION_FLAGS1:  u8  = 0xE0;
    const OPTION_FLAGS2:  u8  = 0x03;

    // Variable-length fields we send (UTF-16LE for strings).
    // Fields we don't use are offset=0, length=0.
    let hostname_utf16: Vec<u8>  = "zeus".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let username_utf16: Vec<u8>  = username.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let password_enc: Vec<u8>    = tds_encode_password(password);
    let appname_utf16: Vec<u8>   = "zeus".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let servername_utf16: Vec<u8> = server.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let dbname_utf16: Vec<u8>    = vec![];
    let language_utf16: Vec<u8>  = vec![];

    // Fixed header (everything before the offset/length table) = 4 bytes (length field itself) +
    // the fixed fields. We will write them below and track the total.
    //
    // Layout of the LOGIN7 fixed portion (after the outer 4-byte total-length):
    //   TDSVersion(4) PacketSize(4) ClientProgVer(4) ClientPID(4) ConnectionID(4)
    //   OptionFlags1(1) OptionFlags2(1) TypeFlags(1) OptionFlags3(1)
    //   ClientTimezone(4) ClientLCID(4)
    //   = 36 bytes
    //
    // Then offset/length pairs for 13 fields × 4 bytes (offset u16 LE + length u16 LE) = 52 bytes
    // But we only need to encode: HostName, UserName, Password, AppName, ServerName,
    // Extension (0), CltIntName (0), Language, Database, ClientID, SSPI (0), AtchDBFile (0), ChangePassword (0)
    // = 13 fields = 52 bytes for offset+length pairs
    //
    // Data offset starts at: 4 (length) + 36 (fixed) + 52 (table) = 92 bytes into the body.
    const FIXED_PRE: usize = 36;
    const N_FIELDS: usize  = 13;
    const TABLE_LEN: usize = N_FIELDS * 4;
    const DATA_START: usize = 4 + FIXED_PRE + TABLE_LEN; // 92

    // Accumulate string data and track offsets (relative to start of body, NOT start of data).
    // The TDS spec says offsets are from the start of the LOGIN7 body (the 4-byte length field).
    let mut string_data: Vec<u8> = Vec::new();
    let mut next_offset = DATA_START as u16;

    let mut push_field = |data: &[u8], out: &mut Vec<u8>| -> (u16, u16) {
        let char_len = (data.len() / 2) as u16; // for UTF-16: char count = byte count / 2
        if data.is_empty() {
            out.extend_from_slice(&[0u8; 0]);
            return (0, 0);
        }
        let off = next_offset;
        out.extend_from_slice(data);
        // we need to mutate next_offset — use closure captures won't work easily, so
        // we return (off, char_len) and update next_offset outside.
        (off, char_len)
    };

    // We need mutable `next_offset` alongside the closure, which doesn't mix in Rust.
    // Inline each field manually instead.
    macro_rules! field {
        ($data:expr) => {{
            if $data.is_empty() {
                string_data.extend_from_slice(&[] as &[u8]);
                (0u16, 0u16)
            } else {
                let off = next_offset;
                let char_len = ($data.len() / 2) as u16;
                string_data.extend_from_slice($data);
                next_offset += $data.len() as u16;
                (off, char_len)
            }
        }};
    }

    // client_id is a 6-byte MAC; we use zeros and write it specially (not a string field).
    let client_id = [0u8; 6];

    // SSPI data (binary, not a UTF-16 string — length in bytes, not chars).
    // We send empty SSPI.
    let sspi_off: u16  = 0;
    let sspi_len: u16  = 0;

    let (hn_off, hn_len) = field!(&hostname_utf16);
    let (un_off, un_len) = field!(&username_utf16);
    let (pw_off, pw_len) = field!(&password_enc);
    let (an_off, an_len) = field!(&appname_utf16);
    let (sn_off, sn_len) = field!(&servername_utf16);
    // Extension: empty
    let (ex_off, ex_len): (u16, u16) = (0, 0);
    // CltIntName: empty
    let (ci_off, ci_len): (u16, u16) = (0, 0);
    let (lg_off, lg_len) = field!(&language_utf16);
    let (db_off, db_len) = field!(&dbname_utf16);
    // AtchDBFile: empty
    let (at_off, at_len): (u16, u16) = (0, 0);
    // ChangePassword: empty
    let (cp_off, cp_len): (u16, u16) = (0, 0);

    let _ = push_field; // suppress unused warning

    let total_body_len = DATA_START + string_data.len();

    let mut body = Vec::with_capacity(total_body_len);

    // 4-byte total body length (LE)
    body.extend_from_slice(&(total_body_len as u32).to_le_bytes());

    // Fixed fields
    body.extend_from_slice(&TDS_VERSION.to_le_bytes());
    body.extend_from_slice(&PACKET_SIZE.to_le_bytes());
    body.extend_from_slice(&CLIENT_PROG_VER.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes()); // ClientPID
    body.extend_from_slice(&0u32.to_le_bytes()); // ConnectionID
    body.push(OPTION_FLAGS1);
    body.push(OPTION_FLAGS2);
    body.push(0x00); // TypeFlags
    body.push(0x00); // OptionFlags3
    body.extend_from_slice(&0i32.to_le_bytes()); // ClientTimezone
    body.extend_from_slice(&0u32.to_le_bytes()); // ClientLCID

    // Offset/length table — each field: offset(2 LE) + length(2 LE)
    // 1. HostName
    body.extend_from_slice(&hn_off.to_le_bytes());
    body.extend_from_slice(&hn_len.to_le_bytes());
    // 2. UserName
    body.extend_from_slice(&un_off.to_le_bytes());
    body.extend_from_slice(&un_len.to_le_bytes());
    // 3. Password
    body.extend_from_slice(&pw_off.to_le_bytes());
    body.extend_from_slice(&pw_len.to_le_bytes());
    // 4. AppName
    body.extend_from_slice(&an_off.to_le_bytes());
    body.extend_from_slice(&an_len.to_le_bytes());
    // 5. ServerName
    body.extend_from_slice(&sn_off.to_le_bytes());
    body.extend_from_slice(&sn_len.to_le_bytes());
    // 6. Extension
    body.extend_from_slice(&ex_off.to_le_bytes());
    body.extend_from_slice(&ex_len.to_le_bytes());
    // 7. CltIntName
    body.extend_from_slice(&ci_off.to_le_bytes());
    body.extend_from_slice(&ci_len.to_le_bytes());
    // 8. Language
    body.extend_from_slice(&lg_off.to_le_bytes());
    body.extend_from_slice(&lg_len.to_le_bytes());
    // 9. Database
    body.extend_from_slice(&db_off.to_le_bytes());
    body.extend_from_slice(&db_len.to_le_bytes());
    // 10. ClientID (6 bytes, not offset/length — it is inline)
    body.extend_from_slice(&client_id);
    // 11. SSPI
    body.extend_from_slice(&sspi_off.to_le_bytes());
    body.extend_from_slice(&sspi_len.to_le_bytes());
    // 12. AtchDBFile
    body.extend_from_slice(&at_off.to_le_bytes());
    body.extend_from_slice(&at_len.to_le_bytes());
    // 13. ChangePassword
    body.extend_from_slice(&cp_off.to_le_bytes());
    body.extend_from_slice(&cp_len.to_le_bytes());

    // Variable-length string data
    body.extend_from_slice(&string_data);

    body
}

// ── Read helpers ──────────────────────────────────────────────────────────────

/// Read a complete TDS response packet.  Returns the raw bytes including the
/// 8-byte TDS header.
async fn read_tds_packet(conn: &mut TcpConnection) -> Result<Vec<u8>, ZeusError> {
    // Read 8-byte TDS header first
    let header = conn.read_bytes(8).await
        .map_err(|e| ZeusError::Protocol(format!("TDS: failed reading header: {e}")))?;

    if header.len() < 8 {
        return Err(ZeusError::Protocol("TDS: response header truncated".into()));
    }

    let total_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if total_len < 8 {
        return Err(ZeusError::Protocol("TDS: packet length field < 8".into()));
    }

    let body_len = total_len - 8;
    let body = if body_len > 0 {
        conn.read_bytes(body_len).await
            .map_err(|e| ZeusError::Protocol(format!("TDS: failed reading body: {e}")))?
    } else {
        vec![]
    };

    let mut pkt = header;
    pkt.extend_from_slice(&body);
    Ok(pkt)
}

/// Scan a TDS token stream (everything after the 8-byte packet header) for
/// LOGINACK (success) or ERROR tokens.
fn scan_tokens(token_stream: &[u8]) -> bool {
    let mut i = 0;
    while i < token_stream.len() {
        let token = token_stream[i];
        i += 1;
        match token {
            TOKEN_LOGINACK => return true,
            TOKEN_ERROR => {
                // ERROR token: 2-byte length, then data
                if i + 2 <= token_stream.len() {
                    let len = u16::from_le_bytes([token_stream[i], token_stream[i + 1]]) as usize;
                    i += 2 + len;
                } else {
                    break;
                }
            }
            TOKEN_DONE => {
                // DONE token is 8 bytes: status(2)+curcmd(2)+rowcount(4)
                i += 8;
            }
            _ => {
                // Unknown token — we can't safely skip without knowing length; bail.
                debug!("TDS: unknown token 0x{:02X} at offset {}", token, i - 1);
                break;
            }
        }
    }
    false
}

// ── Protocol ─────────────────────────────────────────────────────────────────

#[async_trait]
impl Protocol for MssqlProtocol {
    fn name(&self) -> &'static str { "mssql" }
    fn default_port(&self) -> u16 { 1433 }
    fn description(&self) -> &'static str {
        "Microsoft SQL Server TDS 7.4 raw wire authentication (no external crates)"
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

        // ── Step 1: send PRELOGIN ──────────────────────────────────────────
        let prelogin_body = build_prelogin_body();
        let prelogin_pkt  = tds_packet(TDS_PRELOGIN, 0x01, &prelogin_body);
        conn.write_all(&prelogin_pkt).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("MSSQL: sent PRELOGIN ({} bytes)", prelogin_pkt.len());

        // ── Step 2: read PRELOGIN response ────────────────────────────────
        let pre_resp = read_tds_packet(&mut conn).await?;
        debug!("MSSQL: PRELOGIN response {} bytes, type=0x{:02X}", pre_resp.len(), pre_resp.first().copied().unwrap_or(0));

        if pre_resp.is_empty() || pre_resp[0] != TDS_RESPONSE {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error(
                format!("MSSQL: unexpected PRELOGIN response type 0x{:02X}", pre_resp.first().copied().unwrap_or(0)),
            ));
        }

        // Check encryption negotiation — bail if server requires TLS (0x01)
        // Body starts at byte 8; scan for ENCRYPTION option (0x01) in the option list.
        if pre_resp.len() > 8 {
            let body = &pre_resp[8..];
            let mut pos = 0;
            while pos < body.len() {
                let opt = body[pos];
                pos += 1;
                if opt == OPT_TERMINATOR { break; }
                if pos + 4 > body.len() { break; }
                let off = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
                let len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
                pos += 4;
                if opt == OPT_ENCRYPTION && off < body.len() && off + len <= body.len() {
                    let enc_val = body[off];
                    debug!("MSSQL: server encryption={}", enc_val);
                    if enc_val == 0x01 {
                        // ENCRYPT_ON — server requires TLS; we can't proceed without it
                        let _ = conn.shutdown().await;
                        return Ok(AttackResult::Error(
                            "MSSQL: server requires TLS (ENCRYPT_ON); skipping".into(),
                        ));
                    }
                }
            }
        }

        // ── Step 3: send LOGIN7 ───────────────────────────────────────────
        let server = target.host.as_str();
        let login7_body = build_login7_body(&cred.username, &cred.password, server);
        let login7_pkt  = tds_packet(TDS_LOGIN7, 0x01, &login7_body);
        conn.write_all(&login7_pkt).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("MSSQL: sent LOGIN7 ({} bytes)", login7_pkt.len());

        // ── Step 4: read response tokens ──────────────────────────────────
        let resp = read_tds_packet(&mut conn).await?;
        let _ = conn.shutdown().await;
        debug!("MSSQL: LOGIN response {} bytes", resp.len());

        if resp.len() <= 8 {
            return Ok(AttackResult::Failure);
        }

        if scan_tokens(&resp[8..]) {
            Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            })
        } else {
            Ok(AttackResult::Failure)
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mssql_meta() {
        let p = MssqlProtocol;
        assert_eq!(p.name(), "mssql");
        assert_eq!(p.default_port(), 1433);
        assert!(!p.description().is_empty());
    }

    #[test]
    fn tds_password_encoding_roundtrip() {
        // Known-value test: "A" in UTF-16LE = 0x41 0x00
        // 0x41 ^ 0xA5 = 0xE4  →  nibble swap  =  0x4E
        // 0x00 ^ 0xA5 = 0xA5  →  nibble swap  =  0x5A
        let enc = tds_encode_password("A");
        assert_eq!(enc, vec![0x4E, 0x5A]);
    }

    #[test]
    fn tds_password_encoding_non_empty() {
        let plain: Vec<u8> = "password".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let enc = tds_encode_password("password");
        assert_eq!(plain.len(), enc.len(), "lengths must match");
        assert_ne!(plain, enc, "encoded must differ from raw UTF-16LE");
    }

    #[test]
    fn prelogin_packet_has_correct_type() {
        let body = build_prelogin_body();
        let pkt  = tds_packet(TDS_PRELOGIN, 0x01, &body);
        assert_eq!(pkt[0], 0x12, "first byte must be TDS PRELOGIN type (0x12)");
    }

    #[test]
    fn tds_packet_length_field_matches_actual_size() {
        let body = build_prelogin_body();
        let pkt  = tds_packet(TDS_PRELOGIN, 0x01, &body);
        let reported_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        assert_eq!(reported_len, pkt.len(), "TDS length field must equal packet total length");
    }

    #[test]
    fn login7_body_starts_with_self_length() {
        let body = build_login7_body("sa", "password", "localhost");
        // First 4 bytes are total body length (LE)
        let reported = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
        assert_eq!(reported, body.len(), "LOGIN7 length field must equal body.len()");
    }

    #[test]
    fn scan_tokens_finds_loginack() {
        // Craft a minimal LOGINACK token stream:
        // LOGINACK(0xAD) + length(2 LE) + 5 filler bytes
        let mut stream = vec![TOKEN_LOGINACK];
        stream.extend_from_slice(&5u16.to_le_bytes());
        stream.extend_from_slice(&[0u8; 5]);
        assert!(scan_tokens(&stream));
    }

    #[test]
    fn scan_tokens_no_loginack_on_error() {
        // Only an ERROR token in stream
        let mut stream = vec![TOKEN_ERROR];
        stream.extend_from_slice(&4u16.to_le_bytes());
        stream.extend_from_slice(&[0u8; 4]);
        assert!(!scan_tokens(&stream));
    }
}
