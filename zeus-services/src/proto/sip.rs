//! SIP REGISTER Digest authentication (RFC 3261).
//!
//! Flow:
//!   1. Send REGISTER (unauthenticated) over raw TCP
//!   2. Parse 401 Unauthorized — extract realm + nonce from WWW-Authenticate
//!   3. Compute HA1=MD5(user:realm:pass), HA2=MD5("REGISTER":uri)
//!   4. response=MD5(HA1:nonce:HA2)
//!   5. Re-send REGISTER with Authorization header
//!   6. 200 OK = success, 403/407 = failure

use async_trait::async_trait;
use md5::{Digest, Md5};
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

use crate::resolve_addr;

pub struct SipProtocol;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn md5_hex(data: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Parse a quoted or unquoted value from a SIP header field.
/// e.g. `realm="asterisk"` → `asterisk`
fn parse_header_value<'a>(header: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{}=", key);
    let start = header.find(needle.as_str())? + needle.len();
    let rest = &header[start..];
    if rest.starts_with('"') {
        let inner = &rest[1..];
        let end = inner.find('"')?;
        Some(&inner[..end])
    } else {
        let end = rest.find([',', ' ', '\r', '\n']).unwrap_or(rest.len());
        Some(&rest[..end])
    }
}

fn build_register(host: &str, port: u16, user: &str, call_id: &str, cseq: u32) -> String {
    let uri = format!("sip:{}:{}", host, port);
    let contact = format!("sip:{}@{}:{}", user, host, port);
    format!(
        "REGISTER {uri} SIP/2.0\r\n\
         Via: SIP/2.0/TCP {host}:{port};branch=z9hG4bK{cseq:08x}\r\n\
         From: <{contact}>;tag={cseq:08x}\r\n\
         To: <{contact}>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} REGISTER\r\n\
         Contact: <{contact}>\r\n\
         Max-Forwards: 70\r\n\
         Content-Length: 0\r\n\r\n",
        uri = uri,
        host = host,
        port = port,
        contact = contact,
        call_id = call_id,
        cseq = cseq,
    )
}

fn build_register_auth(
    host: &str,
    port: u16,
    user: &str,
    call_id: &str,
    cseq: u32,
    realm: &str,
    nonce: &str,
    response: &str,
) -> String {
    let uri = format!("sip:{}:{}", host, port);
    let contact = format!("sip:{}@{}:{}", user, host, port);
    let auth = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
        user, realm, nonce, uri, response
    );
    format!(
        "REGISTER {uri} SIP/2.0\r\n\
         Via: SIP/2.0/TCP {host}:{port};branch=z9hG4bK{cseq:08x}\r\n\
         From: <{contact}>;tag={cseq:08x}\r\n\
         To: <{contact}>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} REGISTER\r\n\
         Contact: <{contact}>\r\n\
         Max-Forwards: 70\r\n\
         Authorization: {auth}\r\n\
         Content-Length: 0\r\n\r\n",
        uri = uri,
        host = host,
        port = port,
        contact = contact,
        call_id = call_id,
        cseq = cseq,
        auth = auth,
    )
}

/// Read SIP response (potentially multi-line) until blank line.
async fn read_sip_response(conn: &mut TcpConnection) -> Result<String, ZeusError> {
    let mut response = String::new();
    loop {
        let line = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let s = String::from_utf8_lossy(&line).to_string();
        let is_empty_line = s.trim().is_empty();
        response.push_str(&s);
        response.push('\n');
        if is_empty_line {
            break;
        }
    }
    Ok(response)
}

fn status_code(response: &str) -> Option<u16> {
    let line = response.lines().next()?;
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

// ─── Protocol impl ───────────────────────────────────────────────────────────

#[async_trait]
impl Protocol for SipProtocol {
    fn name(&self) -> &'static str { "sip" }
    fn default_port(&self) -> u16 { 5060 }
    fn description(&self) -> &'static str { "SIP REGISTER Digest authentication (VoIP, RFC 3261)" }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let addr = resolve_addr(&target.host, target.port)?;
        let call_id = format!("zeus{:x}@{}", rand_u32(), target.host);

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Step 1: unauthenticated REGISTER
        let reg1 = build_register(&target.host, target.port, &cred.username, &call_id, 1);
        conn.write_all(reg1.as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let resp1 = read_sip_response(&mut conn).await?;
        debug!("SIP resp1: {:?}", &resp1[..resp1.len().min(300)]);

        let code1 = status_code(&resp1).unwrap_or(0);

        if code1 == 200 {
            // Server accepts without auth — report as success
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            });
        }

        if code1 != 401 && code1 != 407 {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Failure);
        }

        // Step 2: extract realm + nonce from WWW-Authenticate or Proxy-Authenticate
        let www_auth_line = resp1
            .lines()
            .find(|l| {
                l.to_ascii_lowercase().starts_with("www-authenticate:")
                    || l.to_ascii_lowercase().starts_with("proxy-authenticate:")
            })
            .unwrap_or("");

        let realm = parse_header_value(www_auth_line, "realm").unwrap_or("asterisk");
        let nonce = parse_header_value(www_auth_line, "nonce").unwrap_or("");
        debug!("SIP realm={} nonce={}", realm, nonce);

        // Step 3: compute Digest response
        let uri = format!("sip:{}:{}", target.host, target.port);
        let ha1 = md5_hex(&format!("{}:{}:{}", cred.username, realm, cred.password));
        let ha2 = md5_hex(&format!("REGISTER:{}", uri));
        let response_val = md5_hex(&format!("{}:{}:{}", ha1, nonce, ha2));

        // Step 4: authenticated REGISTER
        let reg2 = build_register_auth(
            &target.host,
            target.port,
            &cred.username,
            &call_id,
            2,
            realm,
            nonce,
            &response_val,
        );
        conn.write_all(reg2.as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let resp2 = read_sip_response(&mut conn).await?;
        debug!("SIP resp2: {:?}", &resp2[..resp2.len().min(200)]);

        let _ = conn.shutdown().await;

        match status_code(&resp2).unwrap_or(0) {
            200 => Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            }),
            401 | 403 | 407 => Ok(AttackResult::Failure),
            _ => Ok(AttackResult::Failure),
        }
    }
}

/// Simple deterministic pseudo-random u32 based on process id + time.
fn rand_u32() -> u32 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(42);
    (nanos ^ (std::process::id() << 16)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sip_meta() {
        let p = SipProtocol;
        assert_eq!(p.name(), "sip");
        assert_eq!(p.default_port(), 5060);
    }

    #[test]
    fn parse_realm() {
        let header = r#"WWW-Authenticate: Digest realm="asterisk", nonce="abc123", algorithm=MD5"#;
        assert_eq!(parse_header_value(header, "realm"), Some("asterisk"));
        assert_eq!(parse_header_value(header, "nonce"), Some("abc123"));
    }

    #[test]
    fn md5_hex_known() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        assert_eq!(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn status_code_parse() {
        assert_eq!(status_code("SIP/2.0 401 Unauthorized\r\n"), Some(401));
        assert_eq!(status_code("SIP/2.0 200 OK\r\n"), Some(200));
    }
}
