//! SMTP AUTH LOGIN / PLAIN.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct SmtpProtocol;

/// Read a complete SMTP response, consuming all continuation lines (e.g. "250-..." until "250 ...").
async fn read_smtp_response(conn: &mut TcpConnection) -> Result<String, ZeusError> {
    let mut full = String::new();
    loop {
        let line = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let s = String::from_utf8_lossy(&line).to_string();
        let is_continuation = s.len() >= 4 && s.as_bytes().get(3) == Some(&b'-');
        full.push_str(&s);
        if !is_continuation {
            break;
        }
    }
    Ok(full)
}

#[async_trait]
impl Protocol for SmtpProtocol {
    fn name(&self) -> &'static str { "smtp" }
    fn default_port(&self) -> u16 { 25 }
    fn description(&self) -> &'static str { "SMTP AUTH LOGIN/PLAIN" }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let addr_str = format!("{}:{}", target.host, target.port);
        let addr = addr_str.to_socket_addrs().map_err(ZeusError::Network)?
            .next().ok_or_else(|| ZeusError::Protocol("DNS failed".into()))?;

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read server greeting (may be multi-line 220-)
        read_smtp_response(&mut conn).await?;

        // EHLO — server replies with multi-line 250- capability lines
        conn.write_all(b"EHLO zeus\r\n").await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let ehlo_resp = read_smtp_response(&mut conn).await?;
        debug!("SMTP EHLO: {:?}", &ehlo_resp[..ehlo_resp.len().min(300)]);

        // Prefer AUTH PLAIN if advertised, otherwise AUTH LOGIN
        let use_plain = ehlo_resp.contains("AUTH PLAIN") || ehlo_resp.contains("AUTH=PLAIN");

        if use_plain {
            // AUTH PLAIN: single step — base64("\0username\0password")
            let plain = format!("\x00{}\x00{}", cred.username, cred.password);
            let plain_b64 = BASE64.encode(plain.as_bytes());
            conn.write_all(format!("AUTH PLAIN {}\r\n", plain_b64).as_bytes()).await
                .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        } else {
            // AUTH LOGIN: two-step username/password challenge
            conn.write_all(b"AUTH LOGIN\r\n").await
                .map_err(|e| ZeusError::Protocol(e.to_string()))?;
            let challenge1 = read_smtp_response(&mut conn).await?;
            debug!("SMTP AUTH LOGIN challenge1: {:?}", challenge1);
            if !challenge1.starts_with("334") {
                let _ = conn.write_all(b"QUIT\r\n").await;
                let _ = conn.shutdown().await;
                return Ok(AttackResult::Error("SMTP AUTH LOGIN not supported".into()));
            }

            let user_b64 = BASE64.encode(cred.username.as_bytes());
            conn.write_all(format!("{}\r\n", user_b64).as_bytes()).await
                .map_err(|e| ZeusError::Protocol(e.to_string()))?;
            // Read "334 UGFzc3dvcmQ6" (Password: prompt)
            read_smtp_response(&mut conn).await?;

            let pass_b64 = BASE64.encode(cred.password.as_bytes());
            conn.write_all(format!("{}\r\n", pass_b64).as_bytes()).await
                .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        }

        let resp = read_smtp_response(&mut conn).await?;
        debug!("SMTP AUTH resp: {:?}", resp);

        let _ = conn.write_all(b"QUIT\r\n").await;
        let _ = conn.shutdown().await;

        if resp.starts_with("235") {
            Ok(AttackResult::Success { credential: cred.clone(), elapsed: start.elapsed() })
        } else {
            Ok(AttackResult::Failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn smtp_meta() {
        assert_eq!(SmtpProtocol.name(), "smtp");
        assert_eq!(SmtpProtocol.default_port(), 25);
    }

    #[test]
    fn smtp_description_not_empty() {
        assert!(!SmtpProtocol.description().is_empty());
    }
}
