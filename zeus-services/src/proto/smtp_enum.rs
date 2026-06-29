use crate::net::TcpConnection;
use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

// ──────────────────────────────────────────────────────────────────────────────
// Strategy pattern — SMTP enumeration strategies
// ──────────────────────────────────────────────────────────────────────────────

/// SMTP user enumeration method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpEnumMethod {
    /// `VRFY <username>` — direct mailbox verification.
    Vrfy,
    /// `EXPN <list>` — mailing list expansion (may reveal members).
    Expn,
    /// `RCPT TO:<user@domain>` — probe via delivery path.
    RcptTo,
}

impl SmtpEnumMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vrfy => "vrfy",
            Self::Expn => "expn",
            Self::RcptTo => "rcpt",
        }
    }
}

/// Result of a single SMTP enumeration attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnumResult {
    /// User likely exists (2xx response).
    Exists,
    /// User does not exist (5xx response).
    NotFound,
    /// Server returned an ambiguous / non-standard code.
    Ambiguous(String),
}

/// Strategy interface — each method implements this trait.
#[async_trait]
pub trait SmtpEnumStrategy: Send + Sync {
    /// Try to enumerate `user` over the open `conn`.
    ///
    /// The connection is expected to have already completed the EHLO handshake.
    async fn enumerate(
        &self,
        conn: &mut TcpConnection,
        user: &str,
    ) -> Result<EnumResult, ZeusError>;
}

// ── VrfyStrategy ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct VrfyStrategy;

#[async_trait]
impl SmtpEnumStrategy for VrfyStrategy {
    async fn enumerate(
        &self,
        conn: &mut TcpConnection,
        user: &str,
    ) -> Result<EnumResult, ZeusError> {
        let cmd = format!("VRFY {}\r\n", user);
        conn.write_all(cmd.as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        Ok(interpret_smtp_response(&resp))
    }
}

// ── ExpnStrategy ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ExpnStrategy;

#[async_trait]
impl SmtpEnumStrategy for ExpnStrategy {
    async fn enumerate(
        &self,
        conn: &mut TcpConnection,
        user: &str,
    ) -> Result<EnumResult, ZeusError> {
        let cmd = format!("EXPN {}\r\n", user);
        conn.write_all(cmd.as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        Ok(interpret_smtp_response(&resp))
    }
}

// ── RcptToStrategy ───────────────────────────────────────────────────────────

/// `RCPT TO` strategy — requires a valid `MAIL FROM` to have been issued first.
#[derive(Debug)]
pub struct RcptToStrategy {
    /// Sender domain for the `MAIL FROM` envelope.
    pub from_domain: String,
}

impl RcptToStrategy {
    pub fn new(from_domain: impl Into<String>) -> Self {
        Self {
            from_domain: from_domain.into(),
        }
    }
}

#[async_trait]
impl SmtpEnumStrategy for RcptToStrategy {
    async fn enumerate(
        &self,
        conn: &mut TcpConnection,
        user: &str,
    ) -> Result<EnumResult, ZeusError> {
        // Issue MAIL FROM before RCPT TO.
        let mail_from = format!("MAIL FROM:<zeus@{}>\r\n", self.from_domain);
        conn.write_all(mail_from.as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        conn.read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let rcpt = format!("RCPT TO:<{}@{}>\r\n", user, self.from_domain);
        conn.write_all(rcpt.as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        Ok(interpret_smtp_response(&resp))
    }
}

// ── Helper ───────────────────────────────────────────────────────────────────

fn interpret_smtp_response(raw: &[u8]) -> EnumResult {
    let s = String::from_utf8_lossy(raw);
    match s.get(..3).unwrap_or("") {
        "250" | "251" | "252" => EnumResult::Exists,
        "550" | "551" | "553" | "554" => EnumResult::NotFound,
        other => EnumResult::Ambiguous(other.to_string()),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SmtpConn — thin wrapper used by strategy tests / callers
// ──────────────────────────────────────────────────────────────────────────────

/// Re-export alias so external callers can refer to the underlying connection
/// type through the strategy API without depending on `zeus_net` directly.
pub type SmtpConn = TcpConnection;

// ──────────────────────────────────────────────────────────────────────────────
// Legacy Protocol impl (unchanged behaviour, now delegates internally)
// ──────────────────────────────────────────────────────────────────────────────

pub struct SmtpEnumProtocol;

#[async_trait]
impl Protocol for SmtpEnumProtocol {
    fn name(&self) -> &'static str {
        "smtp-enum"
    }
    fn default_port(&self) -> u16 {
        25
    }
    fn description(&self) -> &'static str {
        "SMTP user enumeration via VRFY/EXPN. Options: method=vrfy|expn|rcpt, domain=example.com"
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

        let method = target
            .options
            .get("method")
            .map(String::as_str)
            .unwrap_or("vrfy");
        let domain = target
            .options
            .get("domain")
            .map(String::as_str)
            .unwrap_or("localhost");

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        conn.read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        conn.write_all(b"EHLO zeus\r\n")
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        conn.read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let cmd = match method {
            "expn" => format!("EXPN {}\r\n", cred.username),
            "rcpt" => {
                conn.write_all(format!("MAIL FROM:<zeus@{}>\r\n", domain).as_bytes())
                    .await
                    .map_err(|e| ZeusError::Protocol(e.to_string()))?;
                conn.read_until_crlf()
                    .await
                    .map_err(|e| ZeusError::Protocol(e.to_string()))?;
                format!("RCPT TO:<{}@{}>\r\n", cred.username, domain)
            }
            _ => format!("VRFY {}\r\n", cred.username),
        };

        conn.write_all(cmd.as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp_str = String::from_utf8_lossy(&resp);
        debug!("SMTP-ENUM resp: {:?}", resp_str);

        let _ = conn.write_all(b"QUIT\r\n").await;
        let _ = conn.shutdown().await;

        // 250 or 251 or 252 = user exists
        let code = resp_str.get(..3).unwrap_or("000");
        if matches!(code, "250" | "251" | "252") {
            Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            })
        } else {
            Ok(AttackResult::Failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_enum_meta() {
        assert_eq!(SmtpEnumProtocol.name(), "smtp-enum");
    }

    #[test]
    fn interpret_response_exists() {
        assert_eq!(
            interpret_smtp_response(b"250 alice@example.com"),
            EnumResult::Exists
        );
        assert_eq!(
            interpret_smtp_response(b"251 forwarded"),
            EnumResult::Exists
        );
        assert_eq!(
            interpret_smtp_response(b"252 cannot verify"),
            EnumResult::Exists
        );
    }

    #[test]
    fn interpret_response_not_found() {
        assert_eq!(
            interpret_smtp_response(b"550 no such user"),
            EnumResult::NotFound
        );
        assert_eq!(
            interpret_smtp_response(b"553 mailbox name not allowed"),
            EnumResult::NotFound
        );
    }

    #[test]
    fn interpret_response_ambiguous() {
        assert_eq!(
            interpret_smtp_response(b"421 service unavailable"),
            EnumResult::Ambiguous("421".to_string())
        );
    }

    #[test]
    fn smtp_enum_method_as_str() {
        assert_eq!(SmtpEnumMethod::Vrfy.as_str(), "vrfy");
        assert_eq!(SmtpEnumMethod::Expn.as_str(), "expn");
        assert_eq!(SmtpEnumMethod::RcptTo.as_str(), "rcpt");
    }
}
