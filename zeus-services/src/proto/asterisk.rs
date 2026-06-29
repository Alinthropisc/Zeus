//! Asterisk AMI authentication (port 5038).

use async_trait::async_trait;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

use crate::resolve_addr;

pub struct AsteriskProtocol;

#[async_trait]
impl Protocol for AsteriskProtocol {
    fn name(&self) -> &'static str { "asterisk" }
    fn default_port(&self) -> u16 { 5038 }
    fn description(&self) -> &'static str { "Asterisk AMI login" }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let addr = resolve_addr(&target.host, target.port)?;
        let start = Instant::now();

        let mut conn = TcpConnection::connect(addr, config.timeout).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read greeting: "Asterisk Call Manager/X.Y\r\n"
        let banner = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("Asterisk banner: {:?}", String::from_utf8_lossy(&banner));

        let login = format!(
            "Action: Login\r\nUsername: {}\r\nSecret: {}\r\n\r\n",
            cred.username, cred.password
        );
        conn.write_all(login.as_bytes()).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read response block — multiple \r\n-terminated lines until blank line
        let mut response_lines: Vec<String> = Vec::new();
        loop {
            let line = conn.read_until_crlf().await
                .map_err(|e| ZeusError::Protocol(e.to_string()))?;
            let line_str = String::from_utf8_lossy(&line).to_string();
            debug!("Asterisk resp line: {:?}", line_str);
            let trimmed = line_str.trim().to_string();
            if trimmed.is_empty() {
                break;
            }
            response_lines.push(trimmed);
        }

        let _ = conn.shutdown().await;

        let joined = response_lines.join("\n").to_lowercase();
        if joined.contains("response: success") {
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
    fn asterisk_name() {
        assert_eq!(AsteriskProtocol.name(), "asterisk");
    }

    #[test]
    fn asterisk_default_port() {
        assert_eq!(AsteriskProtocol.default_port(), 5038);
    }

    #[test]
    fn asterisk_description_nonempty() {
        assert!(!AsteriskProtocol.description().is_empty());
    }

    #[test]
    fn asterisk_tls_default_false() {
        assert!(!AsteriskProtocol.tls_default());
    }

    #[test]
    fn success_detection() {
        let lines = vec!["Response: Success".to_string(), "Message: Authentication accepted".to_string()];
        let joined = lines.join("\n").to_lowercase();
        assert!(joined.contains("response: success"));
    }

    #[test]
    fn failure_detection() {
        let lines = vec!["Response: Error".to_string(), "Message: Authentication failed".to_string()];
        let joined = lines.join("\n").to_lowercase();
        assert!(!joined.contains("response: success"));
    }
}
