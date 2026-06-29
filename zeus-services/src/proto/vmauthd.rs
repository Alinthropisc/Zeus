//! VMware Authentication Daemon (vmauthd) login, port 902.
//!
//! vmauthd speaks an FTP-like command/response protocol:
//!   1. Connect; read "220 " banner.
//!   2. Send `USER username\r\n`; read "331 " (password required).
//!   3. Send `PASS password\r\n`; read response:
//!      - "230 " → success
//!      - "530 " → failure (login incorrect)
//!      - Other  → protocol error

use async_trait::async_trait;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

use crate::resolve_addr;

pub struct VmauthdProtocol;

#[async_trait]
impl Protocol for VmauthdProtocol {
    fn name(&self) -> &'static str { "vmauthd" }
    fn default_port(&self) -> u16 { 902 }
    fn description(&self) -> &'static str { "VMware Authentication Daemon (vmauthd)" }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let addr = resolve_addr(&target.host, target.port)?;
        let start = Instant::now();

        let mut conn = TcpConnection::connect(addr, config.timeout)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read banner — expect "220 ".
        let banner = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let banner_str = String::from_utf8_lossy(&banner);
        debug!("vmauthd banner: {:?}", banner_str);

        if !banner_str.starts_with("220") {
            let _ = conn.shutdown().await;
            return Err(ZeusError::Protocol(format!(
                "vmauthd: unexpected banner: {}",
                banner_str.trim()
            )));
        }

        // Send USER.
        conn.write_all(format!("USER {}\r\n", cred.username).as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let user_resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let user_resp_str = String::from_utf8_lossy(&user_resp);
        debug!("vmauthd USER resp: {:?}", user_resp_str);

        if !user_resp_str.starts_with("331") {
            let _ = conn.shutdown().await;
            return Err(ZeusError::Protocol(format!(
                "vmauthd: unexpected USER response: {}",
                user_resp_str.trim()
            )));
        }

        // Send PASS.
        conn.write_all(format!("PASS {}\r\n", cred.password).as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let pass_resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let pass_resp_str = String::from_utf8_lossy(&pass_resp);
        debug!("vmauthd PASS resp: {:?}", pass_resp_str);

        let _ = conn.shutdown().await;

        if pass_resp_str.starts_with("230") {
            Ok(AttackResult::Success {
                credential: cred.clone(),
                elapsed: start.elapsed(),
            })
        } else if pass_resp_str.starts_with("530") {
            Ok(AttackResult::Failure)
        } else {
            // Any other response is treated as a failure rather than a hard error,
            // so the engine can continue trying other credentials.
            Ok(AttackResult::Failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmauthd_meta() {
        let p = VmauthdProtocol;
        assert_eq!(p.name(), "vmauthd");
        assert_eq!(p.default_port(), 902);
    }

    #[test]
    fn vmauthd_description_not_empty() {
        assert!(!VmauthdProtocol.description().is_empty());
    }
}
