use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct Socks5Protocol;

#[async_trait]
impl Protocol for Socks5Protocol {
    fn name(&self) -> &'static str { "socks5" }
    fn default_port(&self) -> u16 { 1080 }
    fn description(&self) -> &'static str { "SOCKS5 username/password authentication (RFC 1928/1929)" }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        if cred.username.len() > 255 || cred.password.len() > 255 {
            return Ok(AttackResult::Error("Credential exceeds SOCKS5 255-byte limit".into()));
        }

        let addr_str = format!("{}:{}", target.host, target.port);
        let addr = addr_str.to_socket_addrs().map_err(ZeusError::Network)?
            .next().ok_or_else(|| ZeusError::Protocol("DNS failed".into()))?;

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Client greeting: VER=5, NMETHODS=2, METHODS=[0x00 NoAuth, 0x02 UserPass]
        conn.write_all(&[0x05, 0x02, 0x00, 0x02]).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let server_choice = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("SOCKS5 method choice: {:?}", server_choice);

        if server_choice.len() < 2 || server_choice[0] != 5 {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("Not a SOCKS5 server".into()));
        }

        // 0xFF = no acceptable method
        if server_choice[1] == 0xFF {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("SOCKS5 rejected all auth methods".into()));
        }

        // 0x00 = no auth required (open proxy)
        if server_choice[1] == 0x00 {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("SOCKS5 requires no authentication (open proxy)".into()));
        }

        // 0x02 = username/password auth (RFC 1929)
        if server_choice[1] != 0x02 {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error(format!("SOCKS5 unsupported method: 0x{:02x}", server_choice[1])));
        }

        // Auth subnegotiation: VER=1, ULEN, USER, PLEN, PASS
        let ulen = cred.username.len() as u8;
        let plen = cred.password.len() as u8;
        let mut auth_packet = Vec::with_capacity(3 + ulen as usize + plen as usize);
        auth_packet.push(0x01);
        auth_packet.push(ulen);
        auth_packet.extend_from_slice(cred.username.as_bytes());
        auth_packet.push(plen);
        auth_packet.extend_from_slice(cred.password.as_bytes());

        conn.write_all(&auth_packet).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let auth_resp = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("SOCKS5 auth resp: {:?}", auth_resp);

        let _ = conn.shutdown().await;

        // Status byte 0x00 = success, anything else = failure
        if auth_resp.len() >= 2 && auth_resp[1] == 0x00 {
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
    fn socks5_meta() {
        assert_eq!(Socks5Protocol.name(), "socks5");
        assert_eq!(Socks5Protocol.default_port(), 1080);
    }
}
