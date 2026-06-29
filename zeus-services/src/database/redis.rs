//! Redis AUTH command.

use crate::net::TcpConnection;
use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct RedisProtocol;

#[async_trait]
impl Protocol for RedisProtocol {
    fn name(&self) -> &'static str {
        "redis"
    }
    fn default_port(&self) -> u16 {
        6379
    }
    fn description(&self) -> &'static str {
        "Redis AUTH command"
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
        let mut conn = TcpConnection::connect(addr, config.timeout)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let auth_cmd = format!("AUTH {}\r\n", cred.password);
        conn.write_all(auth_cmd.as_bytes())
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp_str = String::from_utf8_lossy(&resp);
        debug!("Redis AUTH resp: {:?}", resp_str);

        let _ = conn.shutdown().await;

        if resp_str.starts_with("+OK") {
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
    fn redis_meta() {
        assert_eq!(RedisProtocol.name(), "redis");
        assert_eq!(RedisProtocol.default_port(), 6379);
    }
}
