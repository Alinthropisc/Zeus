use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct XmppProtocol;

#[async_trait]
impl Protocol for XmppProtocol {
    fn name(&self) -> &'static str { "xmpp" }
    fn default_port(&self) -> u16 { 5222 }
    fn description(&self) -> &'static str { "XMPP SASL PLAIN authentication (Jabber)" }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        let addr_str = format!("{}:{}", target.host, target.port);
        let addr = addr_str.to_socket_addrs().map_err(ZeusError::Network)?
            .next().ok_or_else(|| ZeusError::Protocol("DNS failed".into()))?;

        let domain = target.options.get("domain")
            .map(String::as_str)
            .unwrap_or(target.host.as_str());

        // SASL PLAIN: \0username\0password (base64 encoded)
        let plain = format!("\x00{}\x00{}", cred.username, cred.password);
        let plain_b64 = BASE64.encode(plain.as_bytes());

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // XMPP stream open
        let stream_open = format!(
            "<?xml version='1.0'?><stream:stream to='{}' xmlns='jabber:client' \
             xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>",
            domain
        );
        conn.write_all(stream_open.as_bytes()).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read server features
        let mut features = String::new();
        for _ in 0..5 {
            let chunk = conn.read_until_crlf().await
                .map_err(|e| ZeusError::Protocol(e.to_string()))?;
            let s = String::from_utf8_lossy(&chunk);
            features.push_str(&s);
            if features.contains("</stream:features>") { break; }
        }
        debug!("XMPP features: {}", &features[..features.len().min(200)]);

        if !features.contains("PLAIN") {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("XMPP server does not support SASL PLAIN".into()));
        }

        // SASL PLAIN auth
        let auth_xml = format!(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{}</auth>",
            plain_b64
        );
        conn.write_all(auth_xml.as_bytes()).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let resp = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let resp_str = String::from_utf8_lossy(&resp);
        debug!("XMPP auth resp: {:?}", resp_str);

        let _ = conn.shutdown().await;

        if resp_str.contains("<success") {
            Ok(AttackResult::Success { credential: cred.clone(), elapsed: start.elapsed() })
        } else if resp_str.contains("<failure") {
            Ok(AttackResult::Failure)
        } else {
            Ok(AttackResult::Failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn xmpp_meta() {
        assert_eq!(XmppProtocol.name(), "xmpp");
        assert_eq!(XmppProtocol.default_port(), 5222);
    }
}
