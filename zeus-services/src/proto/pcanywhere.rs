//! Symantec pcAnywhere authentication, port 5631.

use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct PcAnywhereProtocol;

// ── crypto helpers ────────────────────────────────────────────────────────────

/// XOR-chain encryption used by pcAnywhere for login strings.
/// Each byte is XOR'd with a rolling key that starts at 0xAB; the key is
/// updated to the *encrypted* byte before processing the next plaintext byte.
fn pca_encrypt(s: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(s.len());
    let mut key: u8 = 0xAB;
    for &b in s.as_bytes() {
        let enc = b ^ key;
        key = enc;
        result.push(enc);
    }
    result
}

/// Build a pcAnywhere length-prefixed string frame:
/// `\x06` | `len` | `encrypted_bytes`
fn build_pca_string(s: &str) -> Vec<u8> {
    let encrypted = pca_encrypt(s);
    let mut frame = Vec::with_capacity(2 + encrypted.len());
    frame.push(0x06); // string type indicator
    frame.push(encrypted.len() as u8);
    frame.extend_from_slice(&encrypted);
    frame
}

// ── protocol impl ─────────────────────────────────────────────────────────────

#[async_trait]
impl Protocol for PcAnywhereProtocol {
    fn name(&self) -> &'static str { "pcanywhere" }
    fn default_port(&self) -> u16 { 5631 }
    fn description(&self) -> &'static str { "Symantec pcAnywhere authentication" }

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

        // Step 1 – read server banner / initial handshake
        let banner = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("pcAnywhere banner: {:02x?}", banner);

        // Step 2 – send username frame
        let user_frame = build_pca_string(&cred.username);
        conn.write_all(&user_frame)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Step 3 – read intermediate response (\x1a\x00 = auth in progress)
        let mid = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("pcAnywhere mid resp: {:02x?}", mid);

        // Step 4 – send password frame
        let pass_frame = build_pca_string(&cred.password);
        conn.write_all(&pass_frame)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Step 5 – read auth result
        let resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("pcAnywhere auth resp: {:02x?}", resp);
        let _ = conn.shutdown().await;

        if resp.len() < 2 {
            return Ok(AttackResult::Error("short response".into()));
        }

        // Success: response starts with \x00\x00
        if resp[0] == 0x00 && resp[1] == 0x00 {
            Ok(AttackResult::Success { credential: cred.clone(), elapsed: start.elapsed() })
        } else {
            Ok(AttackResult::Failure)
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcanywhere_meta() {
        let p = PcAnywhereProtocol;
        assert_eq!(p.name(), "pcanywhere");
        assert_eq!(p.default_port(), 5631);
    }

    #[test]
    fn pca_encrypt_deterministic() {
        // Same input always produces same output
        assert_eq!(pca_encrypt("admin"), pca_encrypt("admin"));
        // Verify first byte manually: 'a'(0x61) ^ 0xAB = 0xCA
        let enc = pca_encrypt("admin");
        assert_eq!(enc[0], b'a' ^ 0xAB);
        // Second byte: 'd'(0x64) ^ enc[0]
        assert_eq!(enc[1], b'd' ^ enc[0]);
    }

    #[test]
    fn pca_encrypt_nonzero() {
        // For a non-empty input the encrypted bytes should not all be zero
        let enc = pca_encrypt("password");
        assert!(enc.iter().any(|&b| b != 0));
    }

    #[test]
    fn build_pca_string_header() {
        let frame = build_pca_string("admin");
        // First byte must be the string type indicator 0x06
        assert_eq!(frame[0], 0x06);
        // Second byte is the length of the encrypted payload
        assert_eq!(frame[1] as usize, "admin".len());
        // Total frame length = 2 + payload length
        assert_eq!(frame.len(), 2 + "admin".len());
    }
}
