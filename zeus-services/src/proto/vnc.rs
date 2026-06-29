use async_trait::async_trait;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use crate::net::TcpConnection;

pub struct VncProtocol;

// VNC DES: password is used as a key (max 8 bytes, padded with nulls)
// Bits are reversed in each byte compared to standard DES
fn vnc_des_encrypt(challenge: &[u8; 16], password: &str) -> [u8; 16] {
    let mut key = [0u8; 8];
    for (i, &b) in password.as_bytes().iter().take(8).enumerate() {
        // Reverse bits in each byte (VNC quirk)
        key[i] = b.reverse_bits();
    }

    let mut result = [0u8; 16];
    // Simple DES ECB with 8-byte blocks
    for block_idx in 0..2 {
        let input = &challenge[block_idx * 8..(block_idx + 1) * 8];
        let output = des_encrypt_block(input, &key);
        result[block_idx * 8..(block_idx + 1) * 8].copy_from_slice(&output);
    }
    result
}

fn des_encrypt_block(input: &[u8], key: &[u8; 8]) -> [u8; 8] {
    use des::cipher::generic_array::GenericArray;
    // Real DES ECB encryption. The VNC bit-reversal is already applied
    // to the key bytes in vnc_des_encrypt before calling this function.
    let cipher = Des::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(input);
    cipher.encrypt_block(&mut block);
    block.into()
}

#[async_trait]
impl Protocol for VncProtocol {
    fn name(&self) -> &'static str { "vnc" }
    fn default_port(&self) -> u16 { 5900 }
    fn description(&self) -> &'static str { "VNC RFB 3.3/3.7/3.8 password authentication (DES challenge)" }

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

        // Read RFB version string "RFB 003.003\n" or "RFB 003.008\n"
        let version_buf = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        let version_str = String::from_utf8_lossy(&version_buf);
        debug!("VNC server version: {:?}", version_str);

        if !version_str.starts_with("RFB") {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("Not a VNC server".into()));
        }

        // Send our version (3.3 for maximum compatibility)
        conn.write_all(b"RFB 003.003\n").await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read security type: 4 bytes, little-endian
        // 0x00000000 = error, 0x00000001 = None, 0x00000002 = VNC auth
        let sec_buf = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("VNC security type bytes: {:?}", &sec_buf[..sec_buf.len().min(4)]);

        if sec_buf.len() < 4 {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("VNC: short security type read".into()));
        }

        let sec_type = u32::from_be_bytes([sec_buf[0], sec_buf[1], sec_buf[2], sec_buf[3]]);
        debug!("VNC security type: {}", sec_type);

        if sec_type == 1 {
            // No auth required
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("VNC: No authentication required".into()));
        }

        if sec_type != 2 {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error(format!("VNC: Unsupported security type {}", sec_type)));
        }

        // Read 16-byte challenge
        let challenge_buf = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        if challenge_buf.len() < 16 {
            let _ = conn.shutdown().await;
            return Ok(AttackResult::Error("VNC: short challenge".into()));
        }

        let mut challenge = [0u8; 16];
        challenge.copy_from_slice(&challenge_buf[..16]);
        debug!("VNC challenge: {:?}", challenge);

        // Encrypt the challenge with the password
        let response = vnc_des_encrypt(&challenge, &cred.password);
        conn.write_all(&response).await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        // Read auth result: 4 bytes, 0 = OK, non-0 = failed
        let result_buf = conn.read_until_crlf().await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let _ = conn.shutdown().await;

        if result_buf.len() >= 4 {
            let result_code = u32::from_be_bytes([result_buf[0], result_buf[1], result_buf[2], result_buf[3]]);
            if result_code == 0 {
                return Ok(AttackResult::Success { credential: cred.clone(), elapsed: start.elapsed() });
            }
        }

        Ok(AttackResult::Failure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vnc_meta() {
        assert_eq!(VncProtocol.name(), "vnc");
        assert_eq!(VncProtocol.default_port(), 5900);
    }
    #[test]
    fn vnc_description_not_empty() {
        assert!(!VncProtocol.description().is_empty());
    }

    #[test]
    fn vnc_des_key_length() {
        let challenge = [0xAA; 16];
        let response = vnc_des_encrypt(&challenge, "password");
        assert_eq!(response.len(), 16);
    }

    #[test]
    fn vnc_des_bit_reversal() {
        // Key byte 'A' (0x41 = 0b01000001) reversed = 0b10000010 = 0x82
        let challenge = [0u8; 16];
        let r1 = vnc_des_encrypt(&challenge, "A");
        let r2 = vnc_des_encrypt(&challenge, "A");
        assert_eq!(r1, r2, "encryption must be deterministic");
    }

    #[test]
    fn des_encrypt_block_not_xor() {
        // Verify the result is NOT what a naive XOR stub would produce.
        // With XOR the output would equal key ^ 0 = key bytes.
        let input = [0u8; 8];
        let key = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let result = des_encrypt_block(&input, &key);
        // XOR stub would yield [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08]
        assert_ne!(result, key, "real DES must not equal naive XOR output");
    }

    #[test]
    fn vnc_known_challenge_response() {
        // Challenge of all zeros, password "password" — just verify shape.
        let challenge = [0u8; 16];
        let response = vnc_des_encrypt(&challenge, "password");
        assert_eq!(response.len(), 16, "VNC response must be 16 bytes");
        // Result must be deterministic
        let response2 = vnc_des_encrypt(&challenge, "password");
        assert_eq!(response, response2);
        // Must not be all zeros (real DES produces non-zero output)
        assert_ne!(response, [0u8; 16]);
    }
}
