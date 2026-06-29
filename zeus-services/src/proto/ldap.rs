use crate::net::TcpConnection;
use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct LdapProtocol;

/// Build a minimal LDAPv3 BindRequest (Simple auth) in BER encoding.
///
/// Wire layout:
///   SEQUENCE {
///     INTEGER msgId,
///     [APPLICATION 0] {        -- BindRequest
///       INTEGER 3,             -- version
///       OCTET STRING dn,       -- name
///       [0] OCTET STRING pass  -- simple authentication
///     }
///   }
pub fn ldap_bind_request(msg_id: u32, dn: &str, password: &str) -> Vec<u8> {
    let version: &[u8] = &[0x02, 0x01, 0x03]; // INTEGER 3
    let dn_encoded = encode_ber_tlv(0x04, dn.as_bytes());
    let pass_bytes = password.as_bytes();
    let auth = encode_ber_tlv(0x80, pass_bytes); // [0] context-specific primitive

    let mut bind_body = Vec::new();
    bind_body.extend_from_slice(version);
    bind_body.extend_from_slice(&dn_encoded);
    bind_body.extend_from_slice(&auth);

    let bind_req = encode_ber_tlv(0x60, &bind_body); // APPLICATION 0 CONSTRUCTED

    let msg_id_enc = {
        let mut v = vec![0x02u8, 0x04];
        v.extend_from_slice(&msg_id.to_be_bytes());
        v
    };

    let mut envelope_body = Vec::new();
    envelope_body.extend_from_slice(&msg_id_enc);
    envelope_body.extend_from_slice(&bind_req);

    encode_ber_tlv(0x30, &envelope_body) // SEQUENCE
}

/// Encode a BER TLV with definite short-form length (works for payloads ≤ 127 bytes).
/// For longer payloads, emits a two-byte length (0x81 + len).
fn encode_ber_tlv(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if data.len() <= 127 {
        out.push(data.len() as u8);
    } else {
        out.push(0x81);
        out.push(data.len() as u8);
    }
    out.extend_from_slice(data);
    out
}

/// Parse the LDAP resultCode from a BindResponse.
///
/// Expected structure (with short-form lengths):
///   [0] 0x30  SEQUENCE tag
///   [1] len
///   [2] 0x02  INTEGER tag  (messageID)
///   [3] 0x01
///   [4] msgId value
///   [5] 0x61  APPLICATION 1 (BindResponse)
///   [6] len
///   [7] 0x0A  ENUMERATED tag (resultCode)
///   [8] 0x01
///   [9] resultCode value  ← we want this
fn parse_ldap_result_code(resp: &[u8]) -> Option<u8> {
    // Walk past SEQUENCE header
    if resp.len() < 10 {
        return None;
    }
    if resp[0] != 0x30 {
        return None;
    }

    // Skip outer SEQUENCE length (1 or 2 bytes)
    let offset = if resp[1] & 0x80 != 0 {
        2 + (resp[1] & 0x7f) as usize
    } else {
        2
    };

    // Skip messageID TLV: 0x02 + len + value
    if resp.get(offset) != Some(&0x02) {
        return None;
    }
    let id_len = *resp.get(offset + 1)? as usize;
    let app_offset = offset + 2 + id_len;

    // Expect APPLICATION 1 (BindResponse) = 0x61
    if resp.get(app_offset) != Some(&0x61) {
        return None;
    }
    let app_len_byte = *resp.get(app_offset + 1)?;
    let body_offset = if app_len_byte & 0x80 != 0 {
        app_offset + 2 + (app_len_byte & 0x7f) as usize
    } else {
        app_offset + 2
    };

    // First field inside BindResponse is resultCode ENUMERATED (0x0A)
    if resp.get(body_offset) != Some(&0x0A) {
        return None;
    }
    let enum_len = *resp.get(body_offset + 1)? as usize;
    if enum_len < 1 {
        return None;
    }
    resp.get(body_offset + 2).copied()
}

#[async_trait]
impl Protocol for LdapProtocol {
    fn name(&self) -> &'static str {
        "ldap"
    }
    fn default_port(&self) -> u16 {
        389
    }
    fn description(&self) -> &'static str {
        "LDAP Simple Bind authentication"
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

        let dn = target
            .options
            .get("dn")
            .map(String::as_str)
            .unwrap_or(cred.username.as_str());

        let start = Instant::now();
        let mut conn = TcpConnection::connect(addr, config.timeout)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let bind_req = ldap_bind_request(1, dn, &cred.password);
        conn.write_all(&bind_req)
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;

        let resp = conn
            .read_until_crlf()
            .await
            .map_err(|e| ZeusError::Protocol(e.to_string()))?;
        debug!("LDAP bind resp len={}", resp.len());

        let _ = conn.shutdown().await;

        match parse_ldap_result_code(&resp) {
            Some(0x00) => {
                debug!("LDAP resultCode=0 (success)");
                Ok(AttackResult::Success {
                    credential: cred.clone(),
                    elapsed: start.elapsed(),
                })
            }
            Some(code) => {
                debug!("LDAP resultCode={} (failure)", code);
                Ok(AttackResult::Failure)
            }
            None => {
                debug!("LDAP: could not parse resultCode from {} bytes", resp.len());
                Ok(AttackResult::Failure)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ldap_meta() {
        assert_eq!(LdapProtocol.name(), "ldap");
        assert_eq!(LdapProtocol.default_port(), 389);
    }

    #[test]
    fn ldap_description_not_empty() {
        assert!(!LdapProtocol.description().is_empty());
    }

    #[test]
    fn bind_request_structure() {
        let req = ldap_bind_request(1, "cn=admin,dc=test,dc=com", "secret");
        assert!(!req.is_empty());
        assert_eq!(req[0], 0x30, "outer tag must be SEQUENCE");
        // messageID INTEGER tag follows SEQUENCE header at offset 2
        assert_eq!(req[2], 0x02, "messageID must be INTEGER");
        // APPLICATION 0 BindRequest follows msgId TLV (offset 2+2+4=8)
        assert_eq!(
            req[8], 0x60,
            "BindRequest must be APPLICATION 0 CONSTRUCTED"
        );
    }

    #[test]
    fn parse_result_code_success_response() {
        // Hand-crafted minimal BindResponse with resultCode=0 (success)
        // SEQUENCE { INTEGER 1, [APPLICATION 1] { ENUM 0, OCTET "" , OCTET "" } }
        let response: &[u8] = &[
            0x30, 0x0C, // SEQUENCE, len=12
            0x02, 0x01, 0x01, // INTEGER msgId=1
            0x61, 0x07, // APPLICATION 1 (BindResponse), len=7
            0x0A, 0x01, 0x00, // ENUMERATED resultCode=0
            0x04, 0x00, // matchedDN="" (OCTET STRING, empty)
            0x04, 0x00, // diagnosticMessage="" (OCTET STRING, empty)
        ];
        assert_eq!(parse_ldap_result_code(response), Some(0x00));
    }

    #[test]
    fn parse_result_code_invalid_credentials() {
        let response: &[u8] = &[
            0x30, 0x0C, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0A, 0x01,
            0x31, // resultCode=49 (invalidCredentials)
            0x04, 0x00, 0x04, 0x00,
        ];
        assert_eq!(parse_ldap_result_code(response), Some(0x31));
    }
}
