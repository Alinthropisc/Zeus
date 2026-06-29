use async_trait::async_trait;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct RdpProtocol;

#[async_trait]
impl Protocol for RdpProtocol {
    fn name(&self) -> &'static str { "rdp" }
    fn default_port(&self) -> u16 { 3389 }
    fn description(&self) -> &'static str {
        "RDP (Remote Desktop Protocol) authentication stub"
    }

    async fn authenticate(
        &self,
        _target: &Target,
        _cred: &Credential,
        _config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        // RDP authentication requires:
        // 1. T.125 MCS CONNECT initial with GCC conference request
        // 2. TLS/CredSSP negotiation (NLA mode, most common)
        // 3. NTLM or Kerberos via CredSSP
        // Python implementation: impacket. Rust: no mature crate yet.
        Err(ZeusError::Protocol(
            "RDP requires CredSSP/NTLM implementation. No stable Rust crate yet.".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rdp_meta() {
        assert_eq!(RdpProtocol.name(), "rdp");
        assert_eq!(RdpProtocol.default_port(), 3389);
    }
}
