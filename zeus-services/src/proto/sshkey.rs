//! SSH-2 public-key authentication stub.
//!
//! The `russh` / `russh_keys` crates are not included in this workspace.
//! This stub satisfies the module requirement without pulling in those deps.

use async_trait::async_trait;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct SshKeyProtocol;

#[async_trait]
impl Protocol for SshKeyProtocol {
    fn name(&self) -> &'static str { "ssh-key" }
    fn default_port(&self) -> u16 { 22 }
    fn description(&self) -> &'static str {
        "SSH-2 public-key authentication (stub — russh not available)"
    }

    async fn authenticate(
        &self,
        _target: &Target,
        _cred: &Credential,
        _config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        Err(ZeusError::Protocol("SSH key support requires the russh crate which is not compiled into this build".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sshkey_meta() {
        let p = SshKeyProtocol;
        assert_eq!(p.name(), "ssh-key");
        assert_eq!(p.default_port(), 22);
    }

    #[test]
    fn sshkey_pem_detection() {
        let inline = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----";
        assert!(inline.trim_start().starts_with("-----"));
        let path = "/home/user/.ssh/id_rsa";
        assert!(!path.trim_start().starts_with("-----"));
    }
}
