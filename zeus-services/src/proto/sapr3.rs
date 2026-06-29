//! SAP R/3 authentication probe — port 3200/TCP (DIAG) or 8080/HTTP.
//!
//! SAP R/3 uses the proprietary DIAG protocol on ports 32NN (where NN is the
//! two-digit system number, e.g. 3200 for system 00).  Full DIAG support
//! requires Wireshark's `sapr3` dissector logic or SAP's own `librfc`/`saprfc`
//! native library; neither is available as a pure-Rust crate.
//!
//! This module therefore implements two paths:
//!
//! 1. **HTTP path** (port ≥ 8000): the SAP Message Server and ICM expose an
//!    HTTP interface.  We attempt HTTP Basic Auth or a form POST to the SAP
//!    Logon page at `/sap/bc/gui/sap/its/webgui`.
//!
//! 2. **DIAG path** (port < 8000): we connect, send a minimal DPMonitor probe
//!    to confirm the server speaks DIAG, then return a descriptive error
//!    explaining that full credential testing requires `librfc`.

use crate::net::{HttpClient, TcpConnection};
use async_trait::async_trait;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tracing::debug;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

// ── SAP DIAG constants ────────────────────────────────────────────────────────

/// Minimal SAP NI (Network Interface) + DIAG initialisation packet.
///
/// Bytes 0-3: NI header length (big-endian u32, length of remaining bytes).
/// Byte  4:   NI protocol version = 0x02.
/// Byte  5:   Message type — 0xFF = DPMON (DPMonitor request).
///
/// This is enough to elicit a DIAG banner from a genuine SAP application server.
const SAP_NI_PROBE: &[u8] = &[
    0x00, 0x00, 0x00, 0x08, // NI length = 8
    0x02, // NI protocol version
    0xFF, // DPMON type
    0x00, 0x00, // padding
];

// ── HTTP path ─────────────────────────────────────────────────────────────────

async fn try_http(
    target: &Target,
    cred: &Credential,
    config: &AttackConfig,
) -> Result<AttackResult, ZeusError> {
    let scheme = if target.tls { "https" } else { "http" };
    let base_url = format!("{}://{}:{}", scheme, target.host, target.port);
    let client = HttpClient::new(base_url, config.timeout)
        .map_err(|e| ZeusError::Protocol(e.to_string()))?;

    // Default SAP ITS WebGUI logon path; overridable via target option.
    let path = target
        .options
        .get("path")
        .map(String::as_str)
        .unwrap_or("/sap/bc/gui/sap/its/webgui");

    let start = Instant::now();

    // Try HTTP Basic Auth first (SAP ICM supports this for some services).
    let (status, body) = client
        .get_basic_auth(path, &cred.username, &cred.password)
        .await
        .map_err(|e| ZeusError::Protocol(e.to_string()))?;

    debug!("SAP R/3 HTTP status={} for {}", status, cred.username);

    match status {
        200 => {
            // SAP logon success leaves no generic fingerprint; we check for
            // known failure strings in the body.
            let body_lc = body.to_ascii_lowercase();
            let failed = body_lc.contains("incorrect")
                || body_lc.contains("invalid")
                || body_lc.contains("error")
                || body_lc.contains("saplogon");
            if failed {
                Ok(AttackResult::Failure)
            } else {
                Ok(AttackResult::Success {
                    credential: cred.clone(),
                    elapsed: start.elapsed(),
                })
            }
        }
        401 | 403 => Ok(AttackResult::Failure),
        429 => Ok(AttackResult::RateLimit),
        other => Ok(AttackResult::Error(format!(
            "SAP R/3 HTTP: unexpected status {}",
            other
        ))),
    }
}

// ── DIAG path ─────────────────────────────────────────────────────────────────

async fn try_diag(target: &Target, config: &AttackConfig) -> Result<AttackResult, ZeusError> {
    let addr = format!("{}:{}", target.host, target.port)
        .to_socket_addrs()
        .map_err(ZeusError::Network)?
        .next()
        .ok_or_else(|| ZeusError::Protocol("DNS resolution failed".into()))?;

    let mut conn = TcpConnection::connect(addr, config.timeout)
        .await
        .map_err(|e| ZeusError::Protocol(e.to_string()))?;

    conn.write_all(SAP_NI_PROBE)
        .await
        .map_err(|e| ZeusError::Protocol(e.to_string()))?;

    debug!(
        "SAP R/3 DIAG: sent NI probe to {}:{}",
        target.host, target.port
    );

    let resp = conn
        .read_until_crlf()
        .await
        .map_err(|e| ZeusError::Protocol(e.to_string()))?;

    let _ = conn.shutdown().await;

    debug!("SAP R/3 DIAG: got {} byte response", resp.len());

    // Full DIAG credential testing requires:
    //  1. Parsing the DIAG login screen atom (atom type 0x1D).
    //  2. Encoding client info TLVs (kernel release, host name, codepage).
    //  3. Sending a DIAG APPL atom with the username and password fields.
    //  4. Decoding the server's response atom to extract the return code.
    //
    // This requires SAP's proprietary `librfc` or equivalent.
    Err(ZeusError::Protocol(
        "SAP R/3 DIAG full authentication requires librfc/saprfc native library; \
         DIAG probe completed — use port ≥ 8000 for HTTP interface brute-force"
            .into(),
    ))
}

// ── Protocol ─────────────────────────────────────────────────────────────────

pub struct SapR3Protocol;

#[async_trait]
impl Protocol for SapR3Protocol {
    fn name(&self) -> &'static str {
        "sapr3"
    }
    fn default_port(&self) -> u16 {
        3200
    }
    fn description(&self) -> &'static str {
        "SAP R/3 DIAG protocol authentication (partial — use port 8080 for HTTP interface)"
    }

    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        if target.port >= 8000 {
            try_http(target, cred, config).await
        } else {
            try_diag(target, config).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sapr3_meta() {
        assert_eq!(SapR3Protocol.name(), "sapr3");
        assert_eq!(SapR3Protocol.default_port(), 3200);
    }

    #[test]
    fn sapr3_description_not_empty() {
        assert!(!SapR3Protocol.description().is_empty());
    }
}
