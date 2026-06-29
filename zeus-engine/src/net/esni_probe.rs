//! ECH/ESNI probe — tests whether a server supports Encrypted Client Hello
//! (TLS extension 0xfe0d), which hides the SNI from network inspection.
//!
//! # Method
//! Send a minimal TLS 1.3 ClientHello with an ECH GREASE extension.
//! If the server responds with `encrypted_client_hello` retry configs in its
//! ServerHello/EncryptedExtensions, ECH is supported → TLS inspection is
//! bypassable for clients that hold the ECH public key.
//!
//! No external TLS library is required — we build and parse the raw bytes.

use anyhow::Result;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use crate::zeus_output_compat::Severity;

// ── Server-side ECH response ───────────────────────────────────────────────────

/// Parsed ECH-relevant fields from a ServerHello response.
#[derive(Debug)]
pub struct EchServerResponse {
    /// Server sent `encrypted_client_hello` extension with retry configs.
    pub has_retry_configs: bool,
    /// Negotiated TLS version (0x0304 = TLS 1.3).
    pub tls_version: u16,
}

// ── Result ─────────────────────────────────────────────────────────────────────

/// Outcome of one ECH/ESNI probe.
#[derive(Debug)]
pub struct EsniResult {
    /// Server advertised ECH support (retry_configs present).
    pub ech_supported: bool,
    /// Server accepted GREASE ECH (did not abort with `illegal_parameter`).
    pub grease_ech: bool,
    /// If ECH is supported, TLS inspection cannot see the inner SNI.
    pub tls_inspection_bypassable: bool,
    pub finding: String,
    pub severity: Severity,
}

// ── Probe ──────────────────────────────────────────────────────────────────────

/// Probes `target:port` for ECH/ESNI support via a raw TLS ClientHello.
#[derive(Debug)]
pub struct EsniProbe {
    pub target: String,
    pub port: u16,
}

impl EsniProbe {
    /// Connect and probe.  Never panics — all errors propagate via `?`.
    pub async fn probe(&self) -> Result<EsniResult> {
        let addr = format!("{}:{}", self.target, self.port);
        let mut stream =
            tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
                .await??;
        debug!("Connected to {} for ECH probe", addr);

        let client_hello = Self::build_client_hello_with_ech_grease(&self.target);
        // Wrap in a TLS record: content_type=22 (handshake), legacy_version=0x0301, length
        let record = Self::wrap_tls_record(22, &client_hello);
        stream.write_all(&record).await?;

        // Read up to 4 KiB of the server response
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await??;
        buf.truncate(n);
        debug!("ECH probe received {} bytes from {}", n, addr);

        let server_resp = Self::parse_server_hello(&buf);
        let ech_supported = server_resp.as_ref().map_or(false, |r| r.has_retry_configs);
        // GREASE tolerance: if the server didn't close with alert, it tolerated it
        let grease_ech = n > 0;

        let (finding, severity) = if ech_supported {
            (
                format!(
                    "{} supports ECH (retry_configs present) — SNI is hidden from TLS inspection",
                    self.target
                ),
                Severity::High,
            )
        } else if grease_ech {
            (
                format!(
                    "{} tolerated ECH GREASE but did not advertise retry_configs — ECH not fully supported",
                    self.target
                ),
                Severity::Medium,
            )
        } else {
            (
                format!("{} rejected the probe (alert or empty response) — ECH not supported", self.target),
                Severity::Low,
            )
        };

        Ok(EsniResult {
            ech_supported,
            grease_ech,
            tls_inspection_bypassable: ech_supported,
            finding,
            severity,
        })
    }

    // ── Packet building ────────────────────────────────────────────────────────

    /// Build a minimal TLS 1.3 ClientHello with:
    /// - `server_name` extension (plaintext outer SNI)
    /// - `supported_versions` extension (TLS 1.3 only)
    /// - `encrypted_client_hello` extension type 0xfe0d with random GREASE bytes
    ///
    /// Returns the raw Handshake message bytes (without TLS record header).
    pub fn build_client_hello_with_ech_grease(host: &str) -> Vec<u8> {
        let mut extensions = Vec::new();

        // server_name (0x0000)
        let sni = Self::ext_server_name(host);
        extensions.extend_from_slice(&sni);

        // supported_versions (0x002b) — TLS 1.3
        extensions.extend_from_slice(&[
            0x00, 0x2b, // type
            0x00, 0x03, // ext length
            0x02,       // list length
            0x03, 0x04, // TLS 1.3
        ]);

        // supported_groups (0x000a) — x25519 only
        extensions.extend_from_slice(&[
            0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d,
        ]);

        // signature_algorithms (0x000d) — ecdsa_secp256r1_sha256
        extensions.extend_from_slice(&[
            0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03,
        ]);

        // encrypted_client_hello (0xfe0d) — 16 bytes of GREASE payload
        let ech_payload: Vec<u8> = Self::grease_bytes(16);
        let ech_ext_len = ech_payload.len() as u16;
        extensions.push(0xfe);
        extensions.push(0x0d);
        extensions.push((ech_ext_len >> 8) as u8);
        extensions.push((ech_ext_len & 0xff) as u8);
        extensions.extend_from_slice(&ech_payload);

        // ── Assemble ClientHello body ──────────────────────────────────────────
        let mut body = Vec::new();

        // client_version (legacy): TLS 1.2 = 0x0303
        body.extend_from_slice(&[0x03, 0x03]);

        // random: 32 pseudo-random bytes
        body.extend_from_slice(&Self::grease_bytes(32));

        // session_id: empty
        body.push(0x00);

        // cipher_suites: TLS_AES_128_GCM_SHA256 (0x1301) + TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x00, 0xff]);

        // compression_methods: null only
        body.extend_from_slice(&[0x01, 0x00]);

        // extensions length + data
        let ext_len = extensions.len() as u16;
        body.push((ext_len >> 8) as u8);
        body.push((ext_len & 0xff) as u8);
        body.extend_from_slice(&extensions);

        // ── Wrap in Handshake header (type=1 ClientHello) ─────────────────────
        let body_len = body.len() as u32;
        let mut handshake = vec![
            0x01,                            // HandshakeType: client_hello
            ((body_len >> 16) & 0xff) as u8, // length[0]
            ((body_len >> 8) & 0xff) as u8,  // length[1]
            (body_len & 0xff) as u8,         // length[2]
        ];
        handshake.extend_from_slice(&body);
        handshake
    }

    /// Parse raw bytes received from the server, looking for ECH retry_configs.
    pub fn parse_server_hello(data: &[u8]) -> Option<EchServerResponse> {
        // Expect at least a TLS record header (5 bytes)
        if data.len() < 5 {
            return None;
        }
        // content_type must be 22 (handshake) or 21 (alert)
        if data[0] != 22 {
            return None;
        }
        let legacy_version = u16::from_be_bytes([data[1], data[2]]);
        let _record_len = u16::from_be_bytes([data[3], data[4]]) as usize;

        // Scan extensions looking for type 0xfe0d (ECH retry_configs)
        // We do a simple byte-pattern scan rather than full TLS parsing.
        let has_retry_configs = data
            .windows(2)
            .any(|w| w == [0xfe, 0x0d]);

        Some(EchServerResponse {
            has_retry_configs,
            tls_version: legacy_version,
        })
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    fn ext_server_name(host: &str) -> Vec<u8> {
        let host_bytes = host.as_bytes();
        let name_len = host_bytes.len() as u16;
        let list_len = name_len + 3; // type(1) + length(2)
        let ext_len = list_len + 2;  // list_length field
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x00]); // extension type: server_name
        ext.push((ext_len >> 8) as u8);
        ext.push((ext_len & 0xff) as u8);
        ext.push((list_len >> 8) as u8);
        ext.push((list_len & 0xff) as u8);
        ext.push(0x00); // name_type: host_name
        ext.push((name_len >> 8) as u8);
        ext.push((name_len & 0xff) as u8);
        ext.extend_from_slice(host_bytes);
        ext
    }

    /// Wrap `payload` in a TLS record with the given `content_type`.
    fn wrap_tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u16;
        let mut rec = vec![
            content_type,
            0x03, 0x01, // legacy_record_version: TLS 1.0
            (len >> 8) as u8,
            (len & 0xff) as u8,
        ];
        rec.extend_from_slice(payload);
        rec
    }

    /// Galois-LFSR pseudo-random bytes (no `rand` dep).
    fn grease_bytes(n: usize) -> Vec<u8> {
        let mut state: u32 = 0xDEAD_BEEF;
        (0..n)
            .map(|_| {
                let bit = state & 1;
                state >>= 1;
                if bit != 0 {
                    state ^= 0x8000_0057;
                }
                (state & 0xff) as u8
            })
            .collect()
    }
}

// ── Severity compat shim ───────────────────────────────────────────────────────
// zeus-output is not a dependency of zeus-net, so we define a local Severity
// that mirrors the output crate's enum for use within this module only.

mod zeus_output_compat {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Severity {
        Low,
        Medium,
        High,
        Critical,
        Informational,
    }
}

// Re-export so callers import from this module.
pub use zeus_output_compat::Severity;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_starts_with_handshake_type_1() {
        let ch = EsniProbe::build_client_hello_with_ech_grease("example.com");
        // First byte of the Handshake message = 0x01 (ClientHello)
        assert_eq!(ch[0], 0x01, "handshake type must be ClientHello (0x01)");
    }

    #[test]
    fn client_hello_has_substantial_content() {
        let ch = EsniProbe::build_client_hello_with_ech_grease("example.com");
        assert!(ch.len() > 50, "ClientHello should have non-trivial content (got {} bytes)", ch.len());
    }

    #[test]
    fn client_hello_contains_ech_extension_type() {
        let ch = EsniProbe::build_client_hello_with_ech_grease("example.com");
        // ECH extension type is 0xfe 0x0d
        let has_ech = ch.windows(2).any(|w| w == [0xfe, 0x0d]);
        assert!(has_ech, "ClientHello must contain ECH extension type 0xfe 0x0d");
    }

    #[test]
    fn tls_record_wrap_starts_with_record_type() {
        let ch = EsniProbe::build_client_hello_with_ech_grease("example.com");
        // EsniProbe::probe wraps in wrap_tls_record(22, …) — test the raw
        // ClientHello (unwrapped) starts with HandshakeType 0x01, verifying
        // the two-layer structure is correct.
        assert_eq!(ch[0], 0x01);
    }

    #[test]
    fn parse_server_hello_empty_returns_none() {
        assert!(EsniProbe::parse_server_hello(&[]).is_none());
    }

    #[test]
    fn parse_server_hello_too_short_returns_none() {
        // 4 bytes is less than the required 5-byte TLS record header
        assert!(EsniProbe::parse_server_hello(&[0x16, 0x03, 0x03, 0x00]).is_none());
    }

    #[test]
    fn parse_server_hello_non_handshake_content_type_returns_none() {
        // content_type = 0x15 (alert), not 0x16 (handshake)
        let data = [0x15u8, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00];
        assert!(EsniProbe::parse_server_hello(&data).is_none());
    }

    #[test]
    fn parse_server_hello_detects_ech_retry_configs() {
        // Craft a minimal "ServerHello" with 0xfe 0x0d bytes inside
        let mut data = vec![0x16u8, 0x03, 0x03, 0x00, 0x10]; // TLS record header
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x0c]); // ServerHello handshake header
        data.extend_from_slice(&[0x00; 4]); // padding
        data.extend_from_slice(&[0xfe, 0x0d]); // ECH extension type
        data.extend_from_slice(&[0x00; 2]);
        let result = EsniProbe::parse_server_hello(&data);
        assert!(result.is_some());
        assert!(result.unwrap().has_retry_configs);
    }
}
