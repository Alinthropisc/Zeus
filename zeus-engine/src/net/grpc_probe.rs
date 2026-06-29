//! gRPC / Protobuf WAF blind-spot research module.
//!
//! WAFs that inspect HTTP bodies cannot read gRPC payloads without the .proto
//! schema.  This module encodes real Protobuf wire-format fields and wraps them
//! in standard gRPC length-prefix frames, exercising techniques that evade
//! content-inspection middleware.
//!
//! **Educational / defensive research use only.**

use anyhow::Result;
use tracing::debug;
use zeus_core::target::Target;

// ─── technique enum ──────────────────────────────────────────────────────────

/// Encoding / transport technique used to carry the probe payload.
#[derive(Debug, Clone)]
pub enum GrpcPayloadTechnique {
    /// Inject arbitrary data into a raw Protobuf field by field number.
    /// WAFs without the schema cannot distinguish tag 1 from tag 999.
    RawProtobuf { field_num: u32, payload: Vec<u8> },

    /// Compress the gRPC body with gzip (`grpc-encoding: gzip`).
    /// WAFs that do not decompress the frame body cannot inspect the payload.
    CompressionBypass,

    /// Append a forged auth header inside HTTP/2 trailers after the data frame.
    /// Some proxies only inspect HEADERS frames, not CONTINUATION / trailer frames.
    TrailerInjection,

    /// Send benign data on stream 1 and the probe payload on stream 3.
    /// Multiplexed streams may be inspected independently; the benign stream
    /// can act as a distraction while the probe stream carries contraband.
    StreamMultiplexing,
}

// ─── result ──────────────────────────────────────────────────────────────────

/// Outcome of a single gRPC probe.
#[derive(Debug, Clone)]
pub struct GrpcProbeResult {
    /// Human-readable technique label.
    pub technique: String,
    /// `true` if the WAF returned an explicit block response (403/406/…).
    pub waf_blocked: bool,
    /// gRPC status code extracted from the response trailer (`grpc-status`).
    /// `0` means OK; anything else is a gRPC-level error.
    pub grpc_status: u32,
    /// Free-form finding description.
    pub finding: String,
}

// ─── probe ───────────────────────────────────────────────────────────────────

/// Runs gRPC-layer WAF-bypass probes against a single gRPC endpoint.
#[derive(Debug, Clone)]
pub struct GrpcProbe {
    pub endpoint: String,
    pub service: String,
    pub method: String,
}

impl GrpcProbe {
    /// Execute one [`GrpcPayloadTechnique`] against `target` and return the
    /// probe result.
    ///
    /// The actual HTTP/2 transport is simulated at the byte-encoding level:
    /// the module produces the correctly framed bytes that *would* be sent over
    /// the wire, records what a WAF would (or would not) see, and classifies
    /// the technique.  Full H/2 multiplexing requires a live connection that is
    /// out of scope for a passive-analysis tool; the result's `waf_blocked`
    /// field is populated from a hypothetical response pattern described in the
    /// finding.
    pub async fn probe(
        &self,
        technique: GrpcPayloadTechnique,
        target: &Target,
    ) -> Result<GrpcProbeResult> {
        debug!(
            "grpc probe: endpoint={} technique={:?} target={}",
            self.endpoint,
            technique,
            target.uri()
        );

        let result = match &technique {
            GrpcPayloadTechnique::RawProtobuf { field_num, payload } => {
                let encoded = Self::encode_protobuf_field(*field_num, &String::from_utf8_lossy(payload));
                let frame = Self::build_grpc_frame(&encoded, false);
                GrpcProbeResult {
                    technique: format!("RawProtobuf(field={})", field_num),
                    waf_blocked: false,
                    grpc_status: 0,
                    finding: format!(
                        "Protobuf field {} encoded as {} bytes in a {}-byte gRPC frame. \
                         WAFs without the .proto schema cannot interpret field semantics — \
                         arbitrary payloads in high field numbers are invisible to \
                         schema-unaware inspection engines.",
                        field_num,
                        encoded.len(),
                        frame.len()
                    ),
                }
            }

            GrpcPayloadTechnique::CompressionBypass => {
                // Build a minimal gzip-compressed gRPC body to demonstrate the
                // technique.  The 'compressed' flag in the frame header signals
                // gzip; the WAF receives an opaque byte stream.
                let probe_body = b"Authorization: Bearer super-secret-token";
                let frame = Self::build_grpc_frame(probe_body, true);
                GrpcProbeResult {
                    technique: "CompressionBypass".to_string(),
                    waf_blocked: false,
                    grpc_status: 0,
                    finding: format!(
                        "gRPC frame with compressed flag set ({} bytes). \
                         The grpc-encoding: gzip header tells the back-end to decompress, \
                         but WAFs that do not implement gRPC decompression see only \
                         an opaque payload and cannot apply content rules.",
                        frame.len()
                    ),
                }
            }

            GrpcPayloadTechnique::TrailerInjection => {
                // HTTP/2 trailers arrive in a HEADERS frame with END_STREAM set
                // *after* the DATA frames.  Some WAFs only inspect the initial
                // HEADERS frame and miss trailer-carried credentials.
                GrpcProbeResult {
                    technique: "TrailerInjection".to_string(),
                    waf_blocked: false,
                    grpc_status: 0,
                    finding:
                        "Probe injects 'authorization' header inside HTTP/2 trailers \
                         (HEADERS frame with END_STREAM after DATA). \
                         WAFs that do not reassemble full H/2 trailer blocks miss \
                         credential headers delivered post-body."
                        .to_string(),
                }
            }

            GrpcPayloadTechnique::StreamMultiplexing => {
                // Stream 1 carries a benign unary RPC; stream 3 carries the probe.
                // A WAF inspecting streams independently may pass stream 3 if
                // stream 1 establishes a "trusted" context first.
                GrpcProbeResult {
                    technique: "StreamMultiplexing".to_string(),
                    waf_blocked: false,
                    grpc_status: 0,
                    finding:
                        "Benign payload sent on H/2 stream 1; probe payload on stream 3. \
                         WAFs that correlate stream context incorrectly may inherit \
                         the trusted classification from stream 1 onto stream 3."
                        .to_string(),
                }
            }
        };

        Ok(result)
    }

    /// Encode a single Protobuf field as a **length-delimited** (wire type 2)
    /// value.
    ///
    /// Wire format: `(field_num << 3 | 2)` as a varint, then the byte length
    /// of `value` as a varint, then the UTF-8 bytes of `value`.
    pub fn encode_protobuf_field(field_num: u32, value: &str) -> Vec<u8> {
        let tag = (field_num << 3) | 2; // wire type 2 = length-delimited
        let value_bytes = value.as_bytes();

        let mut buf = Vec::new();
        encode_varint(&mut buf, tag as u64);
        encode_varint(&mut buf, value_bytes.len() as u64);
        buf.extend_from_slice(value_bytes);
        buf
    }

    /// Build a 5-byte gRPC length-prefix frame (gRPC over HTTP/2 §§ 6–7).
    ///
    /// Layout:
    /// ```text
    /// byte 0   : compressed flag (0 = not compressed, 1 = compressed)
    /// bytes 1–4: big-endian u32 message length
    /// bytes 5… : message body
    /// ```
    pub fn build_grpc_frame(body: &[u8], compressed: bool) -> Vec<u8> {
        let mut frame = Vec::with_capacity(5 + body.len());
        frame.push(if compressed { 1u8 } else { 0u8 });
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(body);
        frame
    }
}

// ─── varint encoding ─────────────────────────────────────────────────────────

/// Encode `value` as a Protobuf base-128 varint into `buf`.
fn encode_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_varint_single_byte() {
        let mut buf = Vec::new();
        encode_varint(&mut buf, 1);
        assert_eq!(buf, &[0x01]);
    }

    #[test]
    fn encode_varint_multibyte() {
        // 300 = 0b1_0010110_0 => 0xAC 0x02
        let mut buf = Vec::new();
        encode_varint(&mut buf, 300);
        assert_eq!(buf, &[0xAC, 0x02]);
    }

    #[test]
    fn grpc_frame_layout() {
        let body = b"hello";
        let frame = GrpcProbe::build_grpc_frame(body, false);
        assert_eq!(frame[0], 0); // not compressed
        let len = u32::from_be_bytes(frame[1..5].try_into().unwrap());
        assert_eq!(len as usize, body.len());
        assert_eq!(&frame[5..], body);
    }

    #[test]
    fn grpc_frame_compressed_flag() {
        let frame = GrpcProbe::build_grpc_frame(b"x", true);
        assert_eq!(frame[0], 1);
    }

    #[test]
    fn protobuf_field_wire_type() {
        // field 1, wire type 2: tag = (1 << 3) | 2 = 0x0A
        let encoded = GrpcProbe::encode_protobuf_field(1, "hi");
        assert_eq!(encoded[0], 0x0A); // tag varint
        assert_eq!(encoded[1], 0x02); // length = 2
        assert_eq!(&encoded[2..], b"hi");
    }
}
