//! DNS tunneling detection probe — exposes whether SIEM/NIDS detects
//! high-entropy or iodine/dnscat-style DNS queries.
//!
//! # Strategy Pattern
//! Each encoding scheme implements [`DnsTunnelStrategy`].
//! [`DnsTunnelAuditor`] runs a chosen strategy and measures detectability.

use anyhow::Result;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::debug;

// ── Base32 alphabet (RFC 4648 §6, iodine-style) ───────────────────────────────
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buf = (buf << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
}

// ── Strategy trait ─────────────────────────────────────────────────────────────

/// Strategy pattern: each DNS tunneling encoding scheme.
pub trait DnsTunnelStrategy: Send + Sync {
    fn name(&self) -> &'static str;

    /// Encode `data` into DNS labels (each ≤63 chars), appended with the
    /// strategy's domain.  Returns the fully-qualified query names.
    fn encode_payload(&self, data: &[u8]) -> Vec<String>;

    /// Decode TXT record values back to raw bytes (best-effort).
    fn decode_response(&self, txt_records: &[String]) -> Vec<u8>;
}

// ── Iodine-style (Base32 subdomains) ──────────────────────────────────────────

/// Base32 encoding in DNS labels — mirrors the iodine DNS-tunnel client.
#[derive(Debug)]
pub struct Iodine32Strategy {
    pub domain: String,
}

impl DnsTunnelStrategy for Iodine32Strategy {
    fn name(&self) -> &'static str {
        "iodine-base32"
    }

    fn encode_payload(&self, data: &[u8]) -> Vec<String> {
        let encoded = base32_encode(data);
        // Split into 63-byte chunks (DNS label limit)
        encoded
            .as_bytes()
            .chunks(63)
            .map(|chunk| {
                // SAFETY: base32 output is ASCII
                let label = std::str::from_utf8(chunk).unwrap_or_default();
                format!("{}.{}", label, self.domain)
            })
            .collect()
    }

    fn decode_response(&self, txt_records: &[String]) -> Vec<u8> {
        // Iodine responses are also base32 — decode concatenated records
        let combined: String = txt_records.join("");
        let upper = combined.to_uppercase();
        let mut out = Vec::new();
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for ch in upper.chars() {
            let val = BASE32_ALPHABET.iter().position(|&b| b == ch as u8);
            if let Some(v) = val {
                buf = (buf << 5) | v as u32;
                bits += 5;
                if bits >= 8 {
                    bits -= 8;
                    out.push((buf >> bits) as u8);
                }
            }
        }
        out
    }
}

// ── dnscat-style (hex subdomains) ─────────────────────────────────────────────

/// Hex-encoded subdomains — mirrors dnscat2 client behaviour.
#[derive(Debug)]
pub struct DnsCatHexStrategy {
    pub domain: String,
}

impl DnsTunnelStrategy for DnsCatHexStrategy {
    fn name(&self) -> &'static str {
        "dnscat-hex"
    }

    fn encode_payload(&self, data: &[u8]) -> Vec<String> {
        // Hex is 2× the byte count; split into 63-char labels
        let hex = data
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        hex.as_bytes()
            .chunks(63)
            .map(|chunk| {
                let label = std::str::from_utf8(chunk).unwrap_or_default();
                format!("{}.{}", label, self.domain)
            })
            .collect()
    }

    fn decode_response(&self, txt_records: &[String]) -> Vec<u8> {
        let combined: String = txt_records.join("").to_lowercase();
        (0..combined.len())
            .step_by(2)
            .filter_map(|i| {
                combined.get(i..i + 2).and_then(|s| u8::from_str_radix(s, 16).ok())
            })
            .collect()
    }
}

// ── High-entropy random subdomains ────────────────────────────────────────────

/// Generates high-entropy subdomains that look like random noise.
#[derive(Debug)]
pub struct HighEntropyStrategy {
    pub domain: String,
    /// Length of each DNS label (≤63)
    pub label_len: usize,
}

impl DnsTunnelStrategy for HighEntropyStrategy {
    fn name(&self) -> &'static str {
        "high-entropy"
    }

    fn encode_payload(&self, data: &[u8]) -> Vec<String> {
        // Base32-encode and pad to `label_len` with pseudo-random noise so
        // every label has identical length — maximises entropy appearance.
        let encoded = base32_encode(data);
        let label_len = self.label_len.min(63);
        encoded
            .as_bytes()
            .chunks(label_len)
            .map(|chunk| {
                let mut label = std::str::from_utf8(chunk).unwrap_or_default().to_string();
                // Pad to fixed width with 'A' (still valid base32)
                while label.len() < label_len {
                    label.push('A');
                }
                format!("{}.{}", label, self.domain)
            })
            .collect()
    }

    fn decode_response(&self, txt_records: &[String]) -> Vec<u8> {
        // Reuse iodine-style decode — labels are base32
        let combined: String = txt_records.join("");
        Iodine32Strategy { domain: self.domain.clone() }.decode_response(&[combined])
    }
}

// ── Auditor ────────────────────────────────────────────────────────────────────

/// Runs one [`DnsTunnelStrategy`] and measures SIEM/NIDS detectability.
#[derive(Debug)]
pub struct DnsTunnelAuditor {
    pub strategy: Box<dyn DnsTunnelStrategy>,
    /// DNS resolver IP to send queries to (e.g. `"8.8.8.8:53"`)
    pub resolver: String,
    /// Number of DNS queries to send during the audit
    pub sample_count: u32,
}

/// Result of one DNS-tunnel audit run.
#[derive(Debug)]
pub struct DnsTunnelFinding {
    pub strategy: String,
    pub queries_sent: u32,
    /// Average Shannon entropy of the DNS labels sent
    pub avg_entropy: f32,
    /// Any NXDOMAIN / rate-limit indicators observed
    pub detected_indicators: Vec<String>,
    /// Heuristic: `true` if entropy or rate-limit signals suggest detection
    pub likely_detected: bool,
}

impl DnsTunnelAuditor {
    /// Build and return a complete audit result.
    pub async fn audit(&self) -> Result<DnsTunnelFinding> {
        // Sample payload — 32 bytes is enough to see encoding behaviour.
        let sample_payload: Vec<u8> = (0u8..32).collect();
        let queries = self.strategy.encode_payload(&sample_payload);

        let mut total_entropy = 0.0f32;
        let mut detected_indicators = Vec::new();
        let mut successful = 0u32;

        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(&self.resolver).await?;

        for (i, query) in queries.iter().enumerate() {
            if successful >= self.sample_count {
                break;
            }
            let packet = Self::build_dns_query(query, i as u16 + 1);
            match sock.send(&packet).await {
                Ok(_) => {
                    let mut buf = [0u8; 512];
                    let recv =
                        tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await;
                    match recv {
                        Ok(Ok(n)) => {
                            // Check RCODE in DNS header flags byte 3
                            if n >= 4 {
                                let rcode = buf[3] & 0x0f;
                                if rcode == 3 {
                                    // NXDOMAIN — often the C2 server is absent
                                    detected_indicators
                                        .push(format!("NXDOMAIN for query: {}", query));
                                }
                            }
                            total_entropy += Self::shannon_entropy(query);
                            successful += 1;
                        }
                        Ok(Err(e)) => {
                            detected_indicators.push(format!("recv error: {}", e));
                        }
                        Err(_) => {
                            detected_indicators.push(format!("timeout on query {}", query));
                        }
                    }
                }
                Err(e) => {
                    debug!("DNS send error: {}", e);
                }
            }
        }

        let avg_entropy = if successful > 0 {
            total_entropy / successful as f32
        } else {
            0.0
        };

        // Heuristic: entropy > 3.5 bits/char is suspicious; so is any rate limit.
        let likely_detected = avg_entropy > 3.5
            || detected_indicators
                .iter()
                .any(|s| s.contains("timeout") || s.contains("rate"));

        Ok(DnsTunnelFinding {
            strategy: self.strategy.name().to_string(),
            queries_sent: successful,
            avg_entropy,
            detected_indicators,
            likely_detected,
        })
    }

    /// Shannon entropy: H = -Σ p(c) · log₂(p(c)) over all distinct characters.
    pub fn shannon_entropy(data: &str) -> f32 {
        if data.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for b in data.bytes() {
            counts[b as usize] += 1;
        }
        let len = data.len() as f32;
        counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f32 / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Build a minimal DNS question packet for a QTYPE=A query.
    fn build_dns_query(fqdn: &str, tx_id: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Transaction ID
        pkt.push((tx_id >> 8) as u8);
        pkt.push((tx_id & 0xff) as u8);
        // Flags: standard query, recursion desired
        pkt.extend_from_slice(&[0x01, 0x00]);
        // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // QNAME
        for label in fqdn.split('.') {
            let bytes = label.as_bytes();
            pkt.push(bytes.len() as u8);
            pkt.extend_from_slice(bytes);
        }
        pkt.push(0x00); // root label
        // QTYPE=A (1), QCLASS=IN (1)
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        pkt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shannon_entropy_all_same_char_is_zero() {
        let entropy = DnsTunnelAuditor::shannon_entropy("aaaaaaaaaa");
        assert!(
            (entropy - 0.0_f32).abs() < 1e-6,
            "uniform distribution has 0 entropy, got {entropy}"
        );
    }

    #[test]
    fn shannon_entropy_balanced_two_char_is_one() {
        // "ab" repeated — p(a)=0.5, p(b)=0.5 → H = 1.0 bit
        let entropy = DnsTunnelAuditor::shannon_entropy("ababababab");
        assert!(
            (entropy - 1.0_f32).abs() < 1e-5,
            "balanced 2-char string should have entropy ~1.0, got {entropy}"
        );
    }

    #[test]
    fn iodine32_encode_empty_returns_empty_vec() {
        let s = Iodine32Strategy { domain: "example.com".into() };
        let result = s.encode_payload(&[]);
        assert!(result.is_empty(), "empty input must produce empty label list");
    }

    #[test]
    fn iodine32_encode_labels_at_most_63_plus_domain() {
        let s = Iodine32Strategy { domain: "t.com".into() };
        let data: Vec<u8> = (0u8..200).collect();
        for label_fqdn in s.encode_payload(&data) {
            // The label is everything before the first '.'
            let label = label_fqdn.split('.').next().unwrap_or("");
            assert!(label.len() <= 63, "label too long: {} chars in {}", label.len(), label_fqdn);
        }
    }

    #[test]
    fn high_entropy_strategy_produces_fixed_length_labels() {
        let s = HighEntropyStrategy { domain: "t.com".into(), label_len: 20 };
        let data = b"hello world";
        for fqdn in s.encode_payload(data) {
            let label = fqdn.split('.').next().unwrap_or("");
            assert_eq!(label.len(), 20, "expected fixed-length label, got {}", label.len());
        }
    }

    #[test]
    fn dnscat_hex_roundtrip() {
        let s = DnsCatHexStrategy { domain: "t.com".into() };
        let data = b"test data 123";
        let encoded = s.encode_payload(data);
        // Strip domain from each label to reconstruct hex
        let hex: String = encoded
            .iter()
            .map(|fqdn| fqdn.split('.').next().unwrap_or(""))
            .collect();
        let decoded = s.decode_response(&[hex]);
        assert_eq!(decoded, data, "hex roundtrip should recover original data");
    }
}
