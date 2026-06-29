//! Zeus Crypto — hashing, encoding, and auth primitives used by protocol handlers.
//!
//! Provides thin, tested wrappers over RustCrypto crates so protocol implementations
//! don't depend on the raw crypto crates directly.

use base64::{Engine as B64Engine, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
}

// ── Hashing ─────────────────────────────────────────────────────────────────

pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize().into()
}

// ── HMAC ────────────────────────────────────────────────────────────────────

pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <Hmac<Md5>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = <Hmac<Sha1>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

// ── Encoding ────────────────────────────────────────────────────────────────

pub fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

pub fn from_hex(s: &str) -> Result<Vec<u8>, CryptoError> {
    Ok(hex::decode(s)?)
}

pub fn to_base64(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn from_base64(s: &str) -> Result<Vec<u8>, CryptoError> {
    Ok(B64.decode(s)?)
}

// ── Auth protocol helpers ────────────────────────────────────────────────────

/// CRAM-MD5 response as used by IMAP/SMTP AUTH CRAM-MD5.
/// Returns `"<username> <hex(HMAC-MD5(password, challenge))"`.
pub fn cram_md5_response(username: &str, password: &str, challenge_b64: &str) -> Result<String, CryptoError> {
    let challenge = from_base64(challenge_b64)?;
    let digest = hmac_md5(password.as_bytes(), &challenge);
    Ok(format!("{} {}", username, to_hex(&digest)))
}

/// NTLM NT hash (MD4 of UTF-16LE password).
/// Used by SMB, MSSQL, and similar Windows protocols.
pub fn ntlm_nt_hash(password: &str) -> [u8; 16] {
    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    md4(&utf16)
}

/// Minimal MD4 implementation for NTLM (RFC 1320).
/// MD4 is intentionally weak — only use for NTLM compatibility, never for new designs.
pub fn md4(data: &[u8]) -> [u8; 16] {
    let f = |x: u32, y: u32, z: u32| (x & y) | (!x & z);
    let g = |x: u32, y: u32, z: u32| (x & y) | (x & z) | (y & z);
    let h = |x: u32, y: u32, z: u32| x ^ y ^ z;

    // Padding per RFC 1320
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let mut a: u32 = 0x6745_2301;
    let mut b: u32 = 0xEFCD_AB89;
    let mut c: u32 = 0x98BA_DCFE;
    let mut d: u32 = 0x1032_5476;

    for block in msg.chunks_exact(64) {
        let x: Vec<u32> = block.chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();

        let (aa, bb, cc, dd) = (a, b, c, d);

        // Round 1
        for &i in &[0usize, 4, 8, 12] {
            a = (a.wrapping_add(f(b,c,d)).wrapping_add(x[i  ])).rotate_left(3);
            d = (d.wrapping_add(f(a,b,c)).wrapping_add(x[i+1])).rotate_left(7);
            c = (c.wrapping_add(f(d,a,b)).wrapping_add(x[i+2])).rotate_left(11);
            b = (b.wrapping_add(f(c,d,a)).wrapping_add(x[i+3])).rotate_left(19);
        }
        // Round 2
        for &i in &[0usize, 1, 2, 3] {
            a = (a.wrapping_add(g(b,c,d)).wrapping_add(x[i  ]).wrapping_add(0x5A82_7999)).rotate_left(3);
            d = (d.wrapping_add(g(a,b,c)).wrapping_add(x[i+4]).wrapping_add(0x5A82_7999)).rotate_left(5);
            c = (c.wrapping_add(g(d,a,b)).wrapping_add(x[i+8]).wrapping_add(0x5A82_7999)).rotate_left(9);
            b = (b.wrapping_add(g(c,d,a)).wrapping_add(x[i+12]).wrapping_add(0x5A82_7999)).rotate_left(13);
        }
        // Round 3
        for &i in &[0usize, 2, 1, 3] {
            a = (a.wrapping_add(h(b,c,d)).wrapping_add(x[i  ]).wrapping_add(0x6ED9_EBA1)).rotate_left(3);
            d = (d.wrapping_add(h(a,b,c)).wrapping_add(x[i+8]).wrapping_add(0x6ED9_EBA1)).rotate_left(9);
            c = (c.wrapping_add(h(d,a,b)).wrapping_add(x[i+4]).wrapping_add(0x6ED9_EBA1)).rotate_left(11);
            b = (b.wrapping_add(h(c,d,a)).wrapping_add(x[i+12]).wrapping_add(0x6ED9_EBA1)).rotate_left(15);
        }

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a.to_le_bytes());
    out[4..8].copy_from_slice(&b.to_le_bytes());
    out[8..12].copy_from_slice(&c.to_le_bytes());
    out[12..16].copy_from_slice(&d.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_empty() {
        assert_eq!(to_hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn md5_abc() {
        assert_eq!(to_hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn sha1_abc() {
        assert_eq!(to_hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn sha256_empty() {
        assert_eq!(
            to_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hmac_md5_rfc2202_v1() {
        // RFC 2202 test vector #1: key=0x0b*16, data="Hi There"
        let key = vec![0x0bu8; 16];
        let result = hmac_md5(&key, b"Hi There");
        assert_eq!(to_hex(&result), "9294727a3811f1f5e8b0d9d5be6d3c7b");
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"hello zeus";
        let enc = to_base64(data);
        let dec = from_base64(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn hex_roundtrip() {
        let data = b"\xde\xad\xbe\xef";
        assert_eq!(to_hex(data), "deadbeef");
        assert_eq!(from_hex("deadbeef").unwrap(), data);
    }

    #[test]
    fn md4_empty() {
        // MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
        assert_eq!(to_hex(&md4(b"")), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn ntlm_nt_hash_known() {
        // NT hash of "Password" = 8846f7eaee8fb117ad06bdd830b7586c
        assert_eq!(to_hex(&ntlm_nt_hash("Password")), "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn cram_md5_response_format() {
        let challenge = to_base64(b"test");
        let resp = cram_md5_response("user", "secret", &challenge).unwrap();
        assert!(resp.starts_with("user "));
        assert_eq!(resp.len(), "user ".len() + 32); // 32 hex chars
    }
}
