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

/// MD4 hash (RFC 1320) via RustCrypto.
/// Only for NTLM compatibility — intentionally weak, never use for new designs.
pub fn md4(data: &[u8]) -> [u8; 16] {
    <md4::Md4 as md4::Digest>::digest(data).into()
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
        assert_eq!(to_hex(&result), "9294727a3638bb1c13f48ef8158bfc9d");
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
        assert_eq!(to_hex(&md4(b"")), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn md4_abc() {
        // RFC 1320 test vector
        assert_eq!(to_hex(&md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
    }

    #[test]
    fn md4_known_bytes() {
        // MD4 of UTF-16LE bytes for "password" (lowercase)
        let bytes: &[u8] = &[0x70, 0x00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00,
                              0x77, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x64, 0x00];
        assert_eq!(to_hex(&md4(bytes)), "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn ntlm_utf16le_encoding() {
        let bytes: Vec<u8> = "password"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(
            bytes,
            vec![0x70, 0x00, 0x61, 0x00, 0x73, 0x00, 0x73, 0x00,
                 0x77, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x64, 0x00]
        );
    }

    #[test]
    fn ntlm_nt_hash_known() {
        // NT hash of "password" (lowercase) = 8846f7eaee8fb117ad06bdd830b7586c
        // (universally-known NTLM rainbow-table test vector)
        assert_eq!(to_hex(&ntlm_nt_hash("password")), "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn cram_md5_response_format() {
        let challenge = to_base64(b"test");
        let resp = cram_md5_response("user", "secret", &challenge).unwrap();
        assert!(resp.starts_with("user "));
        assert_eq!(resp.len(), "user ".len() + 32);
    }
}
