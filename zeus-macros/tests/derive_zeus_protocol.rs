//! Integration tests for `#[derive(ZeusProtocol)]`.
//!
//! Verifies that the derive macro generates the correct `protocol_name()`,
//! `default_port_number()`, and `uses_tls()` methods for a variety of
//! struct-name patterns.

use zeus_macros::ZeusProtocol;

// ── Basic single-segment name ─────────────────────────────────────────────────

#[derive(ZeusProtocol)]
struct FtpProtocol;

#[test]
fn ftp_protocol_name() {
    assert_eq!(FtpProtocol::protocol_name(), "ftp");
}

#[test]
fn ftp_default_port_is_zero() {
    assert_eq!(FtpProtocol::default_port_number(), 0u16);
}

#[test]
fn ftp_uses_tls_is_false() {
    assert!(!FtpProtocol::uses_tls());
}

// ── Multi-word camel-case name ────────────────────────────────────────────────

#[derive(ZeusProtocol)]
struct HttpFormProtocol;

#[test]
fn http_form_protocol_name() {
    assert_eq!(HttpFormProtocol::protocol_name(), "http_form");
}

// ── Another multi-word name ───────────────────────────────────────────────────

#[derive(ZeusProtocol)]
struct SmtpEnumProtocol;

#[test]
fn smtp_enum_protocol_name() {
    assert_eq!(SmtpEnumProtocol::protocol_name(), "smtp_enum");
}

// ── Digit boundary: digit followed by uppercase must NOT insert underscore ────

#[derive(ZeusProtocol)]
struct S7300Protocol;

#[test]
fn s7300_protocol_name() {
    // "S7300Protocol" → "s7300" (no underscore between digit and next char)
    assert_eq!(S7300Protocol::protocol_name(), "s7300");
}

// ── No "Protocol" suffix — whole name snake-cased ────────────────────────────

#[derive(ZeusProtocol)]
struct RdpSession;

#[test]
fn rdp_session_no_suffix_strip() {
    // Suffix is absent; the whole name becomes the snake_case identifier.
    assert_eq!(RdpSession::protocol_name(), "rdp_session");
}

// ── Three-segment name ────────────────────────────────────────────────────────

#[derive(ZeusProtocol)]
struct HttpProxyProtocol;

#[test]
fn http_proxy_protocol_name() {
    assert_eq!(HttpProxyProtocol::protocol_name(), "http_proxy");
}
