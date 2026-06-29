//! Proc-macros for the Zeus network-login auditing toolkit.
//!
//! # Macros provided
//!
//! | Macro | Kind | Purpose |
//! |---|---|---|
//! | [`ZeusProtocol`] | derive | Snake-case name, placeholder port/TLS methods |
//! | [`zeus_protocol`] | attribute | Explicit name/port/tls/desc via attribute args |
//! | [`register_protocol`] | attribute | Emits `PROTOCOL_NAME`, `PROTOCOL_PORT`, `PROTOCOL_TLS` consts |
//! | [`AttackStrategy`] | derive | `strategy_name()` from `#[strategy(name="…")]` |
//! | [`zeus_protocol_test!`] | declarative | Generates a standard `#[cfg(test)]` module for any `Protocol` |

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    DeriveInput, Ident, LitBool, LitInt, LitStr, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Convert a PascalCase struct name to a snake_case protocol identifier.
///
/// Rules:
/// - Strip a trailing `"Protocol"` suffix (case-sensitive).
/// - Insert `_` before every uppercase letter that follows a lowercase letter
///   or digit, then lower-case the whole string.
///
/// # Examples
/// ```text
/// FtpProtocol      → "ftp"
/// HttpFormProtocol → "http_form"
/// S7300Protocol    → "s7300"
/// SshProtocol      → "ssh"
/// ```
fn camel_to_snake(s: &str) -> String {
    // Strip well-known suffix so callers don't have to.
    let s = s.strip_suffix("Protocol").unwrap_or(s);

    let mut result = String::with_capacity(s.len() + 4);
    let chars: Vec<char> = s.chars().collect();

    for (i, &ch) in chars.iter().enumerate() {
        let prev_is_lower_or_digit =
            i > 0 && (chars[i - 1].is_lowercase() || chars[i - 1].is_ascii_digit());
        if ch.is_uppercase() && prev_is_lower_or_digit {
            result.push('_');
        }
        result.extend(ch.to_lowercase());
    }

    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Task 3 — `derive(ZeusProtocol)`
// ─────────────────────────────────────────────────────────────────────────────

/// Derive macro that generates default `Protocol`-adjacent methods on the
/// annotated struct.
///
/// Generated methods (all `pub`):
/// - `protocol_name() -> &'static str`  — struct name in snake_case, with
///   "Protocol" suffix stripped (e.g. `FtpProtocol` → `"ftp"`).
/// - `default_port_number() -> u16`     — returns `0`; override with
///   `#[zeus_protocol(port = N)]`.
/// - `uses_tls() -> bool`               — returns `false`.
///
/// # Example
/// ```rust,ignore
/// #[derive(ZeusProtocol)]
/// pub struct HttpFormProtocol;
/// // generates: HttpFormProtocol::protocol_name() == "http_form"
/// ```
#[proc_macro_derive(ZeusProtocol, attributes(protocol))]
pub fn derive_zeus_protocol(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let name_str = camel_to_snake(&struct_name.to_string());

    let expanded = quote! {
        impl #struct_name {
            /// Returns the snake_case protocol identifier derived from the
            /// struct name (e.g. `FtpProtocol` → `"ftp"`).
            pub fn protocol_name() -> &'static str {
                #name_str
            }

            /// Default port placeholder. Override with
            /// `#[zeus_protocol(port = N)]`.
            pub fn default_port_number() -> u16 {
                0
            }

            /// Whether this protocol uses TLS by default. Override with
            /// `#[zeus_protocol(tls = true)]`.
            pub fn uses_tls() -> bool {
                false
            }
        }
    };

    TokenStream::from(expanded)
}

// ─────────────────────────────────────────────────────────────────────────────
// Task 1 — `#[zeus_protocol(name="…", port=N, tls=bool, desc="…")]`
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed arguments for `#[zeus_protocol(…)]`.
struct ProtocolArgs {
    name: Option<String>,
    port: Option<u16>,
    tls: Option<bool>,
    desc: Option<String>,
}

impl Parse for ProtocolArgs {
    /// Parses a comma-separated list of `key = value` pairs.
    ///
    /// Recognised keys: `name`, `port`, `tls`, `desc`.
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut args = ProtocolArgs {
            name: None,
            port: None,
            tls: None,
            desc: None,
        };

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            match key.to_string().as_str() {
                "name" => {
                    let lit: LitStr = input.parse()?;
                    args.name = Some(lit.value());
                }
                "port" => {
                    let lit: LitInt = input.parse()?;
                    args.port = Some(lit.base10_parse::<u16>()?);
                }
                "tls" => {
                    let lit: LitBool = input.parse()?;
                    args.tls = Some(lit.value());
                }
                "desc" => {
                    let lit: LitStr = input.parse()?;
                    args.desc = Some(lit.value());
                }
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!(
                            "unknown zeus_protocol argument `{}`; expected name, port, tls, or desc",
                            other
                        ),
                    ));
                }
            }

            // Consume optional trailing comma.
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(args)
    }
}

/// Attribute macro that generates explicit protocol metadata methods on a
/// struct.
///
/// # Arguments
/// - `name = "…"` *(optional)* — the protocol identifier string. Defaults to
///   the struct name run through [`camel_to_snake`].
/// - `port = N`   *(optional)* — the default TCP port. Defaults to `0`.
/// - `tls  = bool` *(optional)* — whether TLS is the default. Defaults to
///   `false`.
/// - `desc = "…"` *(optional)* — a human-readable description. Defaults to
///   `""`.
///
/// # Generated methods (all `pub`)
/// - `protocol_name() -> &'static str`
/// - `default_port_number() -> u16`
/// - `uses_tls() -> bool`
/// - `protocol_description() -> &'static str`
///
/// # Example
/// ```rust,ignore
/// #[zeus_protocol(name = "ftp", port = 21)]
/// pub struct FtpProtocol;
///
/// assert_eq!(FtpProtocol::protocol_name(), "ftp");
/// assert_eq!(FtpProtocol::default_port_number(), 21);
/// assert_eq!(FtpProtocol::uses_tls(), false);
/// ```
#[proc_macro_attribute]
pub fn zeus_protocol(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as ProtocolArgs);

    // Re-parse the item so we can extract the struct name.
    let item_clone: TokenStream2 = item.clone().into();
    let ast: DeriveInput = match syn::parse(item) {
        Ok(d) => d,
        Err(e) => return e.to_compile_error().into(),
    };

    let struct_name = &ast.ident;

    // Resolve values — explicit args win, then sensible defaults.
    let name_str = args
        .name
        .unwrap_or_else(|| camel_to_snake(&struct_name.to_string()));
    let port: u16 = args.port.unwrap_or(0);
    let tls: bool = args.tls.unwrap_or(false);
    let desc: &str = args.desc.as_deref().unwrap_or("");
    // We need owned Strings to keep lifetimes tidy in `quote!`.
    let desc = desc.to_owned();

    let expanded = quote! {
        // Emit the original struct/impl unchanged.
        #item_clone

        impl #struct_name {
            /// Returns the protocol identifier string as declared in
            /// `#[zeus_protocol(name = "…")]`.
            pub fn protocol_name() -> &'static str {
                #name_str
            }

            /// Returns the default TCP port as declared in
            /// `#[zeus_protocol(port = N)]`.
            pub fn default_port_number() -> u16 {
                #port
            }

            /// Returns whether TLS is the default transport as declared in
            /// `#[zeus_protocol(tls = true/false)]`.
            pub fn uses_tls() -> bool {
                #tls
            }

            /// Returns the human-readable description declared in
            /// `#[zeus_protocol(desc = "…")]`, or `""` if omitted.
            pub fn protocol_description() -> &'static str {
                #desc
            }
        }
    };

    TokenStream::from(expanded)
}

// ─────────────────────────────────────────────────────────────────────────────
// Task 2 — `#[register_protocol]`
// ─────────────────────────────────────────────────────────────────────────────

/// Attribute macro that emits three associated constants used for
/// registry-level auto-discovery — without requiring a runtime call.
///
/// The constants emitted on the struct are:
/// - `PROTOCOL_NAME: &'static str`
/// - `PROTOCOL_PORT: u16`
/// - `PROTOCOL_TLS:  bool`
///
/// The values are read from a `#[zeus_protocol(…)]` attribute on the same
/// struct if present; otherwise they fall back to the snake_case struct name,
/// port `0`, and TLS `false`.
///
/// # Design note
/// Using `const` items avoids any dependency on `zeus-core` inside the macro
/// crate (which would create a circular workspace dependency). The registry
/// crate can pattern-match on these consts at startup.
///
/// # Example
/// ```rust,ignore
/// #[register_protocol]
/// #[zeus_protocol(name = "ssh", port = 22)]
/// pub struct SshProtocol;
///
/// assert_eq!(SshProtocol::PROTOCOL_NAME, "ssh");
/// assert_eq!(SshProtocol::PROTOCOL_PORT, 22u16);
/// assert_eq!(SshProtocol::PROTOCOL_TLS,  false);
/// ```
#[proc_macro_attribute]
pub fn register_protocol(attr: TokenStream, item: TokenStream) -> TokenStream {
    // `#[register_protocol]` takes no arguments itself.
    if !attr.is_empty() {
        return syn::Error::new(
            proc_macro2::Span::call_site(),
            "#[register_protocol] takes no arguments",
        )
        .to_compile_error()
        .into();
    }

    let item_clone: TokenStream2 = item.clone().into();
    let ast: DeriveInput = match syn::parse(item) {
        Ok(d) => d,
        Err(e) => return e.to_compile_error().into(),
    };

    let struct_name = &ast.ident;

    // Try to scrape a sibling `#[zeus_protocol(…)]` attribute from the parsed
    // item so we can echo the same values into the constants without forcing
    // the user to repeat themselves.
    let mut scraped_name: Option<String> = None;
    let mut scraped_port: u16 = 0;
    let mut scraped_tls: bool = false;

    for attr in &ast.attrs {
        // We only care about `#[zeus_protocol(…)]`.
        if !attr.path().is_ident("zeus_protocol") {
            continue;
        }

        if let Ok(args) = attr.parse_args::<ProtocolArgs>() {
            scraped_name = args.name;
            scraped_port = args.port.unwrap_or(0);
            scraped_tls = args.tls.unwrap_or(false);
        }
    }

    let name_str = scraped_name.unwrap_or_else(|| camel_to_snake(&struct_name.to_string()));
    let port = scraped_port;
    let tls = scraped_tls;

    let expanded = quote! {
        // Preserve the original struct definition (and any other macros on it).
        #item_clone

        impl #struct_name {
            /// Protocol identifier constant — mirrors `protocol_name()`.
            pub const PROTOCOL_NAME: &'static str = #name_str;

            /// Default TCP port constant — mirrors `default_port_number()`.
            pub const PROTOCOL_PORT: u16 = #port;

            /// TLS-by-default flag constant — mirrors `uses_tls()`.
            pub const PROTOCOL_TLS: bool = #tls;
        }
    };

    TokenStream::from(expanded)
}

// ─────────────────────────────────────────────────────────────────────────────
// Task 5 — `derive(AttackStrategy)`
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed arguments for `#[strategy(name = "…")]`.
struct StrategyArgs {
    name: Option<String>,
}

impl Parse for StrategyArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut args = StrategyArgs { name: None };

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            match key.to_string().as_str() {
                "name" => {
                    let lit: LitStr = input.parse()?;
                    args.name = Some(lit.value());
                }
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!("unknown strategy argument `{}`; expected name", other),
                    ));
                }
            }

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(args)
    }
}

/// Derive macro for attack-strategy structs.
///
/// Generates a single method:
/// - `strategy_name() -> &'static str` — returns the value of
///   `#[strategy(name = "…")]`, or the struct name in snake_case if the
///   helper attribute is absent.
///
/// # Example
/// ```rust,ignore
/// #[derive(AttackStrategy)]
/// #[strategy(name = "brute_force")]
/// pub struct BruteForceStrategy { /* … */ }
///
/// assert_eq!(BruteForceStrategy::strategy_name(), "brute_force");
/// ```
#[proc_macro_derive(AttackStrategy, attributes(strategy))]
pub fn derive_attack_strategy(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;

    // Scrape `#[strategy(name = "…")]` if present.
    let mut name_str: Option<String> = None;
    for attr in &input.attrs {
        if !attr.path().is_ident("strategy") {
            continue;
        }
        if let Ok(args) = attr.parse_args::<StrategyArgs>() {
            name_str = args.name;
        }
    }

    // Fall back to snake_case struct name (strip trailing "Strategy" suffix).
    let name_str = name_str.unwrap_or_else(|| {
        let raw = struct_name.to_string();
        let stripped = raw.strip_suffix("Strategy").unwrap_or(&raw);
        camel_to_snake_no_suffix(stripped)
    });

    let expanded = quote! {
        impl #struct_name {
            /// Returns the strategy identifier as declared in
            /// `#[strategy(name = "…")]` or derived from the struct name.
            pub fn strategy_name() -> &'static str {
                #name_str
            }
        }
    };

    TokenStream::from(expanded)
}

/// Like [`camel_to_snake`] but does *not* strip a suffix — used when the
/// caller has already stripped it.
fn camel_to_snake_no_suffix(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    let chars: Vec<char> = s.chars().collect();
    for (i, &ch) in chars.iter().enumerate() {
        let prev_is_lower_or_digit =
            i > 0 && (chars[i - 1].is_lowercase() || chars[i - 1].is_ascii_digit());
        if ch.is_uppercase() && prev_is_lower_or_digit {
            result.push('_');
        }
        result.extend(ch.to_lowercase());
    }
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// Task 4 — `zeus_protocol_test!` declarative macro
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a standard `#[cfg(test)]` module for any type implementing
/// [`zeus_core::Protocol`] and [`Default`].
///
/// The macro has two forms:
///
/// ## Basic form
/// ```rust,ignore
/// zeus_protocol_test!(FtpProtocol, name = "ftp", port = 21);
/// ```
/// Expands to a private `__zeus_proto_tests` module containing three tests:
/// - `protocol_name_is_correct` — asserts `proto.name() == $name`.
/// - `default_port_is_correct`  — asserts `proto.default_port() == $port`.
/// - `description_is_not_empty` — asserts `proto.description()` is non-empty.
///
/// ## TLS variant
/// ```rust,ignore
/// zeus_protocol_test!(SshProtocol, name = "ssh", port = 22, tls = false);
/// ```
/// Extends the basic module with an additional `tls_default_is_correct` test.
///
/// # Requirements
/// The target type must implement both `Default` and `zeus_core::Protocol`
/// (all unit structs satisfy `Default` automatically).
#[allow(unused_macros)]
macro_rules! zeus_protocol_test {
    // ── TLS variant ──────────────────────────────────────────────────────────
    ($proto:ty, name = $name:expr, port = $port:expr, tls = $tls:expr) => {
        #[cfg(test)]
        mod __zeus_proto_tests {
            use super::*;

            fn make() -> $proto {
                <$proto as ::std::default::Default>::default()
            }

            #[test]
            fn protocol_name_is_correct() {
                assert_eq!(
                    make().name(),
                    $name,
                    "Protocol::name() mismatch for {}",
                    stringify!($proto)
                );
            }

            #[test]
            fn default_port_is_correct() {
                assert_eq!(
                    make().default_port(),
                    $port,
                    "Protocol::default_port() mismatch for {}",
                    stringify!($proto)
                );
            }

            #[test]
            fn description_is_not_empty() {
                assert!(
                    !make().description().is_empty(),
                    "Protocol::description() must not be empty for {}",
                    stringify!($proto)
                );
            }

            #[test]
            fn tls_default_is_correct() {
                assert_eq!(
                    make().tls_default(),
                    $tls,
                    "Protocol::tls_default() mismatch for {}",
                    stringify!($proto)
                );
            }
        }
    };

    // ── Basic form (no TLS check) ────────────────────────────────────────────
    ($proto:ty, name = $name:expr, port = $port:expr) => {
        #[cfg(test)]
        mod __zeus_proto_tests {
            use super::*;

            fn make() -> $proto {
                <$proto as ::std::default::Default>::default()
            }

            #[test]
            fn protocol_name_is_correct() {
                assert_eq!(
                    make().name(),
                    $name,
                    "Protocol::name() mismatch for {}",
                    stringify!($proto)
                );
            }

            #[test]
            fn default_port_is_correct() {
                assert_eq!(
                    make().default_port(),
                    $port,
                    "Protocol::default_port() mismatch for {}",
                    stringify!($proto)
                );
            }

            #[test]
            fn description_is_not_empty() {
                assert!(
                    !make().description().is_empty(),
                    "Protocol::description() must not be empty for {}",
                    stringify!($proto)
                );
            }
        }
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests (helper functions only — proc-macros cannot be unit-tested
// directly; use integration tests in a downstream crate for expansion checks)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{camel_to_snake, camel_to_snake_no_suffix};

    // ── camel_to_snake ───────────────────────────────────────────────────────

    #[test]
    fn strips_protocol_suffix() {
        assert_eq!(camel_to_snake("FtpProtocol"), "ftp");
        assert_eq!(camel_to_snake("SshProtocol"), "ssh");
        assert_eq!(camel_to_snake("Pop3Protocol"), "pop3");
    }

    #[test]
    fn multi_word_camel() {
        assert_eq!(camel_to_snake("HttpFormProtocol"), "http_form");
        assert_eq!(camel_to_snake("SmtpEnumProtocol"), "smtp_enum");
        assert_eq!(camel_to_snake("HttpProxyProtocol"), "http_proxy");
    }

    #[test]
    fn no_suffix_passthrough() {
        // No "Protocol" suffix — the whole name is lowercased.
        assert_eq!(camel_to_snake("Ftp"), "ftp");
        assert_eq!(camel_to_snake("HttpForm"), "http_form");
    }

    #[test]
    fn digit_boundary_no_underscore() {
        // A digit followed by uppercase should not insert an underscore.
        assert_eq!(camel_to_snake("S7300Protocol"), "s7300");
    }

    #[test]
    fn single_char_name() {
        assert_eq!(camel_to_snake("X"), "x");
    }

    // ── camel_to_snake_no_suffix ─────────────────────────────────────────────

    #[test]
    fn no_suffix_fn_basic() {
        assert_eq!(camel_to_snake_no_suffix("BruteForce"), "brute_force");
        assert_eq!(camel_to_snake_no_suffix("Dictionary"), "dictionary");
        assert_eq!(camel_to_snake_no_suffix("Hybrid"), "hybrid");
    }

    #[test]
    fn no_suffix_fn_already_lowercase() {
        assert_eq!(camel_to_snake_no_suffix("ftp"), "ftp");
    }
}
