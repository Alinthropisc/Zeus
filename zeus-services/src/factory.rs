//! Protocol Factory — OCP-compliant factory for [`ProtocolHandler`] instances.
//!
//! # Design patterns
//!
//! - **Factory** — [`ProtocolFactory`] creates and stores `Arc<dyn ProtocolHandler>`.
//! - **Strategy** — [`ProtocolHandler`] is the strategy trait; each protocol is a
//!   concrete strategy.
//! - **Adapter** — [`ProtocolHandlerAdapter`] bridges `zeus_core::Protocol` →
//!   [`ProtocolHandler`], so existing `Protocol` impls gain factory support for free.
//!
//! # SOLID compliance
//!
//! | Principle | How |
//! |-----------|-----|
//! | **SRP** | factory creates; [`crate::registry::ProtocolRegistry`] stores; [`crate::builder`] configures |
//! | **OCP** | new protocol = new `impl ProtocolHandler` + one `register` call; no changes to `ProtocolFactory` |
//! | **LSP** | every `ProtocolHandler` impl is fully substitutable behind `Arc<dyn ProtocolHandler>` |
//! | **ISP** | trait surface is minimal: `name` + `probe` |
//! | **DIP** | callers depend on `Arc<dyn ProtocolHandler>`, never on concrete handler types |

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

use crate::registry::ProbeOutcome;

// ──────────────────────────────────────────────────────────────────────────────
// ProbeResult — shared result vocabulary
// ──────────────────────────────────────────────────────────────────────────────

/// Canonical result type returned by [`ProtocolHandler::probe`].
///
/// Aliased to [`ProbeOutcome`] so callers share one result vocabulary across
/// both the registry and factory layers — no parallel type hierarchy.
pub type ProbeResult = ProbeOutcome;

// ──────────────────────────────────────────────────────────────────────────────
// ProtocolHandler trait  (Strategy + ISP)
// ──────────────────────────────────────────────────────────────────────────────

/// Minimal, object-safe interface for probing a single network protocol.
///
/// The interface is deliberately narrow (ISP): implementors only expose
/// `name` and `probe`. All protocol-specific logic stays inside the
/// concrete type and is invisible to callers.
///
/// # Object safety
///
/// The `async fn probe` is made object-safe by the `async_trait` attribute,
/// which desugars it to a `Pin<Box<dyn Future>>` return type at compile time.
#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    /// Stable ASCII key used as the factory lookup key (e.g. `"ftp"`, `"http"`).
    fn name(&self) -> &'static str;

    /// Attempt authentication and return a [`ProbeResult`].
    ///
    /// Returns `Ok(ProbeResult)` for all protocol-level outcomes (success,
    /// failure, timeout, rate-limit). `Err(ZeusError)` is reserved for
    /// unrecoverable internal errors that callers must not silently discard.
    async fn probe(&self, target: &Target, cred: &Credential) -> Result<ProbeResult, ZeusError>;
}

// ──────────────────────────────────────────────────────────────────────────────
// ProtocolHandlerAdapter  (Adapter pattern)
// ──────────────────────────────────────────────────────────────────────────────

/// Bridges any `Arc<dyn Protocol>` into the [`ProtocolHandler`] interface.
///
/// This keeps `ProtocolFactory` decoupled from concrete protocol types: each
/// built-in protocol only needs to implement `zeus_core::Protocol`; the adapter
/// does the translation automatically. External crates can still implement
/// `ProtocolHandler` directly for protocols that don\'t fit the `Protocol` model.
struct ProtocolHandlerAdapter {
    inner: Arc<dyn Protocol>,
    name: &'static str,
}

impl ProtocolHandlerAdapter {
    fn new(inner: Arc<dyn Protocol>, name: &'static str) -> Self {
        Self { inner, name }
    }
}

#[async_trait]
impl ProtocolHandler for ProtocolHandlerAdapter {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn probe(&self, target: &Target, cred: &Credential) -> Result<ProbeResult, ZeusError> {
        let config = AttackConfig::default();
        let outcome = match self.inner.authenticate(target, cred, &config).await {
            Ok(AttackResult::Success { credential, .. }) => ProbeResult::Success {
                message: format!(
                    "{}:{} authenticated on {}",
                    credential.username, credential.password, target.host
                ),
            },
            Ok(AttackResult::Failure) => ProbeResult::Failure {
                reason: "invalid credentials".into(),
            },
            Ok(AttackResult::Timeout) => ProbeResult::Timeout,
            Ok(AttackResult::RateLimit) => ProbeResult::Error {
                detail: "rate-limited by target".into(),
            },
            Ok(AttackResult::Error(msg)) => ProbeResult::Error { detail: msg },
            Err(ZeusError::Timeout(_)) => ProbeResult::Timeout,
            // Surface genuine transport/internal errors so callers can decide.
            Err(e) => return Err(e),
        };
        Ok(outcome)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ProtocolFactory
// ──────────────────────────────────────────────────────────────────────────────

/// Arc-based factory that maps protocol names to shared handler instances.
///
/// # Usage
///
/// ```rust,ignore
/// let mut factory = ProtocolFactory::with_defaults();
///
/// // Look up by name — returns None for unknown protocols, never panics.
/// if let Some(handler) = factory.create("ftp") {
///     let result = handler.probe(&target, &cred).await?;
/// }
///
/// // Register a custom override (OCP: ProtocolFactory itself is unchanged).
/// factory.register(Arc::new(MyCustomFtp));
/// ```
///
/// # Thread safety
///
/// `ProtocolFactory` is intended to be built once and then either placed behind
/// an `Arc<RwLock<ProtocolFactory>>` or stored in a long-lived component.
/// For concurrent registration use [`crate::registry::FactoryRegistry`] which
/// uses `DashMap` internally.
pub struct ProtocolFactory {
    handlers: HashMap<&'static str, Arc<dyn ProtocolHandler>>,
}

impl ProtocolFactory {
    /// Create an empty factory.
    ///
    /// Use [`Self::with_defaults`] to get a factory pre-loaded with all
    /// built-in protocol handlers.
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler.
    ///
    /// If a handler with the same name already exists it is replaced
    /// (last-write-wins). This allows callers to override built-in handlers
    /// with custom implementations without modifying `ProtocolFactory` (OCP).
    pub fn register(&mut self, handler: Arc<dyn ProtocolHandler>) {
        let name = handler.name();
        info!("ProtocolFactory: registered handler '{}'", name);
        self.handlers.insert(name, handler);
    }

    /// Look up a handler by protocol name.
    ///
    /// Returns `None` when the protocol has not been registered so callers can
    /// fail gracefully instead of panicking.
    pub fn create(&self, name: &str) -> Option<Arc<dyn ProtocolHandler>> {
        self.handlers.get(name).map(Arc::clone)
    }

    /// Sorted list of registered protocol names.
    pub fn protocols(&self) -> Vec<&'static str> {
        let mut v: Vec<_> = self.handlers.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// Returns `true` if no handlers have been registered.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Number of registered handlers.
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Build a factory pre-loaded with every built-in protocol handler.
    ///
    /// This is the primary constructor for production use. It registers all
    /// application-layer, network/system, and database protocol handlers by
    /// wrapping their `zeus_core::Protocol` impls in a
    /// [`ProtocolHandlerAdapter`].
    pub fn with_defaults() -> Self {
        use crate::database::{
            FirebirdProtocol, MemcachedProtocol, MongoDbProtocol, MssqlProtocol, MySqlProtocol,
            OracleProtocol, PostgresProtocol, RedisProtocol,
        };
        use crate::proto::{
            CvsProtocol, FtpProtocol, HttpFormProtocol, HttpProtocol, HttpProxyProtocol,
            ImapProtocol, IrcProtocol, LdapProtocol, NntpProtocol, Pop3Protocol, RdpProtocol,
            RexecProtocol, RshProtocol, RtspProtocol, SipProtocol, SmbProtocol, SmtpEnumProtocol,
            SmtpProtocol, SnmpProtocol, Socks5Protocol, SshProtocol, SvnProtocol, TelnetProtocol,
            VncProtocol, XmppProtocol,
        };

        let mut f = Self::new();

        // Convenience macro: wrap a Protocol impl in an adapter and register it.
        macro_rules! reg {
            ($name:literal, $ctor:expr) => {
                f.register(Arc::new(ProtocolHandlerAdapter::new(
                    Arc::new($ctor),
                    $name,
                )));
            };
        }

        // ── Application layer ─────────────────────────────────────────────────
        reg!("http", HttpProtocol::default());
        reg!("http-form", HttpFormProtocol::default());
        reg!("http-proxy", HttpProxyProtocol::default());
        reg!("ftp", FtpProtocol);
        reg!("smtp", SmtpProtocol);
        reg!("smtp-enum", SmtpEnumProtocol);
        reg!("pop3", Pop3Protocol);
        reg!("imap", ImapProtocol);
        reg!("nntp", NntpProtocol);
        reg!("telnet", TelnetProtocol);
        reg!("ssh", SshProtocol);
        reg!("irc", IrcProtocol);
        reg!("xmpp", XmppProtocol);
        reg!("sip", SipProtocol);
        reg!("rtsp", RtspProtocol::default());
        reg!("svn", SvnProtocol::default());
        reg!("cvs", CvsProtocol);
        reg!("socks5", Socks5Protocol);
        // ── Network / system ──────────────────────────────────────────────────
        reg!("ldap", LdapProtocol);
        reg!("snmp", SnmpProtocol);
        reg!("smb", SmbProtocol);
        reg!("rdp", RdpProtocol);
        reg!("vnc", VncProtocol);
        reg!("rsh", RshProtocol);
        reg!("rexec", RexecProtocol);
        // ── Databases ─────────────────────────────────────────────────────────
        reg!("mysql", MySqlProtocol);
        reg!("postgres", PostgresProtocol);
        reg!("redis", RedisProtocol);
        reg!("mssql", MssqlProtocol);
        reg!("mongodb", MongoDbProtocol);
        reg!("memcached", MemcachedProtocol);
        reg!("oracle", OracleProtocol);
        reg!("firebird", FirebirdProtocol);

        f
    }
}

impl Default for ProtocolFactory {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_factory_returns_none() {
        let f = ProtocolFactory::new();
        assert!(f.create("ftp").is_none());
        assert!(f.is_empty());
        assert_eq!(f.len(), 0);
    }

    #[test]
    fn default_is_empty() {
        let f = ProtocolFactory::default();
        assert!(f.is_empty());
    }

    #[test]
    fn with_defaults_registers_key_protocols() {
        let f = ProtocolFactory::with_defaults();
        for name in &[
            "ftp", "http", "ssh", "smtp", "mysql", "redis", "smb", "ldap", "rdp",
        ] {
            assert!(
                f.create(name).is_some(),
                "missing '{}' in ProtocolFactory::with_defaults()",
                name
            );
        }
    }

    #[test]
    fn protocols_sorted() {
        let f = ProtocolFactory::with_defaults();
        let p = f.protocols();
        let mut sorted = p.clone();
        sorted.sort_unstable();
        assert_eq!(p, sorted, "protocols() must return sorted names");
    }

    #[test]
    fn create_returns_shared_arc() {
        let f = ProtocolFactory::with_defaults();
        let h1 = f.create("ftp").unwrap();
        let h2 = f.create("ftp").unwrap();
        // Both arcs point to the same allocation.
        assert!(Arc::ptr_eq(&h1, &h2));
        assert_eq!(h1.name(), "ftp");
    }

    #[test]
    fn register_overwrites_builtin() {
        struct AlwaysTimeout;

        #[async_trait::async_trait]
        impl ProtocolHandler for AlwaysTimeout {
            fn name(&self) -> &'static str {
                "ftp"
            }
            async fn probe(&self, _: &Target, _: &Credential) -> Result<ProbeResult, ZeusError> {
                Ok(ProbeResult::Timeout)
            }
        }

        let mut f = ProtocolFactory::with_defaults();
        f.register(Arc::new(AlwaysTimeout));
        // The custom handler replaced the built-in.
        let h = f.create("ftp").unwrap();
        assert_eq!(h.name(), "ftp");
        // Protocol count unchanged — register replaces, not appends.
        let count_before = ProtocolFactory::with_defaults().len();
        assert_eq!(f.len(), count_before);
    }

    #[test]
    fn create_unknown_returns_none() {
        let f = ProtocolFactory::with_defaults();
        assert!(f.create("nonexistent-proto-xyz").is_none());
    }
}
