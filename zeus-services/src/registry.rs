//! Protocol Registry — Registry/Plugin pattern.
//!
//! Protocols register themselves; the engine looks them up by name.
//!
//! # Patterns implemented
//!
//! - **Registry** — `ProtocolRegistry` maps protocol names to `Arc<dyn Protocol>`.
//! - **Factory Method** — `HandlerFactory` fn-pointer; `FactoryRegistry` stores one per protocol.
//! - **Abstract Factory** — `AuthProbeFactory` and `DatabaseProbeFactory` group related factories.
//! - **Command** — `ProbeCommand` bundles (target, credential, handler) for deferred execution.
//! - **ProbeHandler** — adapter trait over `Protocol` that surfaces `ProbeOutcome`.

use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use tracing::info;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

// ──────────────────────────────────────────────────────────────────────────────
// ProtocolInfo
// ──────────────────────────────────────────────────────────────────────────────

/// Snapshot of static metadata about a registered protocol.
#[derive(Debug, Clone)]
pub struct ProtocolInfo {
    /// Protocol identifier (e.g. `"http"`, `"ftp"`).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Well-known default port.
    pub default_port: u16,
    /// Whether TLS is the default transport for this protocol.
    pub tls_default: bool,
}

// ──────────────────────────────────────────────────────────────────────────────
// ProtocolRegistry
// ──────────────────────────────────────────────────────────────────────────────

/// Thread-safe protocol registry.
pub struct ProtocolRegistry {
    protocols: DashMap<String, Arc<dyn Protocol>>,
}

impl ProtocolRegistry {
    pub fn new() -> Self {
        Self {
            protocols: DashMap::new(),
        }
    }

    pub fn register(&self, protocol: Arc<dyn Protocol>) {
        let name = protocol.name().to_owned();
        info!("Registered protocol: {}", name);
        self.protocols.insert(name, protocol);
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Protocol>> {
        self.protocols.get(name).map(|v| Arc::clone(&v))
    }

    pub fn list(&self) -> Vec<String> {
        let mut names: Vec<_> = self.protocols.iter().map(|e| e.key().clone()).collect();
        names.sort();
        names
    }

    pub fn is_empty(&self) -> bool {
        self.protocols.is_empty()
    }

    /// Return metadata for every registered protocol, sorted by name.
    pub fn list_protocols(&self) -> Vec<ProtocolInfo> {
        let mut infos: Vec<ProtocolInfo> = self
            .protocols
            .iter()
            .map(|entry| {
                let p = entry.value();
                ProtocolInfo {
                    name: p.name().to_owned(),
                    description: p.description().to_owned(),
                    default_port: p.default_port(),
                    tls_default: p.tls_default(),
                }
            })
            .collect();
        infos.sort_by(|a, b| a.name.cmp(&b.name));
        infos
    }

    /// Return the default port for `protocol`, or `None` if not registered.
    pub fn get_or_default_port(&self, protocol: &str) -> Option<u16> {
        self.protocols.get(protocol).map(|p| p.default_port())
    }

    /// Remove a protocol from the registry by name.
    ///
    /// Returns `true` if the protocol was registered and has been removed,
    /// `false` if it was not present (idempotent — never panics).
    pub fn unregister(&self, name: &str) -> bool {
        let removed = self.protocols.remove(name).is_some();
        if removed {
            tracing::info!("Unregistered protocol: {}", name);
        }
        removed
    }

    /// Sorted list of every registered protocol name.
    ///
    /// Semantic alias for [`Self::list`] using Registry-pattern vocabulary,
    /// consistent with `FactoryRegistry::protocols()` and `ProtocolFactory::protocols()`.
    pub fn list_all(&self) -> Vec<String> {
        self.list()
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a registry pre-loaded with all built-in protocols.
pub fn default_registry() -> ProtocolRegistry {
    use crate::database::{
        FirebirdProtocol, MemcachedProtocol, MongoDbProtocol, MssqlProtocol, MySqlProtocol,
        OracleProtocol, PostgresProtocol, RedisProtocol,
    };
    use crate::proto::{
        CvsProtocol, FtpProtocol, HttpFormProtocol, HttpProtocol, HttpProxyProtocol, ImapProtocol,
        IrcProtocol, LdapProtocol, NntpProtocol, Pop3Protocol, RdpProtocol, RexecProtocol,
        RshProtocol, RtspProtocol, SipProtocol, SmbProtocol, SmtpEnumProtocol, SmtpProtocol,
        SnmpProtocol, Socks5Protocol, SshProtocol, SvnProtocol, TelnetProtocol, VncProtocol,
        XmppProtocol,
    };

    let r = ProtocolRegistry::new();

    // Application layer protocols
    r.register(Arc::new(HttpProtocol::default()));
    r.register(Arc::new(HttpFormProtocol::default()));
    r.register(Arc::new(HttpProxyProtocol::default()));
    r.register(Arc::new(FtpProtocol));
    r.register(Arc::new(SmtpProtocol));
    r.register(Arc::new(SmtpEnumProtocol));
    r.register(Arc::new(Pop3Protocol));
    r.register(Arc::new(ImapProtocol));
    r.register(Arc::new(NntpProtocol));
    r.register(Arc::new(TelnetProtocol));
    r.register(Arc::new(SshProtocol));
    r.register(Arc::new(IrcProtocol));
    r.register(Arc::new(XmppProtocol));
    r.register(Arc::new(SipProtocol));
    r.register(Arc::new(RtspProtocol::default()));
    r.register(Arc::new(SvnProtocol::default()));
    r.register(Arc::new(CvsProtocol));
    r.register(Arc::new(Socks5Protocol));

    // Network / system protocols
    r.register(Arc::new(LdapProtocol));
    r.register(Arc::new(SnmpProtocol));
    r.register(Arc::new(SmbProtocol));
    r.register(Arc::new(RdpProtocol));
    r.register(Arc::new(VncProtocol));
    r.register(Arc::new(RshProtocol));
    r.register(Arc::new(RexecProtocol));

    // Database protocols
    r.register(Arc::new(MySqlProtocol));
    r.register(Arc::new(PostgresProtocol));
    r.register(Arc::new(RedisProtocol));
    r.register(Arc::new(MssqlProtocol));
    r.register(Arc::new(MongoDbProtocol));
    r.register(Arc::new(MemcachedProtocol));
    r.register(Arc::new(OracleProtocol));
    r.register(Arc::new(FirebirdProtocol));

    r
}

// ──────────────────────────────────────────────────────────────────────────────
// ProbeOutcome
// ──────────────────────────────────────────────────────────────────────────────

/// High-level result returned by a [`ProbeHandler`].
///
/// Richer than `AttackResult` — carries human-readable strings so callers
/// can log or display results without matching on internal protocol types.
#[derive(Debug, Clone, PartialEq)]
pub enum ProbeOutcome {
    /// Authentication succeeded.
    Success { message: String },
    /// Authentication failed (wrong credentials).
    Failure { reason: String },
    /// Protocol-level or network error.
    Error { detail: String },
    /// The operation timed out.
    Timeout,
}

impl ProbeOutcome {
    /// Returns `true` if the outcome is `Success`.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ProbeHandler  (Strategy / Adapter)
// ──────────────────────────────────────────────────────────────────────────────

/// Object-safe trait that adapts a `Protocol` to a simpler `ProbeOutcome` API.
///
/// Every concrete handler wraps an `Arc<dyn Protocol>` and delegates to
/// `Protocol::authenticate` using a default `AttackConfig`.
#[async_trait]
pub trait ProbeHandler: Send + Sync {
    fn protocol(&self) -> &'static str;
    fn default_port(&self) -> u16;
    fn description(&self) -> &'static str;
    async fn probe(&self, target: &Target, cred: &Credential) -> ProbeOutcome;
}

// ──────────────────────────────────────────────────────────────────────────────
// ProtocolProbeHandler  —  generic Protocol → ProbeHandler adapter
// ──────────────────────────────────────────────────────────────────────────────

struct ProtocolProbeHandler {
    inner: Arc<dyn Protocol>,
    name: &'static str,
    description: &'static str,
    port: u16,
}

impl ProtocolProbeHandler {
    fn new(
        inner: Arc<dyn Protocol>,
        name: &'static str,
        description: &'static str,
        port: u16,
    ) -> Self {
        Self {
            inner,
            name,
            description,
            port,
        }
    }
}

#[async_trait]
impl ProbeHandler for ProtocolProbeHandler {
    fn protocol(&self) -> &'static str {
        self.name
    }
    fn default_port(&self) -> u16 {
        self.port
    }
    fn description(&self) -> &'static str {
        self.description
    }

    async fn probe(&self, target: &Target, cred: &Credential) -> ProbeOutcome {
        let config = AttackConfig::default();
        match self.inner.authenticate(target, cred, &config).await {
            Ok(AttackResult::Success { credential, .. }) => ProbeOutcome::Success {
                message: format!(
                    "{}:{} authenticated on {}",
                    credential.username, credential.password, target.host
                ),
            },
            Ok(AttackResult::Failure) => ProbeOutcome::Failure {
                reason: "invalid credentials".into(),
            },
            Ok(AttackResult::Timeout) => ProbeOutcome::Timeout,
            Ok(AttackResult::RateLimit) => ProbeOutcome::Error {
                detail: "rate-limited by target".into(),
            },
            Ok(AttackResult::Error(msg)) => ProbeOutcome::Error { detail: msg },
            Err(ZeusError::Timeout(_)) => ProbeOutcome::Timeout,
            Err(e) => ProbeOutcome::Error {
                detail: e.to_string(),
            },
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Factory Method — HandlerFactory + FactoryRegistry
// ──────────────────────────────────────────────────────────────────────────────

/// A factory function that produces a boxed [`ProbeHandler`].
///
/// Plain `fn()` pointer — `Copy`, no heap allocation for the factory itself.
pub type HandlerFactory = fn() -> Box<dyn ProbeHandler>;

/// Factory-Method companion to [`ProtocolRegistry`].
///
/// Stores zero-cost factory functions instead of live instances.
/// Each `create` call produces an independent `Box<dyn ProbeHandler>`.
pub struct FactoryRegistry {
    factories: DashMap<&'static str, HandlerFactory>,
}

impl FactoryRegistry {
    pub fn new() -> Self {
        Self {
            factories: DashMap::new(),
        }
    }

    pub fn register(&self, name: &'static str, factory: HandlerFactory) {
        info!("Registered handler factory: {}", name);
        self.factories.insert(name, factory);
    }

    /// Invoke the factory for `protocol` and return a fresh handler,
    /// or `None` if the protocol is not registered.
    pub fn create(&self, protocol: &str) -> Option<Box<dyn ProbeHandler>> {
        self.factories.get(protocol).map(|f| f())
    }

    /// Sorted list of registered protocol names.
    pub fn protocols(&self) -> Vec<&'static str> {
        let mut v: Vec<_> = self.factories.iter().map(|e| *e.key()).collect();
        v.sort_unstable();
        v
    }

    /// Build a `FactoryRegistry` pre-loaded with every built-in protocol.
    pub fn with_builtins() -> Self {
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

        let r = Self::new();

        macro_rules! reg {
            ($name:literal, $desc:literal, $port:expr, $ctor:expr) => {
                r.register($name, || {
                    Box::new(ProtocolProbeHandler::new(
                        Arc::new($ctor),
                        $name,
                        $desc,
                        $port,
                    ))
                });
            };
        }

        // Application layer
        reg!(
            "http",
            "HTTP Basic/Form authentication",
            80,
            HttpProtocol::default()
        );
        reg!(
            "http-form",
            "HTTP HTML form brute-force",
            80,
            HttpFormProtocol::default()
        );
        reg!(
            "http-proxy",
            "HTTP Proxy authentication",
            3128,
            HttpProxyProtocol::default()
        );
        reg!(
            "ftp",
            "FTP username/password authentication",
            21,
            FtpProtocol
        );
        reg!("smtp", "SMTP AUTH LOGIN/PLAIN", 25, SmtpProtocol);
        reg!(
            "smtp-enum",
            "SMTP VRFY/EXPN user enumeration",
            25,
            SmtpEnumProtocol
        );
        reg!("pop3", "POP3 USER/PASS authentication", 110, Pop3Protocol);
        reg!("imap", "IMAP LOGIN authentication", 143, ImapProtocol);
        reg!("nntp", "NNTP AUTHINFO authentication", 119, NntpProtocol);
        reg!(
            "telnet",
            "Telnet login prompt brute-force",
            23,
            TelnetProtocol
        );
        reg!(
            "ssh",
            "SSH-2 password authentication via russh",
            22,
            SshProtocol
        );
        reg!("irc", "IRC PASS/NICK authentication", 6667, IrcProtocol);
        reg!("xmpp", "XMPP SASL PLAIN authentication", 5222, XmppProtocol);
        reg!(
            "sip",
            "SIP REGISTER Digest authentication",
            5060,
            SipProtocol
        );
        reg!(
            "rtsp",
            "RTSP Basic authentication",
            554,
            RtspProtocol::default()
        );
        reg!(
            "svn",
            "Subversion HTTP authentication",
            3690,
            SvnProtocol::default()
        );
        reg!("cvs", "CVS pserver authentication", 2401, CvsProtocol);
        reg!(
            "socks5",
            "SOCKS5 username/password authentication",
            1080,
            Socks5Protocol
        );
        // Network / system
        reg!("ldap", "LDAP simple bind authentication", 389, LdapProtocol);
        reg!(
            "snmp",
            "SNMPv1/v2c community string brute-force",
            161,
            SnmpProtocol
        );
        reg!("smb", "SMB2 NTLMv2 challenge-response", 445, SmbProtocol);
        reg!("rdp", "RDP NLA/Classic authentication", 3389, RdpProtocol);
        reg!("vnc", "VNC password authentication", 5900, VncProtocol);
        reg!("rsh", "RSH remote shell authentication", 514, RshProtocol);
        reg!(
            "rexec",
            "Rexec remote execution authentication",
            512,
            RexecProtocol
        );
        // Databases
        reg!(
            "mysql",
            "MySQL native password authentication",
            3306,
            MySqlProtocol
        );
        reg!(
            "postgres",
            "PostgreSQL MD5/SCRAM authentication",
            5432,
            PostgresProtocol
        );
        reg!("redis", "Redis AUTH command", 6379, RedisProtocol);
        reg!(
            "mssql",
            "Microsoft SQL Server authentication",
            1433,
            MssqlProtocol
        );
        reg!(
            "mongodb",
            "MongoDB SCRAM-SHA-1/256 authentication",
            27017,
            MongoDbProtocol
        );
        reg!(
            "memcached",
            "Memcached SASL authentication",
            11211,
            MemcachedProtocol
        );
        reg!("oracle", "Oracle TNS authentication", 1521, OracleProtocol);
        reg!(
            "firebird",
            "Firebird database authentication",
            3050,
            FirebirdProtocol
        );

        r
    }
}

impl Default for FactoryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Command pattern — ProbeCommand
// ──────────────────────────────────────────────────────────────────────────────

/// A **Command** that bundles (target, credential, handler) for deferred execution.
pub struct ProbeCommand {
    pub target: Target,
    pub credential: Credential,
    pub handler: Box<dyn ProbeHandler>,
}

impl ProbeCommand {
    pub fn new(target: Target, credential: Credential, handler: Box<dyn ProbeHandler>) -> Self {
        Self {
            target,
            credential,
            handler,
        }
    }

    pub async fn execute(&self) -> ProbeOutcome {
        self.handler.probe(&self.target, &self.credential).await
    }

    /// Build from a `FactoryRegistry` lookup; returns `None` if the protocol is unknown.
    pub fn from_registry(
        registry: &FactoryRegistry,
        target: Target,
        credential: Credential,
    ) -> Option<Self> {
        let handler = registry.create(&target.protocol)?;
        Some(Self::new(target, credential, handler))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Abstract Factory — AuthProbeFactory
// ──────────────────────────────────────────────────────────────────────────────

/// **Abstract Factory** for authentication-layer protocols.
pub struct AuthProbeFactory;

impl AuthProbeFactory {
    pub fn ssh() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::proto::SshProtocol),
            "ssh",
            "SSH-2 password authentication via russh",
            22,
        ))
    }
    pub fn ftp() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::proto::FtpProtocol),
            "ftp",
            "FTP username/password authentication",
            21,
        ))
    }
    pub fn http() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::proto::HttpProtocol::default()),
            "http",
            "HTTP Basic/Form authentication",
            80,
        ))
    }
    pub fn http_form() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::proto::HttpFormProtocol::default()),
            "http-form",
            "HTTP HTML form brute-force",
            80,
        ))
    }
    pub fn smtp() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::proto::SmtpProtocol),
            "smtp",
            "SMTP AUTH LOGIN/PLAIN",
            25,
        ))
    }
    pub fn pop3() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::proto::Pop3Protocol),
            "pop3",
            "POP3 USER/PASS authentication",
            110,
        ))
    }
    pub fn imap() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::proto::ImapProtocol),
            "imap",
            "IMAP LOGIN authentication",
            143,
        ))
    }
    pub fn telnet() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::proto::TelnetProtocol),
            "telnet",
            "Telnet login prompt brute-force",
            23,
        ))
    }
    pub fn smb() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::proto::SmbProtocol),
            "smb",
            "SMB2 NTLMv2 challenge-response",
            445,
        ))
    }
    pub fn ldap() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::proto::LdapProtocol),
            "ldap",
            "LDAP simple bind authentication",
            389,
        ))
    }
    pub fn rdp() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::proto::RdpProtocol),
            "rdp",
            "RDP NLA/Classic authentication",
            3389,
        ))
    }
    pub fn vnc() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::proto::VncProtocol),
            "vnc",
            "VNC password authentication",
            5900,
        ))
    }
    pub fn snmp() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::proto::SnmpProtocol),
            "snmp",
            "SNMPv1/v2c community string brute-force",
            161,
        ))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Abstract Factory — DatabaseProbeFactory
// ──────────────────────────────────────────────────────────────────────────────

/// **Abstract Factory** for database protocol handlers.
pub struct DatabaseProbeFactory;

impl DatabaseProbeFactory {
    pub fn mysql() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::database::MySqlProtocol),
            "mysql",
            "MySQL native password authentication",
            3306,
        ))
    }
    pub fn postgres() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::database::PostgresProtocol),
            "postgres",
            "PostgreSQL MD5/SCRAM authentication",
            5432,
        ))
    }
    pub fn redis() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::database::RedisProtocol),
            "redis",
            "Redis AUTH command",
            6379,
        ))
    }
    pub fn mssql() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::database::MssqlProtocol),
            "mssql",
            "Microsoft SQL Server authentication",
            1433,
        ))
    }
    pub fn mongodb() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::database::MongoDbProtocol),
            "mongodb",
            "MongoDB SCRAM-SHA-1/256 authentication",
            27017,
        ))
    }
    pub fn memcached() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::database::MemcachedProtocol),
            "memcached",
            "Memcached SASL authentication",
            11211,
        ))
    }
    pub fn oracle() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::database::OracleProtocol),
            "oracle",
            "Oracle TNS authentication",
            1521,
        ))
    }
    pub fn firebird() -> Box<dyn ProbeHandler> {
        Box::new(ProtocolProbeHandler::new(
            Arc::new(crate::database::FirebirdProtocol),
            "firebird",
            "Firebird database authentication",
            3050,
        ))
    }
}

// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use zeus_core::{AttackConfig, AttackResult, Credential, Target, ZeusError};

    struct DummyProto;

    #[async_trait]
    impl Protocol for DummyProto {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn default_port(&self) -> u16 {
            9999
        }
        async fn authenticate(
            &self,
            _: &Target,
            _: &Credential,
            _: &AttackConfig,
        ) -> Result<AttackResult, ZeusError> {
            Ok(AttackResult::Failure)
        }
    }

    #[test]
    fn register_and_retrieve() {
        let reg = ProtocolRegistry::new();
        reg.register(Arc::new(DummyProto));
        assert!(reg.get("dummy").is_some());
        assert!(reg.get("missing").is_none());
    }

    #[test]
    fn default_registry_populated() {
        let reg = default_registry();
        assert!(!reg.is_empty());
        // Check key protocols are registered
        assert!(reg.get("http").is_some());
        assert!(reg.get("ftp").is_some());
        assert!(reg.get("mysql").is_some());
        assert!(reg.get("redis").is_some());
        assert!(reg.get("pop3").is_some());
        assert!(reg.get("imap").is_some());
        assert!(reg.get("ldap").is_some());
        assert!(reg.get("snmp").is_some());
    }

    #[test]
    fn list_sorted() {
        let reg = default_registry();
        let list = reg.list();
        // Verify sorted
        let mut sorted = list.clone();
        sorted.sort();
        assert_eq!(list, sorted);
    }

    #[test]
    fn list_protocols_returns_info_sorted() {
        let reg = default_registry();
        let infos = reg.list_protocols();
        assert!(!infos.is_empty());
        // Verify sorted by name.
        let names: Vec<&str> = infos.iter().map(|i| i.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "list_protocols should be sorted by name");
    }

    #[test]
    fn list_protocols_contains_known_protocols() {
        let reg = default_registry();
        let infos = reg.list_protocols();
        let names: Vec<&str> = infos.iter().map(|i| i.name.as_str()).collect();
        for expected in &["http", "ftp", "mysql", "redis", "pop3", "imap"] {
            assert!(
                names.contains(expected),
                "expected '{}' in list_protocols",
                expected
            );
        }
    }

    #[test]
    fn list_protocols_fields_non_empty_port() {
        let reg = default_registry();
        for info in reg.list_protocols() {
            assert!(info.default_port > 0, "protocol '{}' has port 0", info.name);
        }
    }

    #[test]
    fn get_or_default_port_known() {
        let reg = ProtocolRegistry::new();
        reg.register(Arc::new(DummyProto));
        assert_eq!(reg.get_or_default_port("dummy"), Some(9999));
    }

    #[test]
    fn get_or_default_port_missing() {
        let reg = ProtocolRegistry::new();
        assert_eq!(reg.get_or_default_port("nonexistent"), None);
    }

    #[test]
    fn get_or_default_port_http() {
        let reg = default_registry();
        assert_eq!(reg.get_or_default_port("http"), Some(80));
    }

    // ── FactoryRegistry ───────────────────────────────────────────────────────

    #[test]
    fn factory_registry_register_and_create() {
        let reg = FactoryRegistry::new();
        reg.register("dummy", || {
            Box::new(ProtocolProbeHandler::new(
                Arc::new(DummyProto),
                "dummy",
                "A dummy protocol",
                9999,
            ))
        });
        let h = reg.create("dummy").expect("dummy should be registered");
        assert_eq!(h.protocol(), "dummy");
        assert_eq!(h.default_port(), 9999);
        assert_eq!(h.description(), "A dummy protocol");
    }

    #[test]
    fn factory_registry_missing_returns_none() {
        assert!(FactoryRegistry::new().create("nonexistent").is_none());
    }

    #[test]
    fn factory_registry_protocols_sorted() {
        let reg = FactoryRegistry::new();
        reg.register("zzz", || {
            Box::new(ProtocolProbeHandler::new(
                Arc::new(DummyProto),
                "zzz",
                "",
                1,
            ))
        });
        reg.register("aaa", || {
            Box::new(ProtocolProbeHandler::new(
                Arc::new(DummyProto),
                "aaa",
                "",
                2,
            ))
        });
        let p = reg.protocols();
        let mut sorted = p.clone();
        sorted.sort_unstable();
        assert_eq!(p, sorted);
    }

    #[test]
    fn factory_registry_with_builtins_populated() {
        let reg = FactoryRegistry::with_builtins();
        for name in &[
            "ssh", "ftp", "smtp", "http", "mysql", "redis", "smb", "ldap",
        ] {
            assert!(
                reg.create(name).is_some(),
                "missing '{}' in FactoryRegistry::with_builtins()",
                name
            );
        }
        let p = reg.protocols();
        let mut sorted = p.clone();
        sorted.sort_unstable();
        assert_eq!(p, sorted, "protocols() must be sorted");
    }

    #[test]
    fn factory_produces_independent_handlers() {
        let reg = FactoryRegistry::with_builtins();
        let h1 = reg.create("ssh").unwrap();
        let h2 = reg.create("ssh").unwrap();
        assert_eq!(h1.default_port(), 22);
        assert_eq!(h2.default_port(), 22);
    }

    // ── ProbeOutcome ──────────────────────────────────────────────────────────

    #[test]
    fn probe_outcome_is_success() {
        assert!(
            ProbeOutcome::Success {
                message: "ok".into()
            }
            .is_success()
        );
        assert!(
            !ProbeOutcome::Failure {
                reason: "bad".into()
            }
            .is_success()
        );
        assert!(!ProbeOutcome::Timeout.is_success());
        assert!(!ProbeOutcome::Error { detail: "e".into() }.is_success());
    }

    // ── ProbeCommand ──────────────────────────────────────────────────────────

    #[test]
    fn probe_command_from_registry_known() {
        let reg = FactoryRegistry::with_builtins();
        let cmd = ProbeCommand::from_registry(
            &reg,
            Target::new("127.0.0.1", 22, "ssh"),
            Credential::new("u", "p"),
        );
        assert!(cmd.is_some());
    }

    #[test]
    fn probe_command_from_registry_unknown() {
        let cmd = ProbeCommand::from_registry(
            &FactoryRegistry::new(),
            Target::new("127.0.0.1", 9999, "nonexistent"),
            Credential::new("u", "p"),
        );
        assert!(cmd.is_none());
    }

    // ── AuthProbeFactory ──────────────────────────────────────────────────────

    #[test]
    fn auth_probe_factory_protocols_and_ports() {
        let cases: &[(&str, u16, Box<dyn ProbeHandler>)] = &[
            ("ssh", 22, AuthProbeFactory::ssh()),
            ("ftp", 21, AuthProbeFactory::ftp()),
            ("http", 80, AuthProbeFactory::http()),
            ("smtp", 25, AuthProbeFactory::smtp()),
            ("pop3", 110, AuthProbeFactory::pop3()),
            ("imap", 143, AuthProbeFactory::imap()),
            ("telnet", 23, AuthProbeFactory::telnet()),
            ("smb", 445, AuthProbeFactory::smb()),
            ("ldap", 389, AuthProbeFactory::ldap()),
            ("rdp", 3389, AuthProbeFactory::rdp()),
            ("vnc", 5900, AuthProbeFactory::vnc()),
            ("snmp", 161, AuthProbeFactory::snmp()),
        ];
        for (name, port, h) in cases {
            assert_eq!(h.protocol(), *name);
            assert_eq!(h.default_port(), *port);
            assert!(
                !h.description().is_empty(),
                "'{}' has empty description",
                name
            );
        }
    }

    // ── DatabaseProbeFactory ──────────────────────────────────────────────────

    #[test]
    fn database_probe_factory_protocols_and_ports() {
        let cases: &[(&str, u16, Box<dyn ProbeHandler>)] = &[
            ("mysql", 3306, DatabaseProbeFactory::mysql()),
            ("postgres", 5432, DatabaseProbeFactory::postgres()),
            ("redis", 6379, DatabaseProbeFactory::redis()),
            ("mssql", 1433, DatabaseProbeFactory::mssql()),
            ("mongodb", 27017, DatabaseProbeFactory::mongodb()),
            ("memcached", 11211, DatabaseProbeFactory::memcached()),
            ("oracle", 1521, DatabaseProbeFactory::oracle()),
            ("firebird", 3050, DatabaseProbeFactory::firebird()),
        ];
        for (name, port, h) in cases {
            assert_eq!(h.protocol(), *name);
            assert_eq!(h.default_port(), *port);
            assert!(
                !h.description().is_empty(),
                "'{}' has empty description",
                name
            );
        }
    }
}
