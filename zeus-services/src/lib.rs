pub mod database;
pub mod net;
pub mod proto;
pub mod registry;
pub mod factory;
pub mod builder;

/// Resolve `host:port` to a [`std::net::SocketAddr`], returning a
/// [`zeus_core::ZeusError`] on failure.
pub fn resolve_addr(host: &str, port: u16) -> Result<std::net::SocketAddr, zeus_core::ZeusError> {
    use std::net::ToSocketAddrs;
    let addr_str = format!("{}:{}", host, port);
    addr_str
        .to_socket_addrs()
        .map_err(zeus_core::ZeusError::Network)?
        .next()
        .ok_or_else(|| zeus_core::ZeusError::Protocol(format!("DNS resolution failed for {host}")))
}
