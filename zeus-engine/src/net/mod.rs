//! Async network primitives — TCP connections, TLS, rate limiting, HTTP, proxies,
//! DNS caching, and smart address resolution.

pub mod connection;
pub mod dns;
pub mod http_client;
pub mod probe_adapter;
pub mod proxy;
pub mod rate_limiter;
pub mod resolver;
pub mod tcp;

pub use connection::ConnectionPool;
pub use dns::{DnsCache, global_dns_cache};
pub use http_client::{HttpClient, HttpClientBuilder};
pub use proxy::{ProxyConfig, ProxyType};
pub use rate_limiter::{GlobalRateLimiter, RateLimiter};
pub use resolver::AddressResolver;
pub use tcp::TcpConnection;
