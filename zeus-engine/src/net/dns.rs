//! DNS resolver with in-memory TTL cache (Cache pattern).
//!
//! Use [`DnsCache`] directly for scoped caches, or [`global_dns_cache()`]
//! for a process-wide singleton with a 5-minute TTL.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::lookup_host;

// ──────────────────────────────────────────────────────────────────────────────
// Internal cache entry
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct CachedEntry {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
}

// ──────────────────────────────────────────────────────────────────────────────
// DnsCache
// ──────────────────────────────────────────────────────────────────────────────

/// Async DNS resolver with TTL-based in-memory caching.
///
/// Thread-safe via `Arc<RwLock<…>>` — cheap to clone.
#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<RwLock<HashMap<String, CachedEntry>>>,
    ttl: Duration,
}

impl fmt::Debug for DnsCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsCache").finish_non_exhaustive()
    }
}

impl DnsCache {
    /// Create a cache with a custom TTL per entry.
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    /// Create with a 5-minute TTL (common default for DNS).
    pub fn new_default() -> Self {
        Self::new(Duration::from_secs(300))
    }

    /// Resolve `host`, returning the cached result if it has not yet expired.
    ///
    /// On a cache miss or expiry the OS resolver is invoked and the result is
    /// stored for `ttl` seconds.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, std::io::Error> {
        // Fast path: read lock, check cache
        {
            let cache = self.cache.read();
            if let Some(entry) = cache.get(host) {
                if entry.expires_at > Instant::now() {
                    return Ok(entry.addrs.clone());
                }
            }
        }

        // Slow path: resolve, then write to cache
        let addrs: Vec<IpAddr> = lookup_host(format!("{}:0", host))
            .await?
            .map(|sa| sa.ip())
            .collect();

        {
            let mut cache = self.cache.write();
            cache.insert(
                host.to_string(),
                CachedEntry {
                    addrs: addrs.clone(),
                    expires_at: Instant::now() + self.ttl,
                },
            );
        }

        Ok(addrs)
    }

    /// Resolve to a [`SocketAddr`] with the given port (first address returned).
    pub async fn resolve_to_addr(
        &self,
        host: &str,
        port: u16,
    ) -> Result<SocketAddr, std::io::Error> {
        let addrs = self.resolve(host).await?;
        addrs
            .first()
            .map(|&ip| SocketAddr::new(ip, port))
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses resolved")
            })
    }

    /// Resolve, preferring IPv4 over IPv6 when both are available.
    pub async fn resolve_ipv4_preferred(
        &self,
        host: &str,
        port: u16,
    ) -> Result<SocketAddr, std::io::Error> {
        let addrs = self.resolve(host).await?;
        let ip = addrs
            .iter()
            .find(|ip| ip.is_ipv4())
            .copied()
            .or_else(|| addrs.first().copied())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses resolved")
            })?;
        Ok(SocketAddr::new(ip, port))
    }

    /// Remove a single cached entry, forcing a fresh lookup on the next call.
    pub fn invalidate(&self, host: &str) {
        self.cache.write().remove(host);
    }

    /// Remove all cached entries.
    pub fn clear(&self) {
        self.cache.write().clear();
    }

    /// Number of entries currently in the cache (including expired ones not yet
    /// evicted).
    pub fn len(&self) -> usize {
        self.cache.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new_default()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// DohResolver — DNS-over-HTTPS using Cloudflare's JSON API
// ──────────────────────────────────────────────────────────────────────────────

/// Resolves hostnames via DNS-over-HTTPS (DoH).
///
/// Queries `https://cloudflare-dns.com/dns-query` with
/// `Accept: application/dns-json` so that DNS traffic is indistinguishable
/// from normal HTTPS and is not visible to on-path observers.
///
/// Results are stored in the embedded [`DnsCache`] with the TTL returned
/// by the upstream resolver.
#[derive(Clone, Debug)]
pub struct DohResolver {
    /// Upstream DoH endpoint.
    pub endpoint: String,
    /// When `true`, prefer AAAA (IPv6) records over A (IPv4).
    pub prefer_ipv6: bool,
    cache: DnsCache,
    client: reqwest::Client,
}

impl DohResolver {
    const DEFAULT_ENDPOINT: &'static str = "https://cloudflare-dns.com/dns-query";

    /// Create a resolver using the Cloudflare DoH endpoint.
    pub fn new(prefer_ipv6: bool) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .user_agent("zeus-research/1.0")
            .build()?;
        Ok(Self {
            endpoint: Self::DEFAULT_ENDPOINT.to_string(),
            prefer_ipv6,
            cache: DnsCache::new_default(),
            client,
        })
    }

    /// Create a resolver with a custom DoH endpoint (useful for testing).
    pub fn with_endpoint(
        endpoint: impl Into<String>,
        prefer_ipv6: bool,
    ) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .user_agent("zeus-research/1.0")
            .build()?;
        Ok(Self {
            endpoint: endpoint.into(),
            prefer_ipv6,
            cache: DnsCache::new_default(),
            client,
        })
    }

    /// Resolve `host` to a list of IP addresses.
    ///
    /// Checks the local cache first; on a miss, queries the DoH endpoint for
    /// both A and (optionally) AAAA records.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DohError> {
        // Fast path: local cache.
        {
            let cache = self.cache.cache.read();
            if let Some(entry) = cache.get(host) {
                if entry.expires_at > Instant::now() {
                    return Ok(entry.addrs.clone());
                }
            }
        }

        // Query for A records; optionally AAAA.
        let mut addrs: Vec<IpAddr> = Vec::new();
        let mut min_ttl = u64::MAX;

        let record_types: &[&str] = if self.prefer_ipv6 {
            &["AAAA", "A"]
        } else {
            &["A", "AAAA"]
        };

        for rtype in record_types {
            if let Ok((ips, ttl)) = self.query_doh(host, rtype).await {
                addrs.extend(ips);
                min_ttl = min_ttl.min(ttl);
            }
        }

        if addrs.is_empty() {
            return Err(DohError::NoRecords(host.to_string()));
        }

        // Prefer IPv6 or IPv4 based on config.
        if self.prefer_ipv6 {
            addrs.sort_by_key(|ip| if ip.is_ipv6() { 0u8 } else { 1u8 });
        } else {
            addrs.sort_by_key(|ip| if ip.is_ipv4() { 0u8 } else { 1u8 });
        }

        // Populate cache with the minimum TTL returned.
        let ttl = Duration::from_secs(min_ttl.min(3600)); // cap at 1 hour
        {
            let mut cache = self.cache.cache.write();
            cache.insert(
                host.to_string(),
                CachedEntry {
                    addrs: addrs.clone(),
                    expires_at: Instant::now() + ttl,
                },
            );
        }

        Ok(addrs)
    }

    /// Resolve to a [`SocketAddr`] with the given port.
    pub async fn resolve_to_addr(&self, host: &str, port: u16) -> Result<SocketAddr, DohError> {
        let addrs = self.resolve(host).await?;
        addrs
            .first()
            .map(|&ip| SocketAddr::new(ip, port))
            .ok_or_else(|| DohError::NoRecords(host.to_string()))
    }

    /// Issue a single DoH JSON query for `host` with record type `qtype`.
    ///
    /// Returns `(ip_addresses, minimum_ttl_seconds)`.
    async fn query_doh(&self, host: &str, qtype: &str) -> Result<(Vec<IpAddr>, u64), DohError> {
        let url = format!("{}?name={}&type={}", self.endpoint, host, qtype);

        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .await
            .map_err(DohError::Http)?;

        if !resp.status().is_success() {
            return Err(DohError::HttpStatus(resp.status().as_u16()));
        }

        let json: serde_json::Value = resp.json().await.map_err(DohError::Http)?;

        let answers = match json.get("Answer").and_then(|a| a.as_array()) {
            Some(a) => a,
            None => return Ok((Vec::new(), 300)),
        };

        let mut ips = Vec::new();
        let mut min_ttl = u64::MAX;

        for answer in answers {
            let rtype = answer.get("type").and_then(|t| t.as_u64()).unwrap_or(0);
            // Type 1 = A, Type 28 = AAAA
            if rtype != 1 && rtype != 28 {
                continue;
            }

            if let Some(data) = answer.get("data").and_then(|d| d.as_str()) {
                if let Ok(ip) = data.parse::<IpAddr>() {
                    ips.push(ip);
                }
            }
            if let Some(ttl) = answer.get("TTL").and_then(|t| t.as_u64()) {
                min_ttl = min_ttl.min(ttl);
            }
        }

        let ttl = if min_ttl == u64::MAX { 300 } else { min_ttl };
        Ok((ips, ttl))
    }
}

/// Errors returned by [`DohResolver`].
#[derive(Debug, thiserror::Error)]
pub enum DohError {
    #[error("DoH HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("DoH returned HTTP {0}")]
    HttpStatus(u16),
    #[error("no DNS records found for '{0}'")]
    NoRecords(String),
}

// ──────────────────────────────────────────────────────────────────────────────
// Global singleton (OnceLock)
// ──────────────────────────────────────────────────────────────────────────────

static GLOBAL_DNS_CACHE: std::sync::OnceLock<DnsCache> = std::sync::OnceLock::new();

/// Process-wide shared [`DnsCache`] with a 5-minute TTL.
///
/// Initialised lazily on first access.
pub fn global_dns_cache() -> &'static DnsCache {
    GLOBAL_DNS_CACHE.get_or_init(DnsCache::new_default)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    /// Helper: insert a fake entry directly into the cache.
    fn insert_fake(cache: &DnsCache, host: &str, ip: IpAddr, ttl: Duration) {
        cache.cache.write().insert(
            host.to_string(),
            CachedEntry {
                addrs: vec![ip],
                expires_at: Instant::now() + ttl,
            },
        );
    }

    #[test]
    fn dns_cache_stores_result() {
        let cache = DnsCache::new(Duration::from_secs(60));
        assert!(cache.is_empty());
        insert_fake(
            &cache,
            "example.com",
            "93.184.216.34".parse().unwrap(),
            Duration::from_secs(60),
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn dns_cache_invalidate() {
        let cache = DnsCache::new(Duration::from_secs(60));
        insert_fake(
            &cache,
            "example.com",
            "93.184.216.34".parse().unwrap(),
            Duration::from_secs(60),
        );
        assert_eq!(cache.len(), 1);
        cache.invalidate("example.com");
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn dns_cache_clear() {
        let cache = DnsCache::new(Duration::from_secs(60));
        insert_fake(
            &cache,
            "a.com",
            "1.1.1.1".parse().unwrap(),
            Duration::from_secs(60),
        );
        insert_fake(
            &cache,
            "b.com",
            "8.8.8.8".parse().unwrap(),
            Duration::from_secs(60),
        );
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn dns_cache_ttl_expiry() {
        let cache = DnsCache::new(Duration::from_secs(60));
        // Insert with an already-expired TTL (negative offset via zero duration)
        cache.cache.write().insert(
            "expired.com".to_string(),
            CachedEntry {
                addrs: vec!["1.2.3.4".parse().unwrap()],
                // Expired in the past
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );
        // The entry is in the map but past its TTL
        let hit = {
            let c = cache.cache.read();
            c.get("expired.com")
                .map(|e| e.expires_at > Instant::now())
                .unwrap_or(false)
        };
        assert!(!hit, "entry should be considered expired");
    }

    #[test]
    fn global_dns_cache_is_same() {
        let a = global_dns_cache() as *const _;
        let b = global_dns_cache() as *const _;
        assert_eq!(a, b, "global_dns_cache() must return the same instance");
    }

    #[test]
    fn default_impl_uses_300s_ttl() {
        let cache = DnsCache::default();
        assert_eq!(cache.ttl, Duration::from_secs(300));
    }
}
