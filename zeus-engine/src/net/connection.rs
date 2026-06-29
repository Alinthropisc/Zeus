use anyhow::Result;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::net::TcpConnection;

// ──────────────────────────────────────────────────────────────────────────────
// ConnectionPool
// ──────────────────────────────────────────────────────────────────────────────

/// Semaphore-backed connection pool.
///
/// Limits the maximum number of concurrently open TCP connections to
/// `max_connections`. Callers block in `get()` until a permit is available.
#[derive(Clone)]
pub struct ConnectionPool {
    addr: SocketAddr,
    timeout: Duration,
    semaphore: Arc<Semaphore>,
    max_connections: usize,
}

impl ConnectionPool {
    pub fn new(addr: SocketAddr, timeout: Duration, max_connections: usize) -> Self {
        assert!(max_connections > 0, "max_connections must be > 0");
        Self {
            addr,
            timeout,
            semaphore: Arc::new(Semaphore::new(max_connections)),
            max_connections,
        }
    }

    /// Acquire a permit and open a fresh TCP connection.
    ///
    /// The returned `PooledConnection` holds the semaphore permit; dropping it
    /// releases the slot back to the pool.
    pub async fn get(&self) -> Result<PooledConnection> {
        let permit = Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .map_err(|e| anyhow::anyhow!("semaphore closed: {e}"))?;

        let inner = TcpConnection::connect(self.addr, self.timeout).await?;
        Ok(PooledConnection { inner, _permit: permit })
    }

    /// Number of currently available slots.
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    pub fn max_connections(&self) -> usize {
        self.max_connections
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// PooledConnection
// ──────────────────────────────────────────────────────────────────────────────

/// A `TcpConnection` bundled with a semaphore permit.
///
/// Dropping this value returns the permit to the pool automatically.
pub struct PooledConnection {
    inner: TcpConnection,
    /// Dropped last (after `inner`) when `PooledConnection` is dropped.
    _permit: OwnedSemaphorePermit,
}

impl Deref for PooledConnection {
    type Target = TcpConnection;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn dummy_addr() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999))
    }

    #[test]
    fn pool_initial_permits() {
        let pool = ConnectionPool::new(dummy_addr(), Duration::from_secs(5), 10);
        assert_eq!(pool.available_permits(), 10);
        assert_eq!(pool.max_connections(), 10);
    }

    #[tokio::test]
    async fn semaphore_limits_concurrency() {
        let pool = ConnectionPool::new(dummy_addr(), Duration::from_secs(1), 3);
        // Directly test the semaphore — don't actually connect.
        let sem = Arc::clone(&pool.semaphore);
        let p1 = sem.clone().acquire_owned().await.unwrap();
        let p2 = sem.clone().acquire_owned().await.unwrap();
        let p3 = sem.clone().acquire_owned().await.unwrap();
        assert_eq!(pool.available_permits(), 0);
        drop(p1);
        assert_eq!(pool.available_permits(), 1);
        drop(p2);
        drop(p3);
        assert_eq!(pool.available_permits(), 3);
    }

    #[test]
    #[should_panic(expected = "max_connections must be > 0")]
    fn zero_max_connections_panics() {
        ConnectionPool::new(dummy_addr(), Duration::from_secs(1), 0);
    }
}
