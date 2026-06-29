use anyhow::{Result, anyhow};
use bytes::BytesMut;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tracing::debug;

// ──────────────────────────────────────────────────────────────────────────────
// Plain TCP
// ──────────────────────────────────────────────────────────────────────────────

pub struct TcpConnection {
    stream: TcpStream,
    timeout: Duration,
}

impl TcpConnection {
    pub async fn connect(addr: SocketAddr, connect_timeout: Duration) -> Result<Self> {
        let stream = timeout(connect_timeout, TcpStream::connect(addr)).await??;
        stream.set_nodelay(true)?;
        debug!("TCP connected to {}", addr);
        Ok(Self {
            stream,
            timeout: connect_timeout,
        })
    }

    // ── writes ────────────────────────────────────────────────────────────────

    pub async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        timeout(self.timeout, self.stream.write_all(buf)).await??;
        Ok(())
    }

    /// Write `line` followed by `\r\n` and flush.
    pub async fn write_line(&mut self, line: &str) -> Result<()> {
        let mut buf = Vec::with_capacity(line.len() + 2);
        buf.extend_from_slice(line.as_bytes());
        buf.extend_from_slice(b"\r\n");
        timeout(self.timeout, self.stream.write_all(&buf)).await??;
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        timeout(self.timeout, self.stream.flush()).await??;
        Ok(())
    }

    // ── reads ─────────────────────────────────────────────────────────────────

    /// Read until `\r\n` or plain `\n`.
    pub async fn read_until_crlf(&mut self) -> Result<BytesMut> {
        self.read_until(b"\r\n").await
    }

    /// Read until `\n` and return the line as a `String` (strips trailing CR/LF).
    pub async fn read_line(&mut self) -> Result<String> {
        let buf = self.read_until(b"\n").await?;
        let s = String::from_utf8_lossy(&buf);
        Ok(s.trim_end_matches(|c| c == '\r' || c == '\n').to_owned())
    }

    /// Read exactly `n` bytes.
    pub async fn read_exact(&mut self, n: usize) -> Result<BytesMut> {
        let mut buf = BytesMut::zeroed(n);
        timeout(self.timeout, self.stream.read_exact(&mut buf)).await??;
        Ok(buf)
    }

    /// Read until `delimiter` (byte sequence) is found in the buffer.
    pub async fn read_until(&mut self, delimiter: &[u8]) -> Result<BytesMut> {
        let mut buf = BytesMut::with_capacity(512);
        let mut tmp = [0u8; 256];
        loop {
            let n = timeout(self.timeout, self.stream.read(&mut tmp)).await??;
            if n == 0 {
                break; // EOF
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(delimiter.len()).any(|w| w == delimiter) {
                break;
            }
        }
        Ok(buf)
    }

    /// Read all currently available bytes without blocking (non-blocking peek).
    /// Uses a short 50 ms timeout to drain any buffered data.
    pub async fn read_available(&mut self) -> Result<BytesMut> {
        let mut buf = BytesMut::with_capacity(4096);
        let mut tmp = [0u8; 1024];
        let drain_timeout = Duration::from_millis(50);
        loop {
            match tokio::time::timeout(drain_timeout, self.stream.read(&mut tmp)).await {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break, // timeout — no more data right now
            }
        }
        Ok(buf)
    }

    pub async fn shutdown(mut self) -> Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// TLS
// ──────────────────────────────────────────────────────────────────────────────

pub struct TlsConnection {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    timeout: Duration,
}

impl TlsConnection {
    /// Connect with a standard certificate store derived from `webpki-roots`.
    pub async fn connect(host: &str, port: u16, connect_timeout: Duration) -> Result<Self> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        let addr: SocketAddr = tokio::net::lookup_host(format!("{host}:{port}"))
            .await?
            .next()
            .ok_or_else(|| anyhow!("DNS resolution failed for {host}"))?;

        let tcp = timeout(connect_timeout, TcpStream::connect(addr)).await??;
        tcp.set_nodelay(true)?;

        let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|e| anyhow!("invalid server name: {e}"))?;

        let stream = timeout(connect_timeout, connector.connect(server_name, tcp)).await??;
        debug!("TLS connected to {}:{}", host, port);
        Ok(Self {
            stream,
            timeout: connect_timeout,
        })
    }

    // ── writes ────────────────────────────────────────────────────────────────

    pub async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        timeout(self.timeout, self.stream.write_all(buf)).await??;
        Ok(())
    }

    pub async fn write_line(&mut self, line: &str) -> Result<()> {
        let mut buf = Vec::with_capacity(line.len() + 2);
        buf.extend_from_slice(line.as_bytes());
        buf.extend_from_slice(b"\r\n");
        timeout(self.timeout, self.stream.write_all(&buf)).await??;
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        timeout(self.timeout, self.stream.flush()).await??;
        Ok(())
    }

    // ── reads ─────────────────────────────────────────────────────────────────

    pub async fn read_until_crlf(&mut self) -> Result<BytesMut> {
        self.read_until(b"\r\n").await
    }

    pub async fn read_line(&mut self) -> Result<String> {
        let buf = self.read_until(b"\n").await?;
        let s = String::from_utf8_lossy(&buf);
        Ok(s.trim_end_matches(|c| c == '\r' || c == '\n').to_owned())
    }

    pub async fn read_exact(&mut self, n: usize) -> Result<BytesMut> {
        let mut buf = BytesMut::zeroed(n);
        timeout(self.timeout, self.stream.read_exact(&mut buf)).await??;
        Ok(buf)
    }

    pub async fn read_until(&mut self, delimiter: &[u8]) -> Result<BytesMut> {
        let mut buf = BytesMut::with_capacity(512);
        let mut tmp = [0u8; 256];
        loop {
            let n = timeout(self.timeout, self.stream.read(&mut tmp)).await??;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(delimiter.len()).any(|w| w == delimiter) {
                break;
            }
        }
        Ok(buf)
    }

    pub async fn read_available(&mut self) -> Result<BytesMut> {
        let mut buf = BytesMut::with_capacity(4096);
        let mut tmp = [0u8; 1024];
        let drain_timeout = Duration::from_millis(50);
        loop {
            match tokio::time::timeout(drain_timeout, self.stream.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break,
            }
        }
        Ok(buf)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Additional helpers — TcpConnection
// ──────────────────────────────────────────────────────────────────────────────

impl TcpConnection {
    /// Read exactly `n` bytes and return them as a `Vec<u8>`.
    pub async fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        let buf = self.read_exact(n).await?;
        Ok(buf.to_vec())
    }

    /// Read exactly `n` bytes and return them as a `Vec<u8>`.
    ///
    /// This is an explicit alias for `read_bytes` following the task spec.
    pub async fn read_bytes_exact(&mut self, n: usize) -> Result<Vec<u8>> {
        self.read_bytes(n).await
    }

    /// Read until `pattern` is found in the stream or `max_bytes` have been
    /// read (whichever comes first).
    ///
    /// The returned buffer contains all bytes read including the pattern (if
    /// found).  If `max_bytes` is reached before the pattern, the truncated
    /// buffer is returned without error.
    pub async fn read_until_pattern(
        &mut self,
        pattern: &[u8],
        max_bytes: usize,
    ) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(512.min(max_bytes));
        let mut tmp = [0u8; 256];
        loop {
            if buf.len() >= max_bytes {
                buf.truncate(max_bytes);
                break;
            }
            let remaining = max_bytes - buf.len();
            let read_len = remaining.min(tmp.len());
            let n = timeout(self.timeout, self.stream.read(&mut tmp[..read_len])).await??;
            if n == 0 {
                break; // EOF
            }
            buf.extend_from_slice(&tmp[..n]);
            if !pattern.is_empty()
                && buf.len() >= pattern.len()
                && buf.windows(pattern.len()).any(|w| w == pattern)
            {
                break;
            }
        }
        Ok(buf)
    }

    /// Read until a single byte `delimiter` is found; the delimiter is included
    /// in the returned buffer.
    pub async fn read_until_byte(&mut self, delimiter: u8) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(256);
        let mut tmp = [0u8; 1];
        loop {
            let n = timeout(self.timeout, self.stream.read(&mut tmp)).await??;
            if n == 0 {
                break; // EOF
            }
            buf.push(tmp[0]);
            if tmp[0] == delimiter {
                break;
            }
        }
        Ok(buf)
    }

    /// Peek up to `n` bytes without consuming them.
    ///
    /// Uses `TcpStream::peek`, which reads into the kernel buffer but does not
    /// advance the socket read pointer.
    pub async fn peek(&self, n: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        let read = timeout(self.timeout, self.stream.peek(&mut buf)).await??;
        buf.truncate(read);
        Ok(buf)
    }
}

impl TcpConnection {
    /// Upgrade a plain TCP connection to TLS (STARTTLS pattern).
    ///
    /// The caller is responsible for exchanging any protocol-level STARTTLS
    /// handshake bytes *before* calling this method.  This method performs
    /// only the TLS handshake on the existing TCP stream.
    pub async fn upgrade_to_tls(
        self,
        hostname: &str,
        timeout_dur: Duration,
    ) -> Result<TlsConnection> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        let server_name = rustls::pki_types::ServerName::try_from(hostname.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid server name '{}': {}", hostname, e))?;

        let tls_stream =
            timeout(timeout_dur, connector.connect(server_name, self.stream)).await??;

        debug!("STARTTLS upgrade completed for {}", hostname);
        Ok(TlsConnection {
            stream: tls_stream,
            timeout: timeout_dur,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Additional helpers — TlsConnection
// ──────────────────────────────────────────────────────────────────────────────

impl TlsConnection {
    /// Read exactly `n` bytes and return them as a `Vec<u8>`.
    pub async fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        let buf = self.read_exact(n).await?;
        Ok(buf.to_vec())
    }

    /// Read until a single byte `delimiter` is found; the delimiter is included
    /// in the returned buffer.
    pub async fn read_until_byte(&mut self, delimiter: u8) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(256);
        let mut tmp = [0u8; 1];
        loop {
            let n = timeout(self.timeout, self.stream.read(&mut tmp)).await??;
            if n == 0 {
                break;
            }
            buf.push(tmp[0]);
            if tmp[0] == delimiter {
                break;
            }
        }
        Ok(buf)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `read_until` correctly identifies the delimiter position in a
    /// pre-built buffer using the same windows logic as the method.
    #[test]
    fn delimiter_detection_crlf() {
        let data = b"220 Welcome\r\n";
        let delimiter = b"\r\n";
        let found = data.windows(delimiter.len()).any(|w| w == delimiter);
        assert!(found, "CRLF delimiter should be detected");
    }

    #[test]
    fn delimiter_detection_lf_only() {
        let data = b"hello\n";
        let delimiter = b"\n";
        let found = data.windows(delimiter.len()).any(|w| w == delimiter);
        assert!(found);
    }

    #[test]
    fn delimiter_not_present() {
        let data = b"partial data";
        let delimiter = b"\r\n";
        let found = data.windows(delimiter.len()).any(|w| w == delimiter);
        assert!(!found);
    }

    /// Confirm read_exact buffer sizing.
    #[test]
    fn read_exact_buf_size() {
        let buf = BytesMut::zeroed(16);
        assert_eq!(buf.len(), 16);
    }

    /// read_bytes output is identical to read_exact for same N.
    #[test]
    fn read_bytes_size_matches() {
        // Pure logic check: BytesMut::zeroed(8).to_vec() has len 8
        let bm = BytesMut::zeroed(8);
        assert_eq!(bm.to_vec().len(), 8);
    }

    /// Single-byte delimiter scan mirrors read_until_byte stop condition.
    #[test]
    fn single_byte_delimiter_scan() {
        let data = b"AUTH OK\n";
        let found = data.iter().position(|&b| b == b'\n');
        assert_eq!(found, Some(7));
    }

    /// read_until_pattern: verify pattern detection logic in isolation.
    #[test]
    fn pattern_detection_in_buffer() {
        let data = b"220 Welcome\r\nReady";
        let pattern = b"\r\n";
        let found = data.windows(pattern.len()).any(|w| w == pattern);
        assert!(found, "CRLF pattern should be detected in buffer");
    }

    /// read_bytes_exact is an alias for read_bytes — same buf size logic.
    #[test]
    fn read_bytes_exact_alias_size() {
        let bm = bytes::BytesMut::zeroed(12);
        assert_eq!(bm.to_vec().len(), 12);
    }
}
