//! Minimal HTTP server that exposes a Prometheus `/metrics` scrape endpoint.
//!
//! Uses raw `tokio::net::TcpListener` — no axum/hyper dependency — to keep the
//! binary small.  Supports only two routes:
//!
//! | Route      | Response                                         |
//! |------------|--------------------------------------------------|
//! | `GET /metrics` | `200 OK`, `text/plain; version=0.0.4`, body = Prometheus format |
//! | `GET /health`  | `200 OK`, body = `ok`                        |
//! | anything else  | `404 Not Found`                              |

use std::sync::Arc;
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::metrics::{MetricsExporter, MetricsRegistry, PrometheusExporter};

// ---------------------------------------------------------------------------
// MetricsServer
// ---------------------------------------------------------------------------

/// A lightweight HTTP/1.1 server that serves `/metrics` for Prometheus scraping
/// and `/health` for liveness probes.
#[derive(Debug)]
pub struct MetricsServer {
    /// Bind address, e.g. `"0.0.0.0:9090"`.
    pub bind_addr: String,
    /// Shared metrics registry.
    pub registry: Arc<MetricsRegistry>,
    /// Exporter used to serialise snapshots for the `/metrics` route.
    pub exporter: Box<dyn MetricsExporter>,
}

impl MetricsServer {
    /// Create a server with the default `PrometheusExporter` (namespace `"zeus"`).
    pub fn new(bind_addr: impl Into<String>, registry: Arc<MetricsRegistry>) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            registry,
            exporter: Box::new(PrometheusExporter::new("zeus")),
        }
    }

    /// Create a server with a custom exporter.
    pub fn with_exporter(
        bind_addr: impl Into<String>,
        registry: Arc<MetricsRegistry>,
        exporter: Box<dyn MetricsExporter>,
    ) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            registry,
            exporter,
        }
    }

    /// Run the server loop.  Accepts connections sequentially (one at a time is
    /// fine for a low-frequency Prometheus scraper).  Returns an error only if
    /// `TcpListener::bind` fails; individual connection errors are logged and
    /// skipped.
    pub async fn serve(self) -> Result<()> {
        let listener = TcpListener::bind(&self.bind_addr).await?;
        tracing::info!(addr = %self.bind_addr, "metrics server listening");

        let registry = Arc::clone(&self.registry);
        let exporter = self.exporter;

        loop {
            let (mut stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "metrics server: accept error");
                    continue;
                }
            };

            // Read enough bytes to determine the request path.
            let mut buf = [0u8; 512];
            let n = match stream.read(&mut buf).await {
                Ok(n) if n == 0 => continue,
                Ok(n) => n,
                Err(e) => {
                    tracing::debug!(peer = %peer, error = %e, "metrics server: read error");
                    continue;
                }
            };

            let request = String::from_utf8_lossy(&buf[..n]);
            // First line of HTTP request: "GET /path HTTP/1.1"
            let first_line = request.lines().next().unwrap_or("");

            let response = if first_line.starts_with("GET /metrics") {
                match registry.snapshot_and_export(&*exporter) {
                    Ok(body) => http_response(200, "OK", "text/plain; version=0.0.4", &body),
                    Err(e) => {
                        tracing::warn!(error = %e, "metrics export failed");
                        http_response(500, "Internal Server Error", "text/plain", "export error")
                    }
                }
            } else if first_line.starts_with("GET /health") {
                http_response(200, "OK", "text/plain", "ok")
            } else {
                http_response(404, "Not Found", "text/plain", "not found")
            };

            if let Err(e) = stream.write_all(response.as_bytes()).await {
                tracing::debug!(peer = %peer, error = %e, "metrics server: write error");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: format a minimal HTTP/1.1 response (no keep-alive)
// ---------------------------------------------------------------------------

fn http_response(status: u16, reason: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    )
}

// ---------------------------------------------------------------------------
// Extension method on MetricsRegistry for convenience
// ---------------------------------------------------------------------------

/// Helper extension so the server can take a snapshot and export it in one
/// call without needing the snapshot type in scope.
trait SnapshotAndExport {
    fn snapshot_and_export(&self, exporter: &dyn MetricsExporter) -> Result<String>;
}

impl SnapshotAndExport for MetricsRegistry {
    fn snapshot_and_export(&self, exporter: &dyn MetricsExporter) -> Result<String> {
        let snap = self.snapshot();
        exporter.export(&snap)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_response_200_format() {
        let resp = http_response(200, "OK", "text/plain", "hello");
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains("Content-Length: 5\r\n"));
        assert!(resp.ends_with("hello"));
    }

    #[test]
    fn http_response_404_format() {
        let resp = http_response(404, "Not Found", "text/plain", "not found");
        assert!(resp.contains("404 Not Found"));
    }

    #[test]
    fn snapshot_and_export_roundtrip() {
        let registry = MetricsRegistry::new();
        registry.inc_attempts();

        let exporter = PrometheusExporter::new("zeus");
        let result = registry.snapshot_and_export(&exporter);
        assert!(result.is_ok());
        let text = result.unwrap();
        assert!(text.contains("zeus_attempts_total 1"));
    }
}
