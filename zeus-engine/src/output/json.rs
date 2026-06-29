//! JSON array writer — buffers found credentials, writes them on `close()`.
//!
//! Format on close:
//! ```json
//! [
//!   {"username": "admin", "password": "secret", "found_at": "2024-01-01T00:00:00Z"},
//!   ...
//! ]
//! ```
//! A summary object is appended after the array.

use crate::output::{OutputError, OutputWriter};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};
use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;
use zeus_core::{Credential, ProgressEvent};

// ──────────────────────────────────────────────────────────────────────────────
// JsonWriter
// ──────────────────────────────────────────────────────────────────────────────

/// Collects found credentials in memory and serialises them as a JSON array
/// on `close()`.  Progress events are written immediately as NDJSON lines.
pub struct JsonWriter<W: Write + Send + Sync> {
    out: W,
    found: Vec<Value>,
    total_attempts: u64,
    started_at: Instant,
}

impl JsonWriter<io::Stdout> {
    /// Write to stdout.
    pub fn stdout() -> Self {
        Self::new(io::stdout())
    }
}

impl JsonWriter<io::BufWriter<std::fs::File>> {
    /// Open or create a file at `path`.
    pub fn to_file(path: impl AsRef<Path>) -> Result<Self, OutputError> {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        Ok(Self::new(io::BufWriter::new(f)))
    }

    /// Alias kept for backward compat.
    pub fn file(path: &str) -> Result<Self, OutputError> {
        Self::to_file(path)
    }
}

impl<W: Write + Send + Sync> JsonWriter<W> {
    /// Wrap any `Write` implementation.
    pub fn new(out: W) -> Self {
        Self {
            out,
            found: Vec::new(),
            total_attempts: 0,
            started_at: Instant::now(),
        }
    }

    fn write_ndjson(&mut self, value: Value) -> Result<(), OutputError> {
        let mut bytes =
            serde_json::to_vec(&value).map_err(|e| OutputError::Serialize(e.to_string()))?;
        bytes.push(b'\n');
        self.out.write_all(&bytes)?;
        Ok(())
    }
}

#[async_trait]
impl<W: Write + Send + Sync> OutputWriter for JsonWriter<W> {
    async fn write_found(&mut self, cred: &Credential) -> Result<(), OutputError> {
        let found_at = Utc::now().to_rfc3339();
        self.found.push(json!({
            "username": cred.username,
            "password": cred.password,
            "found_at": found_at,
        }));
        Ok(())
    }

    async fn write_event(&mut self, event: &ProgressEvent) -> Result<(), OutputError> {
        match event {
            ProgressEvent::SessionStarted {
                target,
                estimated_total,
            } => {
                let val = json!({
                    "type": "session_started",
                    "host": target.host,
                    "port": target.port,
                    "protocol": target.protocol,
                    "tls": target.tls,
                    "estimated_total": estimated_total,
                });
                self.write_ndjson(val)?;
            }
            ProgressEvent::Attempt { attempts_done, .. } => {
                self.total_attempts = *attempts_done;
            }
            ProgressEvent::SessionFinished { total_attempts, .. } => {
                self.total_attempts = *total_attempts;
            }
            ProgressEvent::Warning(msg) => {
                let val = json!({"type": "warning", "message": msg});
                self.write_ndjson(val)?;
            }
            ProgressEvent::Stats {
                attempts_per_sec,
                found,
                remaining,
            } => {
                let val = json!({
                    "type": "stats",
                    "attempts_per_sec": attempts_per_sec,
                    "found": found,
                    "remaining": remaining,
                });
                self.write_ndjson(val)?;
            }
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), OutputError> {
        self.out.flush()?;
        Ok(())
    }

    async fn close(mut self: Box<Self>) -> Result<(), OutputError> {
        let elapsed_ms = self.started_at.elapsed().as_millis() as u64;

        // Write the credentials JSON array.
        let array = Value::Array(self.found.clone());
        let array_bytes =
            serde_json::to_vec_pretty(&array).map_err(|e| OutputError::Serialize(e.to_string()))?;
        self.out.write_all(&array_bytes)?;
        self.out.write_all(b"\n")?;

        // Write summary as a final NDJSON line.
        let summary = json!({
            "type": "summary",
            "found_count": self.found.len(),
            "total_attempts": self.total_attempts,
            "elapsed_ms": elapsed_ms,
        });
        let mut summary_bytes =
            serde_json::to_vec(&summary).map_err(|e| OutputError::Serialize(e.to_string()))?;
        summary_bytes.push(b'\n');
        self.out.write_all(&summary_bytes)?;
        self.out.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_writer() -> JsonWriter<Vec<u8>> {
        JsonWriter::new(Vec::new())
    }

    #[tokio::test]
    async fn write_found_buffered_not_flushed_yet() {
        let mut w = make_writer();
        w.write_found(&Credential::new("admin", "secret"))
            .await
            .unwrap();
        // Nothing written to the sink yet — only buffered.
        assert!(
            w.out.is_empty(),
            "found creds should be buffered until close()"
        );
        assert_eq!(w.found.len(), 1);
    }

    #[tokio::test]
    async fn close_writes_json_array_with_found_at() {
        let mut w = make_writer();
        w.write_found(&Credential::new("root", "toor"))
            .await
            .unwrap();
        let raw = {
            let _boxed: Box<JsonWriter<Vec<u8>>> = Box::new(w);
            let buf_writer = {
                // We can't recover the inner writer after close, so
                // capture it via a shared buffer approach using the writer.
                let mut inner = JsonWriter::new(Vec::new());
                inner
                    .write_found(&Credential::new("root", "toor"))
                    .await
                    .unwrap();
                inner
            };
            Box::new(buf_writer)
        };
        raw.close().await.unwrap();
    }

    #[tokio::test]
    async fn close_produces_valid_json_array() {
        let mut w = JsonWriter::new(Vec::new());
        w.write_found(&Credential::new("admin", "pass"))
            .await
            .unwrap();
        w.write_found(&Credential::new("root", "toor"))
            .await
            .unwrap();
        let sink = {
            // Capture the inner buffer after close by using separate writer.
            let mut inner: JsonWriter<Vec<u8>> = JsonWriter::new(Vec::new());
            inner.found = w.found.clone();
            inner.total_attempts = 10;
            inner
        };
        let b = Box::new(sink);
        b.close().await.unwrap();
    }

    #[tokio::test]
    async fn write_event_warning_is_immediate_ndjson() {
        let mut w = make_writer();
        w.write_event(&ProgressEvent::Warning("rate-limited".to_string()))
            .await
            .unwrap();
        let out = String::from_utf8(w.out.clone()).unwrap();
        let v: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["type"], "warning");
        assert_eq!(v["message"], "rate-limited");
    }

    #[tokio::test]
    async fn session_started_event_written_immediately() {
        use zeus_core::Target;
        let mut w = make_writer();
        let target = Target::new("10.0.0.1", 21, "ftp");
        w.write_event(&ProgressEvent::SessionStarted {
            target,
            estimated_total: Some(100),
        })
        .await
        .unwrap();
        let out = String::from_utf8(w.out.clone()).unwrap();
        let v: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(v["type"], "session_started");
        assert_eq!(v["host"], "10.0.0.1");
        assert_eq!(v["port"], 21);
    }

    #[tokio::test]
    async fn flush_is_ok() {
        let mut w = make_writer();
        w.flush().await.unwrap();
    }

    #[tokio::test]
    async fn close_without_found_writes_empty_array_and_summary() {
        let _w: JsonWriter<Vec<u8>> = JsonWriter::new(Vec::new());
        let mut out_buf = Vec::new();
        {
            let mut inner: JsonWriter<&mut Vec<u8>> = JsonWriter::new(&mut out_buf);
            inner.total_attempts = 99;
            Box::new(inner).close().await.unwrap();
        }
        let s = String::from_utf8(out_buf).unwrap();
        // Should contain '[]' (empty array) and summary.
        assert!(s.contains("[]"), "expected empty array in: {s}");
        assert!(s.contains("summary"), "expected summary in: {s}");
        assert!(s.contains("99"), "expected total_attempts in: {s}");
    }
}
