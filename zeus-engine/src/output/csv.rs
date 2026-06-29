//! CSV output writer — one row per found credential, no external csv crate.
//!
//! Header: `username,password,timestamp`
//!
//! Internal double-quotes are escaped by doubling them (""), and every field
//! value is wrapped in quotes per RFC 4180.

use crate::{OutputError, OutputWriter};
use async_trait::async_trait;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeus_core::{Credential, ProgressEvent};

const HEADER: &str = "username,password,timestamp\n";

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Wrap a CSV field in double-quotes, doubling any internal quote characters.
pub fn csv_escape(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ──────────────────────────────────────────────────────────────────────────────
// CsvWriter
// ──────────────────────────────────────────────────────────────────────────────

/// Writes CSV rows to any `Write` sink.
///
/// The header (`username,password,timestamp`) is written immediately on
/// construction. Only found credentials are emitted — progress events are
/// intentionally ignored to keep the file machine-parseable.
pub struct CsvWriter<W: Write + Send + Sync> {
    out: W,
}

impl CsvWriter<io::Stdout> {
    /// Write CSV to stdout (includes header immediately).
    pub fn to_stdout() -> Result<Self, OutputError> {
        let mut w = Self { out: io::stdout() };
        w.write_header()?;
        Ok(w)
    }

    /// Alias kept for backward compat.
    pub fn stdout() -> Result<Self, OutputError> {
        Self::to_stdout()
    }
}

impl CsvWriter<io::BufWriter<std::fs::File>> {
    /// Open or create a file at `path` (includes header immediately).
    pub fn to_file(path: impl AsRef<Path>) -> Result<Self, OutputError> {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        let mut w = Self { out: io::BufWriter::new(f) };
        w.write_header()?;
        Ok(w)
    }

    /// Alias kept for backward compat.
    pub fn file(path: &str) -> Result<Self, OutputError> {
        Self::to_file(path)
    }
}

impl<W: Write + Send + Sync> CsvWriter<W> {
    /// Wrap any `Write` implementation and write the CSV header immediately.
    pub fn new(out: W) -> Result<Self, OutputError> {
        let mut w = Self { out };
        w.write_header()?;
        Ok(w)
    }

    fn write_header(&mut self) -> Result<(), OutputError> {
        self.out.write_all(HEADER.as_bytes())?;
        Ok(())
    }

    fn write_row(&mut self, username: &str, password: &str, ts: u64) -> Result<(), OutputError> {
        let row = format!(
            "{},{},{}\n",
            csv_escape(username),
            csv_escape(password),
            ts,
        );
        self.out.write_all(row.as_bytes())?;
        Ok(())
    }
}

#[async_trait]
impl<W: Write + Send + Sync> OutputWriter for CsvWriter<W> {
    async fn write_found(&mut self, cred: &Credential) -> Result<(), OutputError> {
        self.write_row(&cred.username, &cred.password, now_ms())
    }

    /// Progress events are intentionally a no-op for the CSV writer.
    ///
    /// The CSV file format is designed for machine parsing of results only;
    /// lifecycle events are better captured by `TextWriter` or `JsonWriter`.
    async fn write_event(&mut self, _event: &ProgressEvent) -> Result<(), OutputError> {
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), OutputError> {
        self.out.flush()?;
        Ok(())
    }

    async fn close(mut self: Box<Self>) -> Result<(), OutputError> {
        self.out.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_writer() -> CsvWriter<Vec<u8>> {
        CsvWriter::new(Vec::new()).unwrap()
    }

    fn output(w: CsvWriter<Vec<u8>>) -> String {
        String::from_utf8(w.out).unwrap()
    }

    #[test]
    fn output_contains_header() {
        let w = make_writer();
        let s = output(w);
        assert!(s.starts_with("username,password,timestamp\n"), "bad header: {s}");
    }

    #[tokio::test]
    async fn write_found_adds_row() {
        let mut w = make_writer();
        w.write_found(&Credential::new("admin", "hunter2")).await.unwrap();
        let s = output(w);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2, "expected header + 1 data row");
        assert!(lines[1].contains("\"admin\""), "username missing");
        assert!(lines[1].contains("\"hunter2\""), "password missing");
    }

    #[tokio::test]
    async fn write_found_multiple_rows() {
        let mut w = make_writer();
        w.write_found(&Credential::new("root", "toor")).await.unwrap();
        w.write_found(&Credential::new("admin", "pass")).await.unwrap();
        let s = output(w);
        assert_eq!(s.lines().count(), 3, "expected header + 2 rows");
    }

    #[tokio::test]
    async fn write_event_is_noop() {
        let mut w = make_writer();
        w.write_event(&ProgressEvent::Warning("blah".to_string())).await.unwrap();
        let s = output(w);
        // Only the header line.
        assert_eq!(s.lines().count(), 1, "events should be ignored by CsvWriter");
    }

    #[test]
    fn csv_escape_plain() {
        assert_eq!(csv_escape("hello"), "\"hello\"");
    }

    #[test]
    fn csv_escape_double_quotes() {
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn csv_escape_empty() {
        assert_eq!(csv_escape(""), "\"\"");
    }

    #[tokio::test]
    async fn flush_is_ok() {
        let mut w = make_writer();
        w.flush().await.unwrap();
    }

    #[tokio::test]
    async fn close_consumes_writer() {
        let w = make_writer();
        Box::new(w).close().await.unwrap();
    }
}
