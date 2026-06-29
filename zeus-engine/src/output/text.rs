//! Text writer — human-readable output with ANSI colours.
//!
//! Implements `OutputWriter` using synchronous `std::io::Write` sinks
//! (stdout, stderr, files, or any in-memory `Vec<u8>` for testing).

use super::{OutputError, OutputWriter};
use async_trait::async_trait;
use std::io::Write;
use std::path::Path;
use zeus_core::{Credential, ProgressEvent};

// ── ANSI colour codes ─────────────────────────────────────────────────────────
const RESET: &str = "\x1b[0m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";

// ──────────────────────────────────────────────────────────────────────────────
// TextWriter
// ──────────────────────────────────────────────────────────────────────────────

/// Writes human-readable lines to any `Write` sink.
pub struct TextWriter<W: Write + Send + Sync> {
    out: W,
    verbose: bool,
}

impl<W: Write + Send + Sync> TextWriter<W> {
    /// Wrap any `Write` implementation.
    pub fn new(out: W, verbose: bool) -> Self {
        Self { out, verbose }
    }
}

impl TextWriter<std::io::Stdout> {
    /// Write to stdout.
    pub fn to_stdout() -> Self {
        Self::new(std::io::stdout(), false)
    }

    /// Write to stdout with explicit verbosity setting.
    pub fn stdout(verbose: bool) -> Self {
        Self::new(std::io::stdout(), verbose)
    }
}

impl TextWriter<std::io::Stderr> {
    /// Write to stderr.
    pub fn stderr(verbose: bool) -> Self {
        Self::new(std::io::stderr(), verbose)
    }
}

impl TextWriter<std::fs::File> {
    /// Open or create a file at `path`.
    pub fn to_file(path: impl AsRef<Path>) -> Result<Self, OutputError> {
        let f = std::fs::File::create(path)?;
        Ok(Self::new(f, false))
    }

    /// Open or create a file at `path` with explicit verbosity.
    pub fn file(path: &str, verbose: bool) -> Result<Self, OutputError> {
        let f = std::fs::File::create(path)?;
        Ok(Self::new(f, verbose))
    }
}

#[async_trait]
impl<W: Write + Send + Sync> OutputWriter for TextWriter<W> {
    async fn write_found(&mut self, cred: &Credential) -> Result<(), OutputError> {
        writeln!(
            self.out,
            "{BOLD}{GREEN}[FOUND]{RESET} {}:{}",
            cred.username, cred.password
        )?;
        Ok(())
    }

    async fn write_event(&mut self, event: &ProgressEvent) -> Result<(), OutputError> {
        match event {
            ProgressEvent::SessionStarted {
                target,
                estimated_total,
            } => {
                let est = estimated_total
                    .map(|n| format!(" (estimated: {n})"))
                    .unwrap_or_default();
                writeln!(
                    self.out,
                    "{CYAN}[>]{RESET} Session started: {}{est}",
                    target.host
                )?;
            }
            ProgressEvent::SessionFinished {
                found,
                total_attempts,
                elapsed,
                ..
            } => {
                writeln!(
                    self.out,
                    "{CYAN}[=]{RESET} Session finished: {} found, {} attempts, {:.1}s",
                    found.len(),
                    total_attempts,
                    elapsed.as_secs_f64()
                )?;
            }
            ProgressEvent::Warning(msg) if self.verbose => {
                writeln!(self.out, "[!] {msg}")?;
            }
            ProgressEvent::Stats {
                attempts_per_sec,
                found,
                remaining,
            } if self.verbose => {
                let rem = remaining
                    .map(|r| format!(", ~{r} remaining"))
                    .unwrap_or_default();
                writeln!(
                    self.out,
                    "[~] {:.1} req/s  found: {found}{rem}",
                    attempts_per_sec
                )?;
            }
            // Non-verbose: skip Attempt, Warning, Stats
            _ => {}
        }
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
    use zeus_core::Target;

    fn make_writer(verbose: bool) -> TextWriter<Vec<u8>> {
        TextWriter::new(Vec::new(), verbose)
    }

    fn output(w: TextWriter<Vec<u8>>) -> String {
        String::from_utf8(w.out).unwrap()
    }

    #[tokio::test]
    async fn write_found_contains_found_marker() {
        let mut w = make_writer(false);
        let cred = Credential::new("admin", "secret");
        w.write_found(&cred).await.unwrap();
        let s = output(w);
        assert!(s.contains("[FOUND]"), "expected [FOUND] in: {s}");
        assert!(s.contains("admin:secret"), "expected cred in: {s}");
    }

    #[tokio::test]
    async fn session_started_event() {
        let mut w = make_writer(true);
        let target = Target::new("192.168.1.1", 22, "ssh");
        let event = ProgressEvent::SessionStarted {
            target,
            estimated_total: Some(500),
        };
        w.write_event(&event).await.unwrap();
        let s = output(w);
        assert!(s.contains("[>]"), "expected [>] in: {s}");
        assert!(s.contains("192.168.1.1"), "expected host in: {s}");
        assert!(s.contains("500"), "expected estimated total in: {s}");
    }

    #[tokio::test]
    async fn session_finished_event() {
        let mut w = make_writer(false);
        let event = ProgressEvent::SessionFinished {
            found: vec![Credential::new("r", "t")],
            total_attempts: 42,
            elapsed: std::time::Duration::from_secs(3),
            successes: 1,
            failures: 41,
            errors: 0,
            rate_limits: 0,
            timeouts: 0,
            rate_per_second: 14.0,
        };
        w.write_event(&event).await.unwrap();
        let s = output(w);
        assert!(s.contains("[=]"), "expected [=] in: {s}");
        assert!(s.contains("42"), "expected attempt count in: {s}");
    }

    #[tokio::test]
    async fn warning_suppressed_when_not_verbose() {
        let mut w = make_writer(false);
        w.write_event(&ProgressEvent::Warning("oops".to_string()))
            .await
            .unwrap();
        let s = output(w);
        assert!(
            s.is_empty(),
            "warning should be suppressed in non-verbose mode"
        );
    }

    #[tokio::test]
    async fn warning_shown_when_verbose() {
        let mut w = make_writer(true);
        w.write_event(&ProgressEvent::Warning("oops".to_string()))
            .await
            .unwrap();
        let s = output(w);
        assert!(s.contains("oops"), "warning should appear in verbose mode");
    }

    #[tokio::test]
    async fn flush_is_ok() {
        let mut w = make_writer(false);
        w.flush().await.unwrap();
    }

    #[tokio::test]
    async fn close_consumes_writer() {
        let w = make_writer(false);
        Box::new(w).close().await.unwrap();
    }
}
