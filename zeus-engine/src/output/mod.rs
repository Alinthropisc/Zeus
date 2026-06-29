//! Zeus Output — structured result formatters and security report generation.
//!
//! ## Original strategy-pattern writers
//! `OutputWriter` trait + `TextWriter`, `JsonWriter`, `CsvWriter` implementations.
//!
//! ## Phase 3 — Reporting & Defence Integration
//! - [`finding`]     — core finding/evidence types
//! - [`builder`]     — `ReportBuilder` (builder pattern)
//! - [`renderer`]    — `ReportRenderer` visitors (JSON, CSV, Nuclei, Timeline)
//! - [`cvss`]        — CVSS v3.1 base-score calculator
//! - [`scoring`]     — severity scoring + false-positive rate
//! - [`remediation`] — static remediation database
//! - [`pipeline`]    — end-to-end render + write convenience wrapper

pub mod csv;
pub mod json;
pub mod text;

// Phase 3 modules
pub mod builder;
pub mod cvss;
pub mod finding;
pub mod pipeline;
pub mod remediation;
pub mod renderer;
pub mod scoring;

// Phase 8/9 modules
pub mod integrations;

pub use integrations::{DefectDojoClient, DefectDojoConfig, JiraClient, JiraConfig};
pub use renderer::HtmlRenderer;

pub use csv::CsvWriter;
pub use json::JsonWriter;
pub use text::TextWriter;

use async_trait::async_trait;
use thiserror::Error;
use zeus_core::{Credential, ProgressEvent};

#[derive(Debug, Error)]
pub enum OutputError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialize error: {0}")]
    Serialize(String),
}

/// Strategy pattern for formatting output.
///
/// All writers must implement this trait. Use `OutputManager` to broadcast
/// events and found credentials to multiple writers simultaneously.
#[async_trait]
pub trait OutputWriter: Send + Sync {
    /// Record a found credential.
    async fn write_found(&mut self, cred: &Credential) -> Result<(), OutputError>;

    /// Record a progress/lifecycle event.
    async fn write_event(&mut self, event: &ProgressEvent) -> Result<(), OutputError>;

    /// Flush internal buffers to the underlying sink.
    async fn flush(&mut self) -> Result<(), OutputError>;

    /// Flush and close the writer, consuming it.
    async fn close(self: Box<Self>) -> Result<(), OutputError>;
}

// ──────────────────────────────────────────────────────────────────────────────
// OutputManager
// ──────────────────────────────────────────────────────────────────────────────

/// Fan-out multiplexer: broadcasts to a list of heterogeneous writers.
///
/// Errors from individual writers are accumulated; the first error encountered
/// is returned after attempting all writers.
pub struct OutputManager {
    writers: Vec<Box<dyn OutputWriter>>,
}

impl OutputManager {
    pub fn new() -> Self {
        Self {
            writers: Vec::new(),
        }
    }

    /// Add a writer to the fan-out set.
    pub fn add(&mut self, writer: Box<dyn OutputWriter>) {
        self.writers.push(writer);
    }

    /// Broadcast a found credential to all writers.
    ///
    /// All writers are attempted; the first error is returned.
    pub async fn broadcast_found(&mut self, cred: &Credential) -> Result<(), OutputError> {
        let mut first_err: Option<OutputError> = None;
        for w in &mut self.writers {
            if let Err(e) = w.write_found(cred).await
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Broadcast a progress event to all writers.
    ///
    /// All writers are attempted; the first error is returned.
    pub async fn broadcast_event(&mut self, event: &ProgressEvent) -> Result<(), OutputError> {
        let mut first_err: Option<OutputError> = None;
        for w in &mut self.writers {
            if let Err(e) = w.write_event(event).await
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Flush and close all writers, consuming the manager.
    ///
    /// All writers are closed regardless of individual errors; the first error
    /// encountered is returned after all have been processed.
    pub async fn close_all(self) -> Result<(), OutputError> {
        let mut first_err: Option<OutputError> = None;
        for w in self.writers {
            if let Err(e) = w.close().await
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl Default for OutputManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    /// In-memory test writer — records every call.
    struct TestWriter {
        found: Arc<Mutex<Vec<String>>>,
        events: Arc<Mutex<Vec<String>>>,
        closed: Arc<Mutex<bool>>,
    }

    impl TestWriter {
        #[allow(clippy::type_complexity)]
        fn new() -> (
            Self,
            Arc<Mutex<Vec<String>>>,
            Arc<Mutex<Vec<String>>>,
            Arc<Mutex<bool>>,
        ) {
            let found = Arc::new(Mutex::new(Vec::new()));
            let events = Arc::new(Mutex::new(Vec::new()));
            let closed = Arc::new(Mutex::new(false));
            let w = Self {
                found: Arc::clone(&found),
                events: Arc::clone(&events),
                closed: Arc::clone(&closed),
            };
            (w, found, events, closed)
        }
    }

    #[async_trait]
    impl OutputWriter for TestWriter {
        async fn write_found(&mut self, cred: &Credential) -> Result<(), OutputError> {
            self.found.lock().unwrap().push(cred.to_string());
            Ok(())
        }

        async fn write_event(&mut self, event: &ProgressEvent) -> Result<(), OutputError> {
            let label = match event {
                ProgressEvent::SessionStarted { .. } => "started",
                ProgressEvent::SessionFinished { .. } => "finished",
                ProgressEvent::Attempt { .. } => "attempt",
                ProgressEvent::Warning(_) => "warning",
                ProgressEvent::Stats { .. } => "stats",
            };
            self.events.lock().unwrap().push(label.to_string());
            Ok(())
        }

        async fn flush(&mut self) -> Result<(), OutputError> {
            Ok(())
        }

        async fn close(self: Box<Self>) -> Result<(), OutputError> {
            *self.closed.lock().unwrap() = true;
            Ok(())
        }
    }

    #[tokio::test]
    async fn manager_broadcasts_found_to_all_writers() {
        let (w1, found1, _, _) = TestWriter::new();
        let (w2, found2, _, _) = TestWriter::new();

        let mut mgr = OutputManager::new();
        mgr.add(Box::new(w1));
        mgr.add(Box::new(w2));

        let cred = Credential::new("admin", "pass");
        mgr.broadcast_found(&cred).await.unwrap();

        assert_eq!(found1.lock().unwrap().as_slice(), ["admin:pass"]);
        assert_eq!(found2.lock().unwrap().as_slice(), ["admin:pass"]);
    }

    #[tokio::test]
    async fn manager_broadcasts_event_to_all_writers() {
        let (w1, _, events1, _) = TestWriter::new();
        let (w2, _, events2, _) = TestWriter::new();

        let mut mgr = OutputManager::new();
        mgr.add(Box::new(w1));
        mgr.add(Box::new(w2));

        let event = ProgressEvent::Warning("test".to_string());
        mgr.broadcast_event(&event).await.unwrap();

        assert_eq!(events1.lock().unwrap().as_slice(), ["warning"]);
        assert_eq!(events2.lock().unwrap().as_slice(), ["warning"]);
    }

    #[tokio::test]
    async fn manager_close_all_marks_closed() {
        let (w1, _, _, closed1) = TestWriter::new();
        let (w2, _, _, closed2) = TestWriter::new();

        let mut mgr = OutputManager::new();
        mgr.add(Box::new(w1));
        mgr.add(Box::new(w2));

        mgr.close_all().await.unwrap();

        assert!(*closed1.lock().unwrap());
        assert!(*closed2.lock().unwrap());
    }

    #[tokio::test]
    async fn manager_default_is_empty() {
        let mgr = OutputManager::default();
        assert!(mgr.writers.is_empty());
    }
}
