//! Pipeline pattern — collects Findings from probes and feeds them into a Report.
//!
//! `ProbeRunner` acts as the glue between the probe layer (which produces
//! probe-specific finding types) and the `zeus-output` reporting layer.
//! It accumulates [`Finding`] values, then renders or saves the finished
//! [`Report`] via any [`ReportRenderer`].

use std::path::Path;

use anyhow::Result;
use crate::output::builder::ReportBuilder;
use crate::output::finding::Finding;
use crate::output::renderer::{JsonRenderer, ReportRenderer};

// ─────────────────────────────────────────────────────────────────────────────
// ProbeRunner
// ─────────────────────────────────────────────────────────────────────────────

/// Accumulates [`Finding`] values emitted by probe modules and renders them
/// into a structured [`Report`] via a pluggable [`ReportRenderer`].
///
/// # Example
/// ```rust,ignore
/// let mut runner = ProbeRunner::new("JWT Audit", "https://api.example.com");
/// for f in jwt_probe.probe(&adapter, endpoint, &token).await? {
///     if f.server_accepted {
///         runner.add_finding(jwt_finding_to_output_finding(&f));
///     }
/// }
/// runner.save(Path::new("report.json"))?;
/// ```
#[derive(Debug)]
pub struct ProbeRunner {
    builder: ReportBuilder,
    renderer: Box<dyn ReportRenderer>,
}

impl ProbeRunner {
    /// Create a new runner with a JSON renderer (the safe default).
    pub fn new(title: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            builder: ReportBuilder::new().title(title).target(target),
            renderer: Box::new(JsonRenderer),
        }
    }

    /// Replace the renderer with any [`ReportRenderer`] implementation.
    ///
    /// Allows switching to `CsvRenderer`, `NucleiRenderer`, etc. at call-site.
    pub fn with_renderer(mut self, renderer: impl ReportRenderer + 'static) -> Self {
        self.renderer = Box::new(renderer);
        self
    }

    /// Record the session start timestamp.
    pub fn session_start(mut self, ts: chrono::DateTime<chrono::Utc>) -> Self {
        self.builder = self.builder.session_start(ts);
        self
    }

    /// Record the session end timestamp.
    pub fn session_end(mut self, ts: chrono::DateTime<chrono::Utc>) -> Self {
        self.builder = self.builder.session_end(ts);
        self
    }

    /// Append a [`Finding`] to the accumulating report.
    pub fn add_finding(&mut self, finding: Finding) {
        // ReportBuilder consumes self — swap it out using Default.
        let builder = std::mem::take(&mut self.builder);
        self.builder = builder.add_finding(finding);
    }

    /// Render all accumulated findings into a string using the active renderer.
    pub fn render(&self) -> Result<String> {
        let report = self.builder.clone().build(0.0);
        self.renderer
            .render(&report)
            .map_err(|e| anyhow::anyhow!("render error: {e}"))
    }

    /// Render and write the report to `path`.
    ///
    /// # Blocking
    /// This method calls `std::fs::write` which is a blocking syscall.
    /// Do **not** call this directly from an async task; use
    /// [`ProbeRunner::save_async`] instead.
    pub fn save(&self, path: &Path) -> Result<()> {
        let output = self.render()?;
        std::fs::write(path, output)
            .map_err(|e| anyhow::anyhow!("failed to write report to {}: {e}", path.display()))
    }

    /// Async version of [`save`](Self::save) — uses `tokio::fs::write` so
    /// the async executor is not blocked.
    pub async fn save_async(&self, path: &Path) -> Result<()> {
        let output = self.render()?;
        tokio::fs::write(path, output)
            .await
            .map_err(|e| anyhow::anyhow!("failed to write report to {}: {e}", path.display()))
    }

    /// Return the number of findings accumulated so far.
    pub fn finding_count(&self) -> usize {
        // Clone a snapshot to build without consuming. This is cheap for typical
        // probe counts (tens of findings, not millions).
        self.builder.clone().build(0.0).findings.len()
    }
}
