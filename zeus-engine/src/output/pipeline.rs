//! End-to-end pipeline convenience wrapper.
//!
//! `ReportPipeline` combines a [`ReportRenderer`] with an optional output path
//! so call-sites can select a format once and reuse it for render + save.

use std::path::PathBuf;

use crate::output::builder::Report;
use crate::output::renderer::{CsvRenderer, JsonRenderer, NucleiRenderer, ReportRenderer};
use crate::output::OutputError;

// ─────────────────────────────────────────────────────────────────────────────
// ReportPipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps a renderer and an optional output path.
///
/// Call [`ReportPipeline::run`] to render a [`Report`]; the result is both
/// returned as a `String` and, when `output_path` is set, written to disk.
///
/// # Example
/// ```rust,ignore
/// let output = ReportPipeline::json()
///     .with_output("reports/jwt.json")
///     .run(&report)?;
/// ```
#[derive(Debug)]
pub struct ReportPipeline {
    pub renderer: Box<dyn ReportRenderer>,
    pub output_path: Option<PathBuf>,
}

impl ReportPipeline {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Pipeline that emits pretty-printed JSON.
    pub fn json() -> Self {
        Self { renderer: Box::new(JsonRenderer), output_path: None }
    }

    /// Pipeline that emits flat CSV (one row per finding).
    pub fn csv() -> Self {
        Self { renderer: Box::new(CsvRenderer), output_path: None }
    }

    /// Pipeline that emits Nuclei-compatible JSONL output.
    pub fn nuclei() -> Self {
        Self { renderer: Box::new(NucleiRenderer), output_path: None }
    }

    /// Set (or replace) the file path the pipeline writes to after rendering.
    pub fn with_output(mut self, path: impl Into<PathBuf>) -> Self {
        self.output_path = Some(path.into());
        self
    }

    // ── Core operation ────────────────────────────────────────────────────────

    /// Render `report` to a string and, if `output_path` is set, write to disk.
    ///
    /// Returns the rendered string regardless of whether a file was written.
    pub fn run(&self, report: &Report) -> Result<String, OutputError> {
        let rendered = self.renderer.render(report)?;
        if let Some(path) = &self.output_path {
            std::fs::write(path, &rendered).map_err(OutputError::Io)?;
        }
        Ok(rendered)
    }
}
