//! Visitor pattern for rendering a [`Report`] into multiple output formats.
//!
//! Each `*Renderer` implements [`ReportRenderer`] and produces a different
//! textual representation of the same report data.

use crate::output::OutputError;
use crate::output::builder::Report;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Visitor trait
// ─────────────────────────────────────────────────────────────────────────────

/// Visitor trait — each renderer "visits" a [`Report`] and returns a string.
pub trait ReportRenderer: Send + Sync + fmt::Debug {
    fn render(&self, report: &Report) -> Result<String, OutputError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// JsonRenderer
// ─────────────────────────────────────────────────────────────────────────────

/// Serialises the full report as pretty-printed JSON.
#[derive(Debug)]
pub struct JsonRenderer;

impl ReportRenderer for JsonRenderer {
    fn render(&self, report: &Report) -> Result<String, OutputError> {
        serde_json::to_string_pretty(report).map_err(|e| OutputError::Serialize(e.to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CsvRenderer
// ─────────────────────────────────────────────────────────────────────────────

/// Flat CSV with one row per finding.
///
/// Columns: `id,title,severity,category,cvss_score,remediation,timestamp`
#[derive(Debug)]
pub struct CsvRenderer;

impl ReportRenderer for CsvRenderer {
    fn render(&self, report: &Report) -> Result<String, OutputError> {
        let mut out = String::from("id,title,severity,category,cvss_score,remediation,timestamp\n");

        for f in &report.findings {
            // Escape double-quotes in free-text fields.
            let title = f.title.replace('"', "\"\"");
            let remediation = f.remediation.replace('"', "\"\"");

            out.push_str(&format!(
                "{},\"{}\",{},{},{:.1},\"{}\",{}\n",
                f.id,
                title,
                f.severity,
                f.category,
                f.cvss_score,
                remediation,
                f.timestamp.to_rfc3339(),
            ));
        }

        Ok(out)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NucleiRenderer
// ─────────────────────────────────────────────────────────────────────────────

/// Emits one Nuclei-compatible JSON object per line (JSONL).
///
/// Each object carries: `templateID`, `host`, `matched-at`, `severity`,
/// `name`, `description`.
#[derive(Debug)]
pub struct NucleiRenderer;

impl ReportRenderer for NucleiRenderer {
    fn render(&self, report: &Report) -> Result<String, OutputError> {
        let mut lines = Vec::with_capacity(report.findings.len());

        for f in &report.findings {
            let obj = serde_json::json!({
                "templateID": format!("zeus-{}", f.category.to_string().to_lowercase()),
                "host": report.metadata.target,
                "matched-at": report.metadata.target,
                "severity": f.severity.to_string().to_lowercase(),
                "name": f.title,
                "description": f.description,
            });

            lines.push(
                serde_json::to_string(&obj).map_err(|e| OutputError::Serialize(e.to_string()))?,
            );
        }

        Ok(lines.join("\n"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TimelineRenderer
// ─────────────────────────────────────────────────────────────────────────────

/// Renders the report timeline as human-readable ASCII.
///
/// Format: `[HH:MM:SS] EVENT_TYPE | detail`
#[derive(Debug)]
pub struct TimelineRenderer;

impl ReportRenderer for TimelineRenderer {
    fn render(&self, report: &Report) -> Result<String, OutputError> {
        let mut out = String::new();

        for event in &report.timeline {
            let hms = event.timestamp.format("%H:%M:%S");
            out.push_str(&format!(
                "[{}] {} | {}\n",
                hms, event.event_type, event.detail,
            ));
        }

        Ok(out)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HtmlRenderer
// ─────────────────────────────────────────────────────────────────────────────

/// Self-contained HTML report — all CSS is inlined; no external dependencies.
#[derive(Debug)]
pub struct HtmlRenderer;

impl HtmlRenderer {
    fn severity_color(severity: &crate::output::finding::Severity) -> &'static str {
        use crate::output::finding::Severity;
        match severity {
            Severity::Critical => "#dc2626",
            Severity::High => "#ea580c",
            Severity::Medium => "#ca8a04",
            Severity::Low => "#2563eb",
            Severity::Info => "#6b7280",
        }
    }

    fn severity_badge(severity: &crate::output::finding::Severity) -> String {
        let label = severity.to_string();
        let css_class = label.to_lowercase();
        format!(r#"<span class="badge badge-{css_class}">{label}</span>"#)
    }

    fn count_by_severity(report: &Report, target: &crate::output::finding::Severity) -> usize {
        report
            .findings
            .iter()
            .filter(|f| &f.severity == target)
            .count()
    }
}

impl ReportRenderer for HtmlRenderer {
    fn render(&self, report: &Report) -> Result<String, OutputError> {
        use crate::output::finding::Severity;

        let generated_at = report.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC");

        // ── severity summary counts ──
        let critical = Self::count_by_severity(report, &Severity::Critical);
        let high = Self::count_by_severity(report, &Severity::High);
        let medium = Self::count_by_severity(report, &Severity::Medium);
        let low = Self::count_by_severity(report, &Severity::Low);
        let info = Self::count_by_severity(report, &Severity::Info);

        // ── findings table rows ──
        let mut findings_rows = String::new();
        for f in &report.findings {
            let badge = Self::severity_badge(&f.severity);
            let ts = f.timestamp.format("%Y-%m-%d %H:%M:%S");
            let id_short = f.id.to_string().chars().take(8).collect::<String>();

            findings_rows.push_str(&format!(
                r#"<tr>
  <td class="mono">{id_short}…</td>
  <td>{title}</td>
  <td>{badge}</td>
  <td>{category}</td>
  <td style="text-align:right;color:{color}">{cvss:.1}</td>
  <td>{remediation}</td>
  <td class="mono ts">{ts}</td>
</tr>"#,
                id_short = id_short,
                title = html_escape(&f.title),
                badge = badge,
                category = html_escape(&f.category.to_string()),
                color = Self::severity_color(&f.severity),
                cvss = f.cvss_score,
                remediation = html_escape(&f.remediation),
                ts = ts,
            ));
        }

        // ── timeline rows ──
        let mut timeline_rows = String::new();
        for event in &report.timeline {
            let ts = event.timestamp.format("%H:%M:%S");
            timeline_rows.push_str(&format!(
                r#"<li><span class="ts">[{ts}]</span> <strong>{etype}</strong> — {detail}</li>"#,
                ts = ts,
                etype = html_escape(&event.event_type.to_string()),
                detail = html_escape(&event.detail),
            ));
        }

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{ font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 2rem;
         background: #f8fafc; color: #1e293b; font-size: 14px; }}
  h1 {{ font-size: 1.6rem; margin: 0 0 0.25rem; }}
  h2 {{ font-size: 1.1rem; margin: 2rem 0 0.75rem; border-bottom: 2px solid #e2e8f0; padding-bottom: 0.4rem; }}
  .meta {{ color: #64748b; font-size: 0.85rem; margin-bottom: 2rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
           border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  thead th {{ background: #1e293b; color: #f1f5f9; padding: 10px 12px; text-align: left;
              font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: .05em; }}
  tbody tr:nth-child(even) {{ background: #f8fafc; }}
  tbody tr:hover {{ background: #e0f2fe; }}
  td, th {{ padding: 9px 12px; vertical-align: top; border-bottom: 1px solid #e2e8f0; }}
  .mono {{ font-family: ui-monospace, monospace; font-size: 0.8rem; }}
  .ts {{ color: #64748b; }}
  /* severity badges */
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 9999px;
            font-size: 0.75rem; font-weight: 700; color: #fff; }}
  .badge-critical {{ background: #dc2626; }}
  .badge-high     {{ background: #ea580c; }}
  .badge-medium   {{ background: #ca8a04; }}
  .badge-low      {{ background: #2563eb; }}
  .badge-info     {{ background: #6b7280; }}
  /* summary card */
  .summary {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .card {{ background: #fff; border-radius: 8px; padding: 1rem 1.5rem;
           box-shadow: 0 1px 3px rgba(0,0,0,.08); min-width: 110px; text-align: center; }}
  .card .count {{ font-size: 2rem; font-weight: 700; line-height: 1; }}
  .card .label  {{ font-size: 0.75rem; color: #64748b; margin-top: 4px; }}
  /* timeline */
  ul.timeline {{ list-style: none; padding: 0; margin: 0; }}
  ul.timeline li {{ padding: 6px 0; border-bottom: 1px solid #e2e8f0; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p class="meta">Target: <strong>{target}</strong> &nbsp;|&nbsp; Generated: {generated_at}</p>

<h2>Attack Summary</h2>
<div class="summary">
  <div class="card"><div class="count">{total}</div><div class="label">Total</div></div>
  <div class="card"><div class="count" style="color:#dc2626">{critical}</div><div class="label">Critical</div></div>
  <div class="card"><div class="count" style="color:#ea580c">{high}</div><div class="label">High</div></div>
  <div class="card"><div class="count" style="color:#ca8a04">{medium}</div><div class="label">Medium</div></div>
  <div class="card"><div class="count" style="color:#2563eb">{low}</div><div class="label">Low</div></div>
  <div class="card"><div class="count" style="color:#6b7280">{info}</div><div class="label">Info</div></div>
</div>

<h2>Findings</h2>
<table>
  <thead>
    <tr>
      <th>ID</th>
      <th>Title</th>
      <th>Severity</th>
      <th>Category</th>
      <th>CVSS</th>
      <th>Remediation</th>
      <th>Timestamp</th>
    </tr>
  </thead>
  <tbody>
    {findings_rows}
  </tbody>
</table>

<h2>Timeline</h2>
<ul class="timeline">
  {timeline_rows}
</ul>

</body>
</html>"#,
            title = html_escape(&report.metadata.title),
            target = html_escape(&report.metadata.target),
            generated_at = generated_at,
            total = report.findings.len(),
            critical = critical,
            high = high,
            medium = medium,
            low = low,
            info = info,
            findings_rows = findings_rows,
            timeline_rows = timeline_rows,
        );

        Ok(html)
    }
}

/// Escape the five XML/HTML special characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::builder::ReportBuilder;
    use crate::output::finding::{Finding, FindingCategory, Severity};

    fn sample_report() -> Report {
        let finding = Finding::new(
            "Default SSH Credentials Found",
            "SSH accepts root:root",
            Severity::Critical,
            FindingCategory::WeakAuthentication,
            "Rotate credentials immediately",
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        );
        ReportBuilder::new()
            .title("Zeus Audit")
            .target("192.168.1.1")
            .add_finding(finding)
            .build(0.0)
    }

    #[test]
    fn html_renderer_contains_findings_table() {
        let report = sample_report();
        let html = HtmlRenderer.render(&report).unwrap();
        assert!(html.contains("<table>"), "expected <table> tag");
        assert!(
            html.contains("Default SSH Credentials Found"),
            "expected finding title"
        );
    }

    #[test]
    fn html_renderer_includes_severity_badge() {
        let report = sample_report();
        let html = HtmlRenderer.render(&report).unwrap();
        assert!(
            html.contains(r#"class="badge badge-critical""#),
            "expected critical badge class"
        );
        assert!(html.contains("CRITICAL"), "expected severity label");
    }

    #[test]
    fn html_renderer_is_valid_html_structure() {
        let report = sample_report();
        let html = HtmlRenderer.render(&report).unwrap();
        assert!(html.contains("<html"), "missing <html>");
        assert!(html.contains("<body>"), "missing <body>");
        assert!(html.contains("</body>"), "missing </body>");
        assert!(html.contains("</html>"), "missing </html>");
        assert!(html.contains("<table>"), "missing <table>");
    }
}
