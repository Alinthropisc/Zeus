//! Builder pattern for constructing Zeus security reports.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::output::finding::Finding;

/// A fully assembled security report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub metadata: ReportMeta,
    pub findings: Vec<Finding>,
    pub timeline: Vec<TimelineEvent>,
    pub false_positive_rate: f32,
}

/// Metadata header attached to every report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMeta {
    pub title: String,
    pub target: String,
    pub session_start: Option<DateTime<Utc>>,
    pub session_end: Option<DateTime<Utc>>,
    pub generated_at: DateTime<Utc>,
}

/// A single entry on the attack timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: TimelineEventType,
    pub detail: String,
}

/// Discriminated union of timeline event kinds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimelineEventType {
    AttackStarted,
    FindingDiscovered,
    LockoutDetected,
    ProbeComplete,
}

impl std::fmt::Display for TimelineEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimelineEventType::AttackStarted => write!(f, "ATTACK_STARTED"),
            TimelineEventType::FindingDiscovered => write!(f, "FINDING_DISCOVERED"),
            TimelineEventType::LockoutDetected => write!(f, "LOCKOUT_DETECTED"),
            TimelineEventType::ProbeComplete => write!(f, "PROBE_COMPLETE"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReportBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Incrementally assembles a [`Report`] using the builder pattern.
///
/// # Example
///
/// ```rust,ignore
/// let report = ReportBuilder::new()
///     .title("Auth Audit — example.com")
///     .target("https://example.com/login")
///     .session_start(Utc::now())
///     .add_finding(finding)
///     .build(0.05);
/// ```
#[derive(Debug, Default, Clone)]
pub struct ReportBuilder {
    title: String,
    target: String,
    session_start: Option<DateTime<Utc>>,
    session_end: Option<DateTime<Utc>>,
    findings: Vec<Finding>,
    timeline: Vec<TimelineEvent>,
}

impl ReportBuilder {
    /// Create a new builder with empty defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the human-readable title of the report.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    /// Set the target (URL, IP, hostname) that was audited.
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = target.into();
        self
    }

    /// Record the wall-clock time when the session began.
    pub fn session_start(mut self, ts: DateTime<Utc>) -> Self {
        self.session_start = Some(ts);
        self
    }

    /// Record the wall-clock time when the session ended.
    pub fn session_end(mut self, ts: DateTime<Utc>) -> Self {
        self.session_end = Some(ts);
        self
    }

    /// Append a finding to the report.
    pub fn add_finding(mut self, finding: Finding) -> Self {
        // Auto-generate a timeline event for discovered findings.
        let event = TimelineEvent {
            timestamp: finding.timestamp,
            event_type: TimelineEventType::FindingDiscovered,
            detail: format!("[{}] {}", finding.severity, finding.title),
        };
        self.timeline.push(event);
        self.findings.push(finding);
        self
    }

    /// Append an arbitrary timeline event.
    pub fn add_timeline_event(mut self, event: TimelineEvent) -> Self {
        self.timeline.push(event);
        self
    }

    /// Finalise the builder into a [`Report`].
    ///
    /// `false_positive_rate` — a pre-computed rate in [0.0, 1.0]; use
    /// [`crate::scoring::SeverityScorer::false_positive_rate`] to derive it.
    pub fn build(mut self, false_positive_rate: f32) -> Report {
        // Sort timeline chronologically.
        self.timeline.sort_by_key(|e| e.timestamp);

        Report {
            metadata: ReportMeta {
                title: self.title,
                target: self.target,
                session_start: self.session_start,
                session_end: self.session_end,
                generated_at: Utc::now(),
            },
            findings: self.findings,
            timeline: self.timeline,
            false_positive_rate,
        }
    }
}
