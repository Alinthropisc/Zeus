//! Core finding types for the Zeus reporting system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single security finding discovered during a Zeus session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: FindingCategory,
    pub evidence: Vec<Evidence>,
    pub remediation: String,
    pub timestamp: DateTime<Utc>,
    pub cvss_score: f32,
    pub cvss_vector: String,
}

impl Finding {
    /// Construct a new finding with a freshly generated UUID and the current timestamp.
    pub fn new(
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        category: FindingCategory,
        remediation: impl Into<String>,
        cvss_score: f32,
        cvss_vector: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            description: description.into(),
            severity,
            category,
            evidence: Vec::new(),
            remediation: remediation.into(),
            timestamp: Utc::now(),
            cvss_score,
            cvss_vector: cvss_vector.into(),
        }
    }

    /// Append a piece of evidence to this finding.
    pub fn add_evidence(&mut self, evidence: Evidence) {
        self.evidence.push(evidence);
    }
}

/// CVSS v3.1-aligned severity levels.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

/// Taxonomy of finding categories that Zeus can detect.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingCategory {
    TimingSideChannel,
    WeakAuthentication,
    ProtocolWeakness,
    WafBypass,
    NetworkExposure,
    MisconfiguredService,
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingCategory::TimingSideChannel => write!(f, "TimingSideChannel"),
            FindingCategory::WeakAuthentication => write!(f, "WeakAuthentication"),
            FindingCategory::ProtocolWeakness => write!(f, "ProtocolWeakness"),
            FindingCategory::WafBypass => write!(f, "WafBypass"),
            FindingCategory::NetworkExposure => write!(f, "NetworkExposure"),
            FindingCategory::MisconfiguredService => write!(f, "MisconfiguredService"),
        }
    }
}

/// A single piece of supporting evidence attached to a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub data: String,
    pub timestamp: DateTime<Utc>,
}

impl Evidence {
    pub fn new(kind: EvidenceKind, data: impl Into<String>) -> Self {
        Self {
            kind,
            data: data.into(),
            timestamp: Utc::now(),
        }
    }
}

/// The type of evidence captured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceKind {
    Request,
    Response,
    Timing,
    Screenshot,
}

impl std::fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceKind::Request => write!(f, "Request"),
            EvidenceKind::Response => write!(f, "Response"),
            EvidenceKind::Timing => write!(f, "Timing"),
            EvidenceKind::Screenshot => write!(f, "Screenshot"),
        }
    }
}
