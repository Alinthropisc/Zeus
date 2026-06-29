//! Severity scoring and false-positive rate calculation.

use uuid::Uuid;

use crate::finding::{Finding, Severity};

/// Maps CVSS base scores to [`Severity`] levels and computes false-positive rates.
pub struct SeverityScorer;

impl SeverityScorer {
    /// Map a CVSS base score to a [`Severity`] level using CVSS v3.1 ranges.
    ///
    /// | Score range   | Severity |
    /// |---------------|----------|
    /// | 9.0 – 10.0    | Critical |
    /// | 7.0 – 8.9     | High     |
    /// | 4.0 – 6.9     | Medium   |
    /// | 0.1 – 3.9     | Low      |
    /// | 0.0           | Info     |
    pub fn score(finding: &Finding) -> Severity {
        Self::score_from_value(finding.cvss_score)
    }

    /// Score directly from a raw f32 CVSS value.
    pub fn score_from_value(cvss: f32) -> Severity {
        if cvss >= 9.0 {
            Severity::Critical
        } else if cvss >= 7.0 {
            Severity::High
        } else if cvss >= 4.0 {
            Severity::Medium
        } else if cvss >= 0.1 {
            Severity::Low
        } else {
            Severity::Info
        }
    }

    /// Compute the false-positive rate.
    ///
    /// Returns `confirmed.len() / findings.len()` as a value in [0.0, 1.0].
    /// Returns `0.0` when `findings` is empty to avoid division by zero.
    ///
    /// # Arguments
    ///
    /// * `findings` — all findings produced by the session.
    /// * `confirmed` — UUIDs of findings that have been manually confirmed as
    ///   true positives.
    pub fn false_positive_rate(findings: &[Finding], confirmed: &[Uuid]) -> f32 {
        if findings.is_empty() {
            return 0.0;
        }

        let confirmed_count = findings
            .iter()
            .filter(|f| confirmed.contains(&f.id))
            .count();

        confirmed_count as f32 / findings.len() as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_ranges() {
        assert_eq!(SeverityScorer::score_from_value(9.8), Severity::Critical);
        assert_eq!(SeverityScorer::score_from_value(9.0), Severity::Critical);
        assert_eq!(SeverityScorer::score_from_value(8.9), Severity::High);
        assert_eq!(SeverityScorer::score_from_value(7.0), Severity::High);
        assert_eq!(SeverityScorer::score_from_value(6.9), Severity::Medium);
        assert_eq!(SeverityScorer::score_from_value(4.0), Severity::Medium);
        assert_eq!(SeverityScorer::score_from_value(3.9), Severity::Low);
        assert_eq!(SeverityScorer::score_from_value(0.1), Severity::Low);
        assert_eq!(SeverityScorer::score_from_value(0.0), Severity::Info);
    }

    #[test]
    fn fp_rate_empty_slice() {
        assert_eq!(SeverityScorer::false_positive_rate(&[], &[]), 0.0);
    }
}
