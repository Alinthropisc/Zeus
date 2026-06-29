//! Payload builders for DefectDojo and JIRA integrations.
//!
//! No HTTP calls are made here — callers supply the transport (e.g. reqwest).
//! This keeps the module fully testable without a live server.

use crate::finding::{Finding, Severity};

// ─────────────────────────────────────────────────────────────────────────────
// DefectDojo
// ─────────────────────────────────────────────────────────────────────────────

/// Connection parameters for a DefectDojo instance.
#[derive(Debug, Clone)]
pub struct DefectDojoConfig {
    pub base_url: String,
    pub api_token: String,
    pub engagement_id: u32,
    pub test_type: String,
}

impl DefectDojoConfig {
    pub fn new(
        base_url: impl Into<String>,
        api_token: impl Into<String>,
        engagement_id: u32,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            api_token: api_token.into(),
            engagement_id,
            test_type: "Zeus Scan".to_string(),
        }
    }
}

/// Builds DefectDojo finding payloads; does not perform network I/O.
#[derive(Debug, Clone)]
pub struct DefectDojoClient {
    pub config: DefectDojoConfig,
}

impl DefectDojoClient {
    pub fn new(config: DefectDojoConfig) -> Self {
        Self { config }
    }

    /// Convert a [`Finding`] to the DefectDojo REST finding payload.
    pub fn finding_to_payload(
        finding: &Finding,
        config: &DefectDojoConfig,
    ) -> serde_json::Value {
        let severity_str = match finding.severity {
            Severity::Critical => "Critical",
            Severity::High     => "High",
            Severity::Medium   => "Medium",
            Severity::Low      => "Low",
            Severity::Info     => "Info",
        };

        serde_json::json!({
            "title":        finding.title,
            "description":  finding.description,
            "severity":     severity_str,
            "engagement":   config.engagement_id,
            "test_type":    config.test_type,
            "active":       true,
            "verified":     false,
            "cvssv3_score": finding.cvss_score,
            "date":         finding.timestamp.format("%Y-%m-%d").to_string(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JIRA
// ─────────────────────────────────────────────────────────────────────────────

/// Connection and project parameters for a JIRA Cloud/Server instance.
#[derive(Debug, Clone)]
pub struct JiraConfig {
    pub base_url: String,
    pub username: String,
    pub api_token: String,
    pub project_key: String,
    pub issue_type: String,
    pub severity_label_prefix: String,
}

impl JiraConfig {
    pub fn new(
        base_url: impl Into<String>,
        username: impl Into<String>,
        api_token: impl Into<String>,
        project_key: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            username: username.into(),
            api_token: api_token.into(),
            project_key: project_key.into(),
            issue_type: "Bug".to_string(),
            severity_label_prefix: "security-".to_string(),
        }
    }
}

/// Builds JIRA issue creation payloads; does not perform network I/O.
#[derive(Debug, Clone)]
pub struct JiraClient {
    pub config: JiraConfig,
}

impl JiraClient {
    pub fn new(config: JiraConfig) -> Self {
        Self { config }
    }

    /// Map a [`Severity`] to the JIRA priority name.
    fn severity_to_priority(severity: &Severity) -> &'static str {
        match severity {
            Severity::Critical => "Highest",
            Severity::High     => "High",
            Severity::Medium   => "Medium",
            Severity::Low      => "Low",
            Severity::Info     => "Lowest",
        }
    }

    /// Convert a [`Finding`] to the JIRA issue creation payload (Atlassian Document Format body).
    pub fn finding_to_payload(
        finding: &Finding,
        config: &JiraConfig,
    ) -> serde_json::Value {
        let severity_label = format!(
            "{}{}",
            config.severity_label_prefix,
            finding.severity.to_string().to_lowercase()
        );

        let summary = format!(
            "[Zeus] {}: {}",
            finding.severity,
            finding.title,
        );

        let description_doc = serde_json::json!({
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        { "type": "text", "text": finding.description.clone() }
                    ]
                },
                {
                    "type": "paragraph",
                    "content": [
                        { "type": "text", "text": "Remediation: ", "marks": [{ "type": "strong" }] },
                        { "type": "text", "text": finding.remediation.clone() }
                    ]
                },
                {
                    "type": "paragraph",
                    "content": [
                        { "type": "text", "text": format!("CVSS Score: {:.1}", finding.cvss_score) }
                    ]
                }
            ]
        });

        serde_json::json!({
            "fields": {
                "project":     { "key": config.project_key },
                "summary":     summary,
                "description": description_doc,
                "issuetype":   { "name": config.issue_type },
                "labels":      [severity_label, "zeus-finding"],
                "priority":    { "name": Self::severity_to_priority(&finding.severity) }
            }
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, FindingCategory, Severity};

    fn critical_finding() -> Finding {
        Finding::new(
            "Default SSH Credentials Found",
            "SSH accepts root:root on port 22",
            Severity::Critical,
            FindingCategory::WeakAuthentication,
            "Rotate credentials and disable root login",
            9.1,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
    }

    fn dd_config() -> DefectDojoConfig {
        DefectDojoConfig::new("https://dojo.example.com", "token-abc", 42)
    }

    fn jira_config() -> JiraConfig {
        JiraConfig::new("https://jira.example.com", "user@example.com", "jira-token", "SEC")
    }

    #[test]
    fn defectdojo_payload_includes_severity() {
        let finding = critical_finding();
        let payload = DefectDojoClient::finding_to_payload(&finding, &dd_config());
        assert_eq!(payload["severity"], "Critical");
    }

    #[test]
    fn defectdojo_payload_sets_engagement_id() {
        let finding = critical_finding();
        let payload = DefectDojoClient::finding_to_payload(&finding, &dd_config());
        assert_eq!(payload["engagement"], 42u32);
    }

    #[test]
    fn jira_payload_summary_includes_severity() {
        let finding = critical_finding();
        let payload = JiraClient::finding_to_payload(&finding, &jira_config());
        let summary = payload["fields"]["summary"].as_str().unwrap_or("");
        assert!(summary.contains("CRITICAL"), "expected severity in summary: {summary}");
    }

    #[test]
    fn jira_priority_maps_critical_to_highest() {
        let finding = critical_finding();
        let payload = JiraClient::finding_to_payload(&finding, &jira_config());
        let priority = payload["fields"]["priority"]["name"].as_str().unwrap_or("");
        assert_eq!(priority, "Highest");
    }

    #[test]
    fn jira_labels_include_prefix() {
        let finding = critical_finding();
        let payload = JiraClient::finding_to_payload(&finding, &jira_config());
        let labels = payload["fields"]["labels"].as_array().unwrap();
        let has_prefixed = labels.iter().any(|l| {
            l.as_str().unwrap_or("").starts_with("security-")
        });
        assert!(has_prefixed, "expected a label with 'security-' prefix");
    }
}
