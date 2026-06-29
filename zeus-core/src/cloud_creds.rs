//! Cloud Credentials Module — test and enumerate cloud authentication endpoints.
//!
//! Implements:
//! - **Adapter pattern**: [`CloudAuthAdapter`] unifies AWS IAM, GCP, and Azure AD APIs.
//! - **Chain of Responsibility**: [`CloudCredChecker`] tries adapters in order.
//! - [`CloudCredential`] models the distinct auth formats used by major cloud providers.
//!
//! All `verify` calls are **simulated** (no real HTTP) and are designed to be
//! replaced by live HTTP backends in production.

use async_trait::async_trait;

use crate::Credential;

// ── CloudProvider ─────────────────────────────────────────────────────────────

/// Identifies the cloud platform associated with a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudProvider {
    /// Amazon Web Services.
    Aws,
    /// Google Cloud Platform.
    Gcp,
    /// Microsoft Azure Active Directory.
    Azure,
    /// Generic / unknown provider.
    Generic,
}

impl CloudProvider {
    /// Return a human-readable label for the provider.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Aws => "AWS",
            Self::Gcp => "GCP",
            Self::Azure => "Azure",
            Self::Generic => "Generic",
        }
    }
}

// ── CloudCredential ───────────────────────────────────────────────────────────

/// A cloud authentication credential in one of the supported formats.
#[derive(Debug, Clone)]
pub enum CloudCredential {
    /// AWS IAM long-term or short-term (STS) credential.
    AwsIam {
        /// Access key ID, typically starts with `AKIA` or `ASIA`.
        access_key_id: String,
        /// Secret access key.
        secret_access_key: String,
        /// Optional STS session token (required for temporary credentials).
        session_token: Option<String>,
    },
    /// GCP service account key metadata.
    GcpServiceAccount {
        /// GCP project ID.
        project_id: String,
        /// Service account email address.
        client_email: String,
        /// Private key ID (from the JSON key file).
        private_key_id: String,
    },
    /// Azure Active Directory application credential.
    AzureAd {
        /// Azure AD tenant (directory) ID.
        tenant_id: String,
        /// Application (client) ID.
        client_id: String,
        /// Client secret value.
        client_secret: String,
    },
    /// Generic API key passed via an HTTP header.
    ApiKey {
        /// Provider name (e.g. `"stripe"`, `"sendgrid"`).
        provider: String,
        /// The raw API key value.
        key: String,
        /// HTTP header name used to transmit the key (e.g. `"X-API-Key"`).
        header_name: String,
    },
}

impl CloudCredential {
    /// Return the cloud provider associated with this credential.
    pub fn provider(&self) -> CloudProvider {
        match self {
            Self::AwsIam { .. } => CloudProvider::Aws,
            Self::GcpServiceAccount { .. } => CloudProvider::Gcp,
            Self::AzureAd { .. } => CloudProvider::Azure,
            Self::ApiKey { .. } => CloudProvider::Generic,
        }
    }

    /// Convert to a generic [`Credential`] for use with the core engine.
    ///
    /// The mapping depends on the credential type:
    /// - **AWS IAM**: `username = access_key_id`, `password = secret_access_key`
    /// - **GCP**: `username = client_email`, `password = private_key_id`
    /// - **Azure AD**: `username = client_id`, `password = client_secret`
    /// - **ApiKey**: `username = header_name`, `password = key`
    pub fn to_basic_credential(&self) -> Credential {
        match self {
            Self::AwsIam { access_key_id, secret_access_key, .. } => {
                Credential::new(access_key_id.clone(), secret_access_key.clone())
            }
            Self::GcpServiceAccount { client_email, private_key_id, .. } => {
                Credential::new(client_email.clone(), private_key_id.clone())
            }
            Self::AzureAd { client_id, client_secret, .. } => {
                Credential::new(client_id.clone(), client_secret.clone())
            }
            Self::ApiKey { header_name, key, .. } => {
                Credential::new(header_name.clone(), key.clone())
            }
        }
    }

    /// Return a log-safe masked representation of the credential.
    ///
    /// Secrets are truncated and padded with asterisks, e.g.
    /// `AKIA****XXXX` for an AWS access key ID.
    pub fn mask(&self) -> String {
        fn mask_secret(s: &str) -> String {
            let len = s.len();
            if len <= 8 {
                return "*".repeat(len);
            }
            let prefix = &s[..4];
            let suffix = &s[len - 4..];
            format!("{}****{}", prefix, suffix)
        }

        match self {
            Self::AwsIam { access_key_id, .. } => {
                format!("AWS IAM key={}", mask_secret(access_key_id))
            }
            Self::GcpServiceAccount { client_email, .. } => {
                let at_pos = client_email.find('@').unwrap_or(client_email.len());
                format!("GCP SA email={}@***", &client_email[..at_pos.min(6)])
            }
            Self::AzureAd { client_id, .. } => {
                format!("Azure AD client_id={}", mask_secret(client_id))
            }
            Self::ApiKey { provider, key, .. } => {
                format!("ApiKey provider={} key={}", provider, mask_secret(key))
            }
        }
    }
}

// ── CloudAuthResult ───────────────────────────────────────────────────────────

/// Result of a cloud credential verification attempt.
#[derive(Debug)]
pub struct CloudAuthResult {
    /// The credential that was tested.
    pub credential: CloudCredential,
    /// Whether the credential authenticated successfully.
    pub valid: bool,
    /// IAM/RBAC permissions confirmed for this credential.
    pub permissions: Vec<String>,
    /// Cloud account / project / subscription identifier (if available).
    pub account_id: Option<String>,
    /// Error message if verification failed.
    pub error: Option<String>,
}

impl CloudAuthResult {
    fn success(
        credential: CloudCredential,
        permissions: Vec<String>,
        account_id: impl Into<String>,
    ) -> Self {
        Self {
            credential,
            valid: true,
            permissions,
            account_id: Some(account_id.into()),
            error: None,
        }
    }

    fn failure(credential: CloudCredential, reason: impl Into<String>) -> Self {
        Self {
            credential,
            valid: false,
            permissions: Vec::new(),
            account_id: None,
            error: Some(reason.into()),
        }
    }
}

// ── Adapter pattern: CloudAuthAdapter ────────────────────────────────────────

/// Verifies a [`CloudCredential`] against a specific cloud provider's API.
///
/// Each implementor adapts a different provider's authentication surface to
/// a common interface, allowing [`CloudCredChecker`] to remain provider-agnostic.
#[async_trait]
pub trait CloudAuthAdapter: Send + Sync {
    /// The cloud provider this adapter handles.
    fn provider(&self) -> CloudProvider;

    /// Human-readable adapter name (used in logs and reports).
    fn name(&self) -> &'static str;

    /// Verify the credential.
    ///
    /// Implementations should return [`CloudAuthResult::failure`] (not `Err`)
    /// for authentication failures; errors are reserved for transport/network
    /// issues.
    async fn verify(&self, cred: &CloudCredential) -> CloudAuthResult;
}

// ── AwsIamAdapter ─────────────────────────────────────────────────────────────

/// Simulated AWS IAM credential verifier.
///
/// In production this would call `sts:GetCallerIdentity`.
pub struct AwsIamAdapter;

#[async_trait]
impl CloudAuthAdapter for AwsIamAdapter {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }

    fn name(&self) -> &'static str {
        "aws-iam"
    }

    async fn verify(&self, cred: &CloudCredential) -> CloudAuthResult {
        match cred {
            CloudCredential::AwsIam { access_key_id, .. } => {
                // Simulated rule: keys starting with "AKIA" and length ≥ 20
                // are treated as valid in this stub.
                if access_key_id.starts_with("AKIA") && access_key_id.len() >= 20 {
                    CloudAuthResult::success(
                        cred.clone(),
                        vec!["sts:GetCallerIdentity".into(), "s3:ListBuckets".into()],
                        "123456789012",
                    )
                } else {
                    CloudAuthResult::failure(
                        cred.clone(),
                        "InvalidClientTokenId: access key format invalid",
                    )
                }
            }
            other => CloudAuthResult::failure(
                other.clone(),
                "AwsIamAdapter: credential is not an AWS IAM key",
            ),
        }
    }
}

// ── GcpAdapter ────────────────────────────────────────────────────────────────

/// Simulated GCP service account verifier.
///
/// In production this would call `oauth2/v4/token` with a signed JWT.
pub struct GcpAdapter;

#[async_trait]
impl CloudAuthAdapter for GcpAdapter {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    fn name(&self) -> &'static str {
        "gcp-service-account"
    }

    async fn verify(&self, cred: &CloudCredential) -> CloudAuthResult {
        match cred {
            CloudCredential::GcpServiceAccount { client_email, project_id, .. } => {
                // Simulated: service accounts ending in @<project>.iam.gserviceaccount.com are valid.
                if client_email.ends_with(".iam.gserviceaccount.com") {
                    CloudAuthResult::success(
                        cred.clone(),
                        vec!["storage.objects.list".into(), "iam.serviceAccounts.get".into()],
                        project_id.clone(),
                    )
                } else {
                    CloudAuthResult::failure(
                        cred.clone(),
                        "invalid_grant: service account email format invalid",
                    )
                }
            }
            other => CloudAuthResult::failure(
                other.clone(),
                "GcpAdapter: credential is not a GCP service account",
            ),
        }
    }
}

// ── AzureAdAdapter ────────────────────────────────────────────────────────────

/// Simulated Azure AD client-credentials verifier.
///
/// In production this would POST to `login.microsoftonline.com/<tenant>/oauth2/v2.0/token`.
pub struct AzureAdAdapter;

#[async_trait]
impl CloudAuthAdapter for AzureAdAdapter {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    fn name(&self) -> &'static str {
        "azure-ad"
    }

    async fn verify(&self, cred: &CloudCredential) -> CloudAuthResult {
        match cred {
            CloudCredential::AzureAd { tenant_id, client_id, client_secret } => {
                // Simulated: non-empty fields with a client_secret longer than 8 chars → valid.
                if !tenant_id.is_empty()
                    && !client_id.is_empty()
                    && client_secret.len() > 8
                {
                    CloudAuthResult::success(
                        cred.clone(),
                        vec!["User.Read".into(), "Directory.Read.All".into()],
                        tenant_id.clone(),
                    )
                } else {
                    CloudAuthResult::failure(
                        cred.clone(),
                        "AADSTS7000215: Invalid client secret provided",
                    )
                }
            }
            other => CloudAuthResult::failure(
                other.clone(),
                "AzureAdAdapter: credential is not an Azure AD credential",
            ),
        }
    }
}

// ── Chain of Responsibility: CloudCredChecker ─────────────────────────────────

/// Checks a [`CloudCredential`] by walking a chain of [`CloudAuthAdapter`]s.
///
/// Each adapter is tried in order. The first adapter whose
/// [`CloudAuthAdapter::provider`] matches the credential's provider is used.
/// If no adapter matches, a generic failure result is returned.
pub struct CloudCredChecker {
    adapters: Vec<Box<dyn CloudAuthAdapter>>,
}

impl CloudCredChecker {
    /// Create an empty checker with no adapters.
    pub fn new() -> Self {
        Self { adapters: Vec::new() }
    }

    /// Append an adapter to the chain (builder pattern).
    pub fn add_adapter(mut self, adapter: Box<dyn CloudAuthAdapter>) -> Self {
        self.adapters.push(adapter);
        self
    }

    /// Pre-configured checker with AWS, GCP, and Azure AD adapters.
    pub fn with_all_providers() -> Self {
        Self::new()
            .add_adapter(Box::new(AwsIamAdapter))
            .add_adapter(Box::new(GcpAdapter))
            .add_adapter(Box::new(AzureAdAdapter))
    }

    /// Verify a single credential using the first matching adapter.
    ///
    /// If no adapter handles the credential's provider, returns a failure
    /// result indicating no handler was found.
    pub async fn check(&self, cred: &CloudCredential) -> CloudAuthResult {
        let provider = cred.provider();
        for adapter in &self.adapters {
            if adapter.provider() == provider {
                return adapter.verify(cred).await;
            }
        }
        CloudAuthResult::failure(
            cred.clone(),
            format!("no adapter registered for provider {:?}", provider),
        )
    }

    /// Verify a batch of credentials, returning one result per credential.
    pub async fn check_all(&self, creds: &[CloudCredential]) -> Vec<CloudAuthResult> {
        let mut results = Vec::with_capacity(creds.len());
        for cred in creds {
            results.push(self.check(cred).await);
        }
        results
    }
}

impl Default for CloudCredChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ── CloudWordlistSource ───────────────────────────────────────────────────────

/// Generates sample cloud credential patterns commonly seen during audits.
///
/// These are intentionally obvious / default values that should never appear
/// in production environments.
pub struct CloudWordlistSource;

impl CloudWordlistSource {
    /// Return a set of AWS IAM keys that match common default or test patterns.
    pub fn common_aws_keys() -> Vec<CloudCredential> {
        // Well-known placeholder / example keys seen in public repos and docs.
        vec![
            CloudCredential::AwsIam {
                access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
                secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
                session_token: None,
            },
            CloudCredential::AwsIam {
                access_key_id: "AKIAI44QH8DHBEXAMPLE".into(),
                secret_access_key: "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY".into(),
                session_token: None,
            },
            CloudCredential::AwsIam {
                access_key_id: "AKIATEST00000EXAMPLE".into(),
                secret_access_key: "testSecretKey1234567890abcdefEXAMPLEKEY".into(),
                session_token: None,
            },
        ]
    }

    /// Return GCP service account emails that match common default naming patterns.
    pub fn common_gcp_emails() -> Vec<CloudCredential> {
        vec![
            CloudCredential::GcpServiceAccount {
                project_id: "my-project".into(),
                client_email: "default@my-project.iam.gserviceaccount.com".into(),
                private_key_id: "key-id-placeholder-001".into(),
            },
            CloudCredential::GcpServiceAccount {
                project_id: "test-project".into(),
                client_email: "firebase-adminsdk@test-project.iam.gserviceaccount.com".into(),
                private_key_id: "key-id-placeholder-002".into(),
            },
            CloudCredential::GcpServiceAccount {
                project_id: "dev-project".into(),
                client_email: "compute@developer.gserviceaccount.com".into(),
                private_key_id: "key-id-placeholder-003".into(),
            },
        ]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── CloudCredential ───────────────────────────────────────────────────────

    #[test]
    fn provider_discrimination() {
        assert_eq!(
            CloudCredential::AwsIam {
                access_key_id: "x".into(),
                secret_access_key: "y".into(),
                session_token: None,
            }
            .provider(),
            CloudProvider::Aws
        );

        assert_eq!(
            CloudCredential::GcpServiceAccount {
                project_id: "p".into(),
                client_email: "e".into(),
                private_key_id: "k".into(),
            }
            .provider(),
            CloudProvider::Gcp
        );

        assert_eq!(
            CloudCredential::AzureAd {
                tenant_id: "t".into(),
                client_id: "c".into(),
                client_secret: "s".into(),
            }
            .provider(),
            CloudProvider::Azure
        );
    }

    #[test]
    fn to_basic_credential_aws() {
        let cred = CloudCredential::AwsIam {
            access_key_id: "AKIATEST".into(),
            secret_access_key: "secretXYZ".into(),
            session_token: None,
        };
        let basic = cred.to_basic_credential();
        assert_eq!(basic.username, "AKIATEST");
        assert_eq!(basic.password, "secretXYZ");
    }

    #[test]
    fn mask_hides_secret_interior() {
        let cred = CloudCredential::AwsIam {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "secret".into(),
            session_token: None,
        };
        let masked = cred.mask();
        assert!(masked.contains("AKIA"), "prefix should be visible");
        assert!(masked.contains("****"), "middle should be masked");
        assert!(!masked.contains("SFODNN7EXAM"), "interior should be hidden");
    }

    // ── AwsIamAdapter ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn aws_adapter_accepts_valid_akia_key() {
        let adapter = AwsIamAdapter;
        let cred = CloudCredential::AwsIam {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        };
        let result = adapter.verify(&cred).await;
        assert!(result.valid, "expected valid for AKIA key");
        assert!(!result.permissions.is_empty());
        assert!(result.account_id.is_some());
    }

    #[tokio::test]
    async fn aws_adapter_rejects_short_key() {
        let adapter = AwsIamAdapter;
        let cred = CloudCredential::AwsIam {
            access_key_id: "AKIASHORT".into(),
            secret_access_key: "any".into(),
            session_token: None,
        };
        let result = adapter.verify(&cred).await;
        assert!(!result.valid);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn aws_adapter_rejects_wrong_type() {
        let adapter = AwsIamAdapter;
        let cred = CloudCredential::ApiKey {
            provider: "stripe".into(),
            key: "sk_test_123".into(),
            header_name: "Authorization".into(),
        };
        let result = adapter.verify(&cred).await;
        assert!(!result.valid);
    }

    // ── GcpAdapter ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn gcp_adapter_accepts_valid_service_account() {
        let adapter = GcpAdapter;
        let cred = CloudCredential::GcpServiceAccount {
            project_id: "my-project".into(),
            client_email: "svc@my-project.iam.gserviceaccount.com".into(),
            private_key_id: "abc123".into(),
        };
        let result = adapter.verify(&cred).await;
        assert!(result.valid);
    }

    #[tokio::test]
    async fn gcp_adapter_rejects_bad_email() {
        let adapter = GcpAdapter;
        let cred = CloudCredential::GcpServiceAccount {
            project_id: "proj".into(),
            client_email: "notaserviceaccount@gmail.com".into(),
            private_key_id: "k".into(),
        };
        let result = adapter.verify(&cred).await;
        assert!(!result.valid);
    }

    // ── AzureAdAdapter ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn azure_adapter_accepts_long_secret() {
        let adapter = AzureAdAdapter;
        let cred = CloudCredential::AzureAd {
            tenant_id: "tenant-uuid".into(),
            client_id: "client-uuid".into(),
            client_secret: "SuperSecretValue123!".into(),
        };
        let result = adapter.verify(&cred).await;
        assert!(result.valid);
        assert!(result.permissions.contains(&"User.Read".to_string()));
    }

    #[tokio::test]
    async fn azure_adapter_rejects_short_secret() {
        let adapter = AzureAdAdapter;
        let cred = CloudCredential::AzureAd {
            tenant_id: "t".into(),
            client_id: "c".into(),
            client_secret: "short".into(),
        };
        let result = adapter.verify(&cred).await;
        assert!(!result.valid);
    }

    // ── CloudCredChecker (Chain of Responsibility) ────────────────────────────

    #[tokio::test]
    async fn checker_routes_to_correct_adapter() {
        let checker = CloudCredChecker::with_all_providers();

        let aws_cred = CloudCredential::AwsIam {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "secret".into(),
            session_token: None,
        };
        let result = checker.check(&aws_cred).await;
        // Valid AKIA key → should succeed via AwsIamAdapter.
        assert!(result.valid);

        let gcp_cred = CloudCredential::GcpServiceAccount {
            project_id: "p".into(),
            client_email: "svc@p.iam.gserviceaccount.com".into(),
            private_key_id: "k".into(),
        };
        let result = checker.check(&gcp_cred).await;
        assert!(result.valid);
    }

    #[tokio::test]
    async fn checker_returns_failure_for_unregistered_provider() {
        let checker = CloudCredChecker::new(); // no adapters
        let cred = CloudCredential::AwsIam {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "secret".into(),
            session_token: None,
        };
        let result = checker.check(&cred).await;
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("no adapter registered"));
    }

    #[tokio::test]
    async fn checker_check_all_returns_one_result_per_cred() {
        let checker = CloudCredChecker::with_all_providers();
        let creds = CloudWordlistSource::common_aws_keys();
        let results = checker.check_all(&creds).await;
        assert_eq!(results.len(), creds.len());
    }

    // ── CloudWordlistSource ───────────────────────────────────────────────────

    #[test]
    fn wordlist_aws_keys_not_empty() {
        let keys = CloudWordlistSource::common_aws_keys();
        assert!(!keys.is_empty());
        for key in &keys {
            assert_eq!(key.provider(), CloudProvider::Aws);
        }
    }

    #[test]
    fn wordlist_gcp_emails_not_empty() {
        let emails = CloudWordlistSource::common_gcp_emails();
        assert!(!emails.is_empty());
        for email in &emails {
            assert_eq!(email.provider(), CloudProvider::Gcp);
        }
    }
}
