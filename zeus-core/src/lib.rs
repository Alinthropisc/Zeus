//! Zeus Core — shared contracts between all workspace crates.

pub mod config;
pub mod context;
pub mod credential;
pub mod credential_store;
pub mod default_creds;
pub mod error;
pub mod event;
pub mod filter;
pub mod fingerprint;
pub mod lockout;
pub mod ml_classifier;
pub mod osint_wordlist;
pub mod plan;
pub mod probe;
pub mod response_analyzer;
pub mod target;
pub mod target_list;
pub mod timing;

pub use config::{AttackConfig, AttackConfigBuilder};
pub use context::ZeusContext;
pub use credential::Credential;
pub use credential_store::{CredentialStore, FoundCredential};
pub use error::ZeusError;
pub use event::ProgressEvent;
pub use filter::{
    BlacklistFilter, ClosureFilter, CredentialFilter, FilterChain, MaxLengthFilter,
    MinLengthFilter, NoSameUserPassFilter, PatternFilter, RequiresDigitFilter,
};
pub use fingerprint::{BaselineCollector, ResponseFingerprint};
pub use lockout::LockoutTracker;
pub use plan::{
    AttackPlan, AttackPlanBuilder, CredentialSpec, OutputFormat, OutputSpec, TargetSpec,
};
pub use response_analyzer::{CaptchaType, EnrichedResult, MfaType, ResponseAnalyzer};
pub use target::Target;
pub use target_list::TargetList;
pub use timing::{TimingAnalysis, TimingOracle, TimingStats};

use async_trait::async_trait;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum AttackResult {
    Success {
        credential: Credential,
        elapsed: Duration,
    },
    Failure,
    Timeout,
    RateLimit,
    Error(String),
}

impl AttackResult {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }
}

/// Strategy pattern — each protocol implements this trait.
#[async_trait]
pub trait Protocol: Send + Sync {
    fn name(&self) -> &'static str;
    fn default_port(&self) -> u16;
    fn tls_default(&self) -> bool {
        false
    }
    fn description(&self) -> &'static str {
        ""
    }
    async fn authenticate(
        &self,
        target: &Target,
        cred: &Credential,
        config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError>;
}
