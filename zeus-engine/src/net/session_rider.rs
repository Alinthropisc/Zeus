//! Session-riding State Machine — models a realistic user session so that
//! exploit traffic is preceded by genuine authenticated activity, evading
//! behavioural-anomaly detectors that flag "cold-start" attack patterns.
//!
//! # Design
//! - **State Machine** — [`SessionState`] encodes every phase from
//!   unauthenticated through to exfiltration.
//! - **Decorator** — [`SessionRider`] holds a [`BehaviorProfile`] and sleeps
//!   between transitions to mimic human pacing.

use crate::behavioral::BehaviorProfile;
use crate::http_client::HttpClient;
use anyhow::Result;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};

// ──────────────────────────────────────────────────────────────────────────────
// Error type
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid state transition: {from} → {event}")]
    InvalidTransition { from: &'static str, event: &'static str },

    #[error("HTTP error during {action}: {source}")]
    Http {
        action: &'static str,
        #[source]
        source: anyhow::Error,
    },

    #[error("authentication failed: server returned {status}")]
    AuthFailed { status: u16 },

    #[error("session expired unexpectedly")]
    SessionExpired,
}

// ──────────────────────────────────────────────────────────────────────────────
// State Machine types
// ──────────────────────────────────────────────────────────────────────────────

/// All possible states in the session-riding state machine.
#[derive(Debug)]
pub enum SessionState {
    /// No credentials held; initial state.
    Unauthenticated,
    /// Login request in flight or credentials being submitted.
    Authenticating,
    /// Successfully logged in; holds the session token and User-Agent used.
    Authenticated {
        token: String,
        user_agent: String,
    },
    /// Post-auth warm-up: visiting normal pages to generate a benign history.
    BrowsingNormal {
        pages_visited: u32,
    },
    /// Active credential-stuffing / exploit phase.
    Exploiting,
    /// Data exfiltration phase (e.g. scraping, download).
    Exfiltrating,
}

impl SessionState {
    fn label(&self) -> &'static str {
        match self {
            Self::Unauthenticated   => "Unauthenticated",
            Self::Authenticating    => "Authenticating",
            Self::Authenticated { .. } => "Authenticated",
            Self::BrowsingNormal { .. } => "BrowsingNormal",
            Self::Exploiting        => "Exploiting",
            Self::Exfiltrating      => "Exfiltrating",
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Session events and outputs
// ──────────────────────────────────────────────────────────────────────────────

/// Events that drive the state machine forward.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// A valid login was performed; carries the session token.
    LoginSuccess { token: String },
    /// The rider visited a normal page (path, HTTP status).
    PageVisit { path: String, status: u16 },
    /// An exploitable credential-reuse or session-fixation attempt.
    CredentialReuse { username: String, password: String },
    /// The server returned a 401/403 indicating the session ended.
    SessionExpiry,
}

impl SessionEvent {
    fn label(&self) -> &'static str {
        match self {
            Self::LoginSuccess { .. }   => "LoginSuccess",
            Self::PageVisit { .. }      => "PageVisit",
            Self::CredentialReuse { .. } => "CredentialReuse",
            Self::SessionExpiry         => "SessionExpiry",
        }
    }
}

/// Result of a state transition.
#[derive(Debug)]
pub enum SessionOutput {
    /// No finding; keep going.
    Continue,
    /// A research finding was produced.
    Finding(FindingType),
    /// The rider should stop (e.g. session expired, max pages reached).
    Abort(String),
}

/// Types of findings the session rider can surface.
#[derive(Debug)]
pub enum FindingType {
    /// SIEM did not alert on credential reuse after normal browsing.
    CredentialReuseUndetected { username: String },
    /// Token still valid after `pages` browsed — no session-idle timeout.
    LongLivedToken { pages: u32 },
    /// Successful transition to exfiltration without triggering an alert.
    ExfiltrationUndetected,
}

// ──────────────────────────────────────────────────────────────────────────────
// SessionRider
// ──────────────────────────────────────────────────────────────────────────────

/// Session-riding state machine.
///
/// Usage:
/// ```no_run
/// # use std::sync::Arc;
/// # use zeus_engine::net::session_rider::{SessionRider, SessionEvent};
/// # use zeus_engine::net::behavioral::BehaviorProfile;
/// # use zeus_engine::net::http_client::HttpClient;
/// # use std::time::Duration;
/// # async fn run() -> anyhow::Result<()> {
/// let client = Arc::new(HttpClient::new("https://target.example.com", Duration::from_secs(10))?);
/// let mut rider = SessionRider::new(BehaviorProfile::chrome_windows(), client);
/// rider.transition(SessionEvent::LoginSuccess { token: "tok123".into() }).await?;
/// # Ok(())
/// # }
/// ```
pub struct SessionRider {
    state: SessionState,
    profile: BehaviorProfile,
    http: Arc<HttpClient>,
    /// Maximum normal pages to visit before moving to Exploiting.
    pub warm_up_pages: u32,
}

impl SessionRider {
    /// Create a new rider in the `Unauthenticated` state.
    pub fn new(profile: BehaviorProfile, http: Arc<HttpClient>) -> Self {
        Self {
            state: SessionState::Unauthenticated,
            profile,
            http,
            warm_up_pages: 5,
        }
    }

    /// Return the current state label for logging.
    pub fn state_label(&self) -> &'static str {
        self.state.label()
    }

    /// Drive the state machine with `event`.
    ///
    /// Returns [`SessionOutput`] describing what the rider concluded after the
    /// transition, or [`SessionError`] if the event is invalid for the current
    /// state.
    pub async fn transition(
        &mut self,
        event: SessionEvent,
    ) -> Result<SessionOutput, SessionError> {
        debug!(
            state = self.state.label(),
            event = event.label(),
            "SessionRider: transition"
        );

        // Apply think-time between transitions (mimic human pacing)
        self.profile.think().await;

        match (&self.state, &event) {
            // ── Unauthenticated → Authenticating ─────────────────────────────
            (SessionState::Unauthenticated, SessionEvent::LoginSuccess { token }) => {
                let token = token.clone();
                let user_agent = self.profile.user_agent.to_string();
                info!(token = %&token[..token.len().min(8)], "SessionRider: authenticated");
                self.state = SessionState::Authenticated { token, user_agent };
                Ok(SessionOutput::Continue)
            }

            // ── Authenticated → BrowsingNormal (first PageVisit) ─────────────
            (SessionState::Authenticated { .. }, SessionEvent::PageVisit { path, status }) => {
                info!(path = %path, status = status, "SessionRider: first normal page");
                self.state = SessionState::BrowsingNormal { pages_visited: 1 };
                Ok(SessionOutput::Continue)
            }

            // ── BrowsingNormal → BrowsingNormal or Exploiting ─────────────────
            (SessionState::BrowsingNormal { pages_visited }, SessionEvent::PageVisit { path, status }) => {
                let visited = *pages_visited + 1;
                info!(path = %path, status = status, pages = visited, "SessionRider: page visit");

                if visited >= self.warm_up_pages {
                    // Warm-up complete: token has been alive for N pages — finding
                    let finding = FindingType::LongLivedToken { pages: visited };
                    self.state = SessionState::Exploiting;
                    info!("SessionRider: warm-up complete, moving to Exploiting");
                    Ok(SessionOutput::Finding(finding))
                } else {
                    self.state = SessionState::BrowsingNormal { pages_visited: visited };
                    Ok(SessionOutput::Continue)
                }
            }

            // ── Exploiting → credential-reuse finding ─────────────────────────
            (SessionState::Exploiting, SessionEvent::CredentialReuse { username, password: _ }) => {
                let username = username.clone();
                warn!(username = %username, "SessionRider: credential reuse attempted");
                // Move to Exfiltrating only if exploit "succeeds" (simulated)
                self.state = SessionState::Exfiltrating;
                Ok(SessionOutput::Finding(FindingType::CredentialReuseUndetected { username }))
            }

            // ── Exfiltrating ──────────────────────────────────────────────────
            (SessionState::Exfiltrating, SessionEvent::PageVisit { path, .. }) => {
                info!(path = %path, "SessionRider: exfiltrating");
                Ok(SessionOutput::Finding(FindingType::ExfiltrationUndetected))
            }

            // ── Session expiry from any state ─────────────────────────────────
            (_, SessionEvent::SessionExpiry) => {
                warn!("SessionRider: session expired");
                self.state = SessionState::Unauthenticated;
                Ok(SessionOutput::Abort("session expired".into()))
            }

            // ── Invalid transitions ───────────────────────────────────────────
            (state, event) => Err(SessionError::InvalidTransition {
                from: state.label(),
                event: event.label(),
            }),
        }
    }

    /// Convenience: visit a page via the HTTP client and fire a [`PageVisit`] event.
    pub async fn visit_page(&mut self, path: &str) -> Result<SessionOutput, SessionError> {
        let (status, _body) = self
            .http
            .get_with_headers(path, &self.profile.headers(0))
            .await
            .map_err(|e| SessionError::Http { action: "page_visit", source: e })?;

        self.transition(SessionEvent::PageVisit {
            path: path.to_string(),
            status,
        })
        .await
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_rider() -> SessionRider {
        let http = Arc::new(
            HttpClient::new("http://localhost:9999", Duration::from_secs(1)).unwrap(),
        );
        SessionRider::new(BehaviorProfile::firefox_linux(), http)
    }

    #[tokio::test]
    async fn unauthenticated_to_authenticated() {
        let mut rider = make_rider();
        let out = rider
            .transition(SessionEvent::LoginSuccess { token: "tok_abc".into() })
            .await
            .unwrap();
        assert!(matches!(out, SessionOutput::Continue));
        assert_eq!(rider.state_label(), "Authenticated");
    }

    #[tokio::test]
    async fn invalid_transition_returns_error() {
        let mut rider = make_rider();
        let err = rider
            .transition(SessionEvent::CredentialReuse {
                username: "admin".into(),
                password: "pass".into(),
            })
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn full_warm_up_produces_long_lived_token_finding() {
        let mut rider = make_rider();
        rider.warm_up_pages = 2;

        rider
            .transition(SessionEvent::LoginSuccess { token: "tok".into() })
            .await
            .unwrap();
        rider
            .transition(SessionEvent::PageVisit { path: "/home".into(), status: 200 })
            .await
            .unwrap();
        let out = rider
            .transition(SessionEvent::PageVisit { path: "/profile".into(), status: 200 })
            .await
            .unwrap();

        assert!(matches!(out, SessionOutput::Finding(FindingType::LongLivedToken { .. })));
        assert_eq!(rider.state_label(), "Exploiting");
    }

    #[tokio::test]
    async fn session_expiry_resets_to_unauthenticated() {
        let mut rider = make_rider();
        rider
            .transition(SessionEvent::LoginSuccess { token: "tok".into() })
            .await
            .unwrap();
        let out = rider
            .transition(SessionEvent::SessionExpiry)
            .await
            .unwrap();
        assert!(matches!(out, SessionOutput::Abort(_)));
        assert_eq!(rider.state_label(), "Unauthenticated");
    }
}
