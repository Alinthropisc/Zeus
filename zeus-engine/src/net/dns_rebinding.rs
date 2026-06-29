//! DNS rebinding probe — IP-based lockout bypass research.
//!
//! DNS rebinding exploits the gap between when a name is resolved and when
//! access controls are enforced.  This module simulates the two-phase attack:
//!
//! 1. Authenticate with `initial_ip` (the attacker-controlled IP that the
//!    rebind domain resolves to initially).
//! 2. Switch to `target_ip` (the real target) while reusing the same session
//!    cookie / token.  If the server checks the IP only at bind time, the
//!    session remains valid from the new IP.
//!
//! **Educational / defensive research use only.**

use anyhow::Result;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;
use zeus_core::target::Target;
use crate::net::http_client::HttpClient;

// ─── result ──────────────────────────────────────────────────────────────────

/// Outcome of the DNS rebinding simulation.
#[derive(Debug, Clone)]
pub struct RebindingResult {
    /// `true` if the server accepted the session from the rebind IP.
    pub ip_lockout_bypassable: bool,
    /// `true` if the server's CORS headers do not prevent rebinding.
    pub same_origin_bypassable: bool,
    /// Collected evidence strings explaining each conclusion.
    pub evidence: Vec<String>,
}

// ─── probe ───────────────────────────────────────────────────────────────────

/// Simulates the DNS rebinding attack lifecycle.
#[derive(Debug, Clone)]
pub struct DnsRebindingProbe {
    /// The attacker-controlled domain whose DNS TTL will be set to 0 s.
    pub rebind_domain: String,
    /// The real target IP that the domain will rebind to.
    pub target_ip: IpAddr,
    /// The initial IP the domain resolves to (attacker-controlled server).
    pub initial_ip: IpAddr,
    /// How long (ms) to wait before simulating the DNS rebind.
    pub rebind_after_ms: u64,
}

impl DnsRebindingProbe {
    /// Simulate the full DNS rebinding lifecycle:
    ///
    /// **Phase 1** — Make an authenticated request through `initial_ip`.  In a
    /// real attack this is the attacker-controlled IP; here we use `client`
    /// with the target's URL to obtain a session token.
    ///
    /// **Phase 2** — Wait `rebind_after_ms`, then replay the session token
    /// against `target_ip` directly (bypassing DNS).  If the server accepts
    /// the session from a different IP, `ip_lockout_bypassable` is `true`.
    pub async fn probe(
        &self,
        client: &HttpClient,
        target: &Target,
    ) -> Result<RebindingResult> {
        let mut evidence = Vec::new();
        debug!(
            "dns rebinding probe: domain={} initial={} target={}",
            self.rebind_domain, self.initial_ip, self.target_ip
        );

        // ── Phase 1: initial request with initial_ip ──────────────────────────
        let path = target.path.as_deref().unwrap_or("/");
        let phase1_url = format!(
            "http://{}:{}{}", self.initial_ip, target.port, path
        );

        let resp1 = client.get(&phase1_url).await?;
        let session_cookie = extract_set_cookie(&resp1);

        evidence.push(format!(
            "Phase 1: GET {phase1_url} → HTTP {} (cookie={})",
            resp1.status().as_u16(),
            session_cookie.as_deref().unwrap_or("<none>")
        ));

        // ── Simulate DNS TTL expiry ───────────────────────────────────────────
        sleep(Duration::from_millis(self.rebind_after_ms)).await;

        // ── Phase 2: replay session against target_ip ─────────────────────────
        let phase2_url = format!(
            "http://{}:{}{}", self.target_ip, target.port, path
        );

        let resp2 = if let Some(ref cookie) = session_cookie {
            client
                .get_with_header(&phase2_url, "Cookie", cookie)
                .await?
        } else {
            client.get(&phase2_url).await?
        };

        let phase2_status = resp2.status().as_u16();
        evidence.push(format!(
            "Phase 2: GET {phase2_url} (replayed cookie) → HTTP {phase2_status}"
        ));

        // A 200 or 302 on phase 2 (while 401/403 would be correct) indicates
        // that the IP-based lockout was not enforced after the rebind.
        let ip_lockout_bypassable = matches!(phase2_status, 200 | 201 | 204 | 302 | 304);

        if ip_lockout_bypassable {
            evidence.push(
                "Session accepted from rebind IP — lockout checked at bind time only".to_string()
            );
        } else {
            evidence.push(format!(
                "Session rejected from rebind IP (HTTP {phase2_status}) — lockout enforced per-request"
            ));
        }

        // ── CORS check ────────────────────────────────────────────────────────
        let same_origin_bypassable = self.check_cors_protection(client, target).await?;
        if same_origin_bypassable {
            evidence.push(
                "CORS: server does not send restrictive Access-Control-Allow-Origin \
                 — same-origin policy bypassable via DNS rebinding"
                    .to_string(),
            );
        } else {
            evidence.push("CORS: server enforces origin restrictions".to_string());
        }

        Ok(RebindingResult {
            ip_lockout_bypassable,
            same_origin_bypassable,
            evidence,
        })
    }

    /// Check whether the server's CORS headers would prevent a DNS rebinding
    /// attack.
    ///
    /// Sends a preflight OPTIONS request with `Origin: http://<rebind_domain>`
    /// and inspects `Access-Control-Allow-Origin`.  Returns `true` (bypassable)
    /// if the header is absent, `*`, or echoes the attacker's origin back.
    pub async fn check_cors_protection(
        &self,
        client: &HttpClient,
        target: &Target,
    ) -> Result<bool> {
        let path = target.path.as_deref().unwrap_or("/");
        let url = format!("http://{}:{}{}", target.host, target.port, path);
        let origin = format!("http://{}", self.rebind_domain);

        let resp = client
            .options_with_headers(
                &url,
                &[
                    ("Origin", origin.as_str()),
                    ("Access-Control-Request-Method", "GET"),
                ],
            )
            .await?;

        let acao = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        debug!("CORS check: Access-Control-Allow-Origin={acao:?}");

        // Bypassable if ACAO is absent, wildcard, or echoes our origin.
        let bypassable = acao.is_empty() || acao == "*" || acao == origin.as_str();
        Ok(bypassable)
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Extract the first `Set-Cookie` header value from an `reqwest::Response`.
fn extract_set_cookie(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            // Return only the cookie name=value part (strip attributes).
            s.split(';').next().unwrap_or(s).trim().to_string()
        })
}
