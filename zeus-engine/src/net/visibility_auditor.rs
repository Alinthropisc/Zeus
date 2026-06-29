//! Facade over all Phase 8 network-visibility probes.
//!
//! [`NetworkVisibilityAuditor`] is a single entry point that orchestrates
//! DNS-tunnel, ICMP covert-channel, C2 traffic, and ECH/ESNI probes, then
//! produces a unified [`VisibilityReport`] with an overall visibility score.

use anyhow::Result;
use std::net::IpAddr;
use tracing::info;

use crate::c2_traffic::{C2Auditor, C2Finding, C2Pattern, CovertChannelFactory};
use crate::dns_tunnel::DnsTunnelFinding;
use crate::esni_probe::EsniResult;
use crate::http_client::HttpClient;
use crate::icmp_probe::IcmpProbeResult;

// ── Report ─────────────────────────────────────────────────────────────────────

/// Aggregated results from all Phase 8 probes.
#[derive(Debug)]
pub struct VisibilityReport {
    pub dns_tunnel_findings: Vec<DnsTunnelFinding>,
    pub icmp_findings: Vec<IcmpProbeResult>,
    pub c2_findings: Vec<C2Finding>,
    pub esni_results: Vec<EsniResult>,
    /// 0.0 = all traffic invisible to SIEM/NIDS, 1.0 = all traffic detected.
    pub overall_visibility_score: f32,
}

// ── Facade ─────────────────────────────────────────────────────────────────────

/// Single entry point over all Phase 8 network-visibility gap probes.
///
/// Use the builder methods (`with_dns`, `with_icmp`, …) to enable each probe,
/// then call [`run_audit`] to execute them all concurrently and get a report.
#[derive(Debug, Default)]
pub struct NetworkVisibilityAuditor {
    pub dns_domain: Option<String>,
    pub icmp_target: Option<IpAddr>,
    pub c2_base_url: Option<String>,
    pub esni_targets: Vec<String>,
}

impl NetworkVisibilityAuditor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable DNS-tunnel probing against `domain`.
    pub fn with_dns(mut self, domain: impl Into<String>) -> Self {
        self.dns_domain = Some(domain.into());
        self
    }

    /// Enable ICMP covert-channel probing against `target`.
    pub fn with_icmp(mut self, target: IpAddr) -> Self {
        self.icmp_target = Some(target);
        self
    }

    /// Enable C2 traffic probing against `url` (e.g. `"https://example.com"`).
    pub fn with_c2_url(mut self, url: impl Into<String>) -> Self {
        self.c2_base_url = Some(url.into());
        self
    }

    /// Enable ECH/ESNI probing for each hostname in `targets`.
    pub fn with_esni(mut self, targets: Vec<String>) -> Self {
        self.esni_targets = targets;
        self
    }

    /// Run all enabled probes and return a consolidated report.
    pub async fn run_audit(&self, client: &HttpClient) -> Result<VisibilityReport> {
        info!("NetworkVisibilityAuditor: starting Phase 8 audit");

        // ── DNS tunnel ────────────────────────────────────────────────────────
        let mut dns_tunnel_findings = Vec::new();
        if let Some(domain) = &self.dns_domain {
            let auditor = CovertChannelFactory::dns_tunnel(domain);
            match auditor.audit().await {
                Ok(f) => {
                    info!("DNS tunnel probe complete: strategy={}", f.strategy);
                    dns_tunnel_findings.push(f);
                }
                Err(e) => {
                    tracing::warn!("DNS tunnel probe failed: {}", e);
                }
            }
        }

        // ── ICMP ──────────────────────────────────────────────────────────────
        let mut icmp_findings = Vec::new();
        if let Some(target) = self.icmp_target {
            let channel = CovertChannelFactory::icmp_channel(target);
            match channel.probe().await {
                Ok(r) => {
                    info!("ICMP probe complete: {}", r.finding);
                    icmp_findings.push(r);
                }
                Err(e) => {
                    tracing::warn!("ICMP probe failed: {}", e);
                }
            }
        }

        // ── C2 traffic ────────────────────────────────────────────────────────
        let mut c2_findings = Vec::new();
        if let Some(base_url) = &self.c2_base_url {
            let patterns = vec![
                C2Pattern::cobalt_strike_default(),
                C2Pattern::sliver_https(),
                C2Pattern::covenant_profile(),
                C2Pattern::metasploit_meterpreter(),
            ];
            let auditor = CovertChannelFactory::c2_auditor(patterns);
            match auditor.audit(client, base_url).await {
                Ok(findings) => {
                    info!("C2 audit complete: {} patterns tested", findings.len());
                    c2_findings.extend(findings);
                }
                Err(e) => {
                    tracing::warn!("C2 audit failed: {}", e);
                }
            }
        }

        // ── ECH/ESNI ──────────────────────────────────────────────────────────
        let mut esni_results = Vec::new();
        for host in &self.esni_targets {
            let probe = CovertChannelFactory::esni_probe(host);
            match probe.probe().await {
                Ok(r) => {
                    info!("ECH probe '{}': supported={}", host, r.ech_supported);
                    esni_results.push(r);
                }
                Err(e) => {
                    tracing::warn!("ECH probe '{}' failed: {}", host, e);
                }
            }
        }

        let mut report = VisibilityReport {
            dns_tunnel_findings,
            icmp_findings,
            c2_findings,
            esni_results,
            overall_visibility_score: 0.0,
        };
        report.overall_visibility_score = Self::score_visibility(&report);
        Ok(report)
    }

    /// Compute an overall visibility score in [0.0, 1.0].
    ///
    /// - 1.0 = all traffic visible / detected by SIEM/NIDS.
    /// - 0.0 = all traffic invisible (maximum evasion).
    pub fn score_visibility(report: &VisibilityReport) -> f32 {
        let mut total = 0u32;
        let mut detected = 0u32;

        // DNS tunnel: each finding contributes 1 point; `likely_detected` scores it.
        for f in &report.dns_tunnel_findings {
            total += 1;
            if f.likely_detected {
                detected += 1;
            }
        }

        // ICMP: payload_filtered means NIDS inspected and acted on the payload.
        for r in &report.icmp_findings {
            total += 1;
            if r.payload_filtered {
                detected += 1;
            }
        }

        // C2: each detected pattern counts.
        for f in &report.c2_findings {
            total += 1;
            if f.detected {
                detected += 1;
            }
        }

        // ECH: if ECH is supported the traffic is *not* visible → subtract.
        for r in &report.esni_results {
            total += 1;
            if !r.tls_inspection_bypassable {
                // TLS inspection can see it → detected
                detected += 1;
            }
        }

        if total == 0 {
            0.0
        } else {
            detected as f32 / total as f32
        }
    }
}
