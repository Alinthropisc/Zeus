//! C2 traffic pattern detection probe — tests whether IDS/SIEM identifies
//! malleable C2 beacon traffic from known frameworks (Cobalt Strike, Sliver,
//! Covenant, Meterpreter).
//!
//! # Patterns
//! - **Observer pattern** — [`C2TrafficObserver`] receives per-request events.
//! - **Factory Method** — [`CovertChannelFactory`] builds the right channel.

use anyhow::Result;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tracing::debug;

use crate::dns_tunnel::{DnsTunnelAuditor, HighEntropyStrategy, Iodine32Strategy};
use crate::esni_probe::EsniProbe;
use crate::http_client::HttpClient;
use crate::icmp_probe::{IcmpCovertChannel, IcmpPayloadStrategy};
use std::net::IpAddr;

// ── Observer trait ─────────────────────────────────────────────────────────────

/// Observer pattern: receives per-request events during a C2 audit.
pub trait C2TrafficObserver: Send + Sync {
    fn on_request(&self, pattern: &C2Pattern, response_code: u16);
    fn on_detection_indicator(&self, indicator: &str);
    fn summary(&self) -> Vec<C2Finding>;
}

// ── Body pattern ───────────────────────────────────────────────────────────────

/// Shape of the HTTP body in a C2 beacon request.
#[derive(Debug, Clone)]
pub enum C2BodyPattern {
    Empty,
    JsonBeacon,
    Base64Blob { size: usize },
    RandomBytes { size: usize },
}

// ── C2 pattern descriptor ──────────────────────────────────────────────────────

/// Describes one C2 framework's HTTP beacon characteristics.
#[derive(Debug, Clone)]
pub struct C2Pattern {
    pub name: &'static str,
    pub user_agent: &'static str,
    pub uri: &'static str,
    pub method: &'static str,
    pub headers: Vec<(&'static str, &'static str)>,
    pub body_pattern: C2BodyPattern,
    /// Simulated beacon interval (not enforced in the probe; recorded for scoring).
    pub beacon_interval_ms: u64,
}

impl C2Pattern {
    /// Default Cobalt Strike HTTP beacon profile.
    pub fn cobalt_strike_default() -> Self {
        Self {
            name: "cobalt-strike-default",
            user_agent: "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; 1349)",
            uri: "/jquery-3.3.1.min.js",
            method: "GET",
            headers: vec![
                ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                ("Accept-Language", "en-US,en;q=0.5"),
                ("Referer", "http://code.jquery.com/"),
            ],
            body_pattern: C2BodyPattern::Empty,
            beacon_interval_ms: 60_000,
        }
    }

    /// Sliver HTTPS implant default profile.
    pub fn sliver_https() -> Self {
        Self {
            name: "sliver-https",
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            uri: "/static/css/bootstrap.min.css",
            method: "GET",
            headers: vec![
                ("Accept", "text/css,*/*;q=0.1"),
                ("Accept-Encoding", "gzip, deflate, br"),
            ],
            body_pattern: C2BodyPattern::Empty,
            beacon_interval_ms: 30_000,
        }
    }

    /// Covenant C2 framework HTTP listener profile.
    pub fn covenant_profile() -> Self {
        Self {
            name: "covenant",
            user_agent: "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
            uri: "/en-us/docs.html",
            method: "GET",
            headers: vec![
                ("Accept", "application/json, text/javascript, */*; q=0.01"),
                ("X-Requested-With", "XMLHttpRequest"),
            ],
            body_pattern: C2BodyPattern::JsonBeacon,
            beacon_interval_ms: 5_000,
        }
    }

    /// Metasploit Meterpreter reverse HTTPS default profile.
    pub fn metasploit_meterpreter() -> Self {
        Self {
            name: "meterpreter-https",
            user_agent: "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)",
            uri: "/api/v1/status",
            method: "GET",
            headers: vec![],
            body_pattern: C2BodyPattern::RandomBytes { size: 256 },
            beacon_interval_ms: 10_000,
        }
    }
}

// ── C2 finding ─────────────────────────────────────────────────────────────────

/// Result of testing one C2 pattern against a target.
#[derive(Debug, Clone)]
pub struct C2Finding {
    pub pattern: String,
    pub detected: bool,
    /// Indicators that may have revealed the pattern to SIEM/IDS.
    pub detection_clues: Vec<String>,
    pub recommendation: String,
}

// ── Default observer ───────────────────────────────────────────────────────────

/// A basic collecting observer — records all events and produces findings.
#[derive(Debug, Default)]
pub struct CollectingObserver {
    events: Mutex<Vec<(String, u16, Vec<String>)>>,
}

impl C2TrafficObserver for CollectingObserver {
    fn on_request(&self, pattern: &C2Pattern, response_code: u16) {
        debug!("C2 pattern '{}' → HTTP {}", pattern.name, response_code);
        let mut ev = self.events.lock().unwrap();
        ev.push((pattern.name.to_string(), response_code, vec![]));
    }

    fn on_detection_indicator(&self, indicator: &str) {
        debug!("Detection indicator: {}", indicator);
        let mut ev = self.events.lock().unwrap();
        if let Some(last) = ev.last_mut() {
            last.2.push(indicator.to_string());
        }
    }

    fn summary(&self) -> Vec<C2Finding> {
        let ev = self.events.lock().unwrap();
        ev.iter()
            .map(|(name, code, clues)| {
                let detected = *code == 403 || *code == 429 || !clues.is_empty();
                C2Finding {
                    pattern: name.clone(),
                    detected,
                    detection_clues: clues.clone(),
                    recommendation: if detected {
                        "Rotate user-agent and URI; consider malleable C2 profile".to_string()
                    } else {
                        "Pattern not detected — monitor for retroactive correlation".to_string()
                    },
                }
            })
            .collect()
    }
}

// ── Auditor ────────────────────────────────────────────────────────────────────

/// Runs multiple [`C2Pattern`] probes against a target and notifies observers.
pub struct C2Auditor {
    pub patterns: Vec<C2Pattern>,
    pub observers: Vec<Box<dyn C2TrafficObserver>>,
}

impl C2Auditor {
    pub fn new(patterns: Vec<C2Pattern>) -> Self {
        Self { patterns, observers: vec![] }
    }

    pub fn add_observer(&mut self, obs: Box<dyn C2TrafficObserver>) {
        self.observers.push(obs);
    }

    /// Send each pattern's beacon request to `base_url` and return findings.
    pub async fn audit(&self, client: &HttpClient, base_url: &str) -> Result<Vec<C2Finding>> {
        let mut all_findings = Vec::new();

        for pattern in &self.patterns {
            let url = format!("{}{}", base_url.trim_end_matches('/'), pattern.uri);
            debug!("Probing C2 pattern '{}' → {}", pattern.name, url);

            let resp = client
                .get(&url)
                .header("User-Agent", pattern.user_agent)
                .send()
                .await;

            let (code, clues) = match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    let mut clues = vec![];
                    // Known-bad user-agents often get a 403/429 immediately
                    if status == 403 {
                        clues.push("HTTP 403 — WAF/proxy may have flagged user-agent".to_string());
                    } else if status == 429 {
                        clues.push("HTTP 429 — rate-limit or C2 detection heuristic".to_string());
                    }
                    // Suspicious URI patterns
                    if pattern.uri.ends_with(".js") || pattern.uri.ends_with(".css") {
                        clues.push(format!(
                            "URI '{}' mimics static asset — common C2 evasion; may trigger DPI rules",
                            pattern.uri
                        ));
                    }
                    (status, clues)
                }
                Err(e) => {
                    let clues =
                        vec![format!("connection error: {} — host may be blocking probes", e)];
                    (0u16, clues)
                }
            };

            for obs in &self.observers {
                obs.on_request(pattern, code);
                for clue in &clues {
                    obs.on_detection_indicator(clue);
                }
            }

            let detected = code == 403 || code == 429 || !clues.is_empty();
            all_findings.push(C2Finding {
                pattern: pattern.name.to_string(),
                detected,
                detection_clues: clues,
                recommendation: if detected {
                    "Modify profile: randomise beacon interval, rotate UA/URI per implant".to_string()
                } else {
                    "Pattern undetected — consider adding to threat model for SIEM tuning".to_string()
                },
            });
        }

        Ok(all_findings)
    }

    /// Produce a JSON beacon summary for one pattern (useful for logging/SIEM feeds).
    pub fn beacon(&self, pattern: &C2Pattern) -> Value {
        serde_json::json!({
            "pattern": pattern.name,
            "method": pattern.method,
            "uri": pattern.uri,
            "user_agent": pattern.user_agent,
            "beacon_interval_ms": pattern.beacon_interval_ms,
        })
    }
}

// ── Factory Method ─────────────────────────────────────────────────────────────

/// Factory for covert channel probes — picks the right type from config.
pub struct CovertChannelFactory;

impl CovertChannelFactory {
    /// Build a DNS-tunnel auditor using iodine-style base32 encoding.
    pub fn dns_tunnel(domain: &str) -> DnsTunnelAuditor {
        DnsTunnelAuditor {
            strategy: Box::new(Iodine32Strategy { domain: domain.to_string() }),
            resolver: "8.8.8.8:53".to_string(),
            sample_count: 5,
        }
    }

    /// Build a C2 auditor pre-loaded with all known framework profiles.
    pub fn c2_auditor(patterns: Vec<C2Pattern>) -> C2Auditor {
        let mut auditor = C2Auditor::new(patterns);
        auditor.add_observer(Box::new(CollectingObserver::default()));
        auditor
    }

    /// Build an ICMP covert-channel probe with random-padding strategy.
    pub fn icmp_channel(target: IpAddr) -> IcmpCovertChannel {
        IcmpCovertChannel {
            target,
            payload_strategy: IcmpPayloadStrategy::RandomPadding,
        }
    }

    /// Build an ECH/ESNI probe for the given hostname.
    pub fn esni_probe(target: &str) -> EsniProbe {
        EsniProbe { target: target.to_string(), port: 443 }
    }
}
