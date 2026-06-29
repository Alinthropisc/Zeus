//! SSH-2 password authentication stub.
//!
//! The `russh` crate is not included in this workspace. This stub satisfies
//! the module requirement and provides the public types used by the registry
//! without pulling in any external SSH dependency.

use async_trait::async_trait;
use std::fmt;
use std::sync::Arc;
use std::time::Instant;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};

pub struct SshProtocol;

#[async_trait]
impl Protocol for SshProtocol {
    fn name(&self) -> &'static str {
        "ssh"
    }
    fn default_port(&self) -> u16 {
        22
    }
    fn description(&self) -> &'static str {
        "SSH-2 password authentication (stub — russh not available)"
    }

    async fn authenticate(
        &self,
        _target: &Target,
        _cred: &Credential,
        _config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        Err(ZeusError::Protocol(
            "SSH support requires the russh crate which is not compiled into this build".into(),
        ))
    }
}

// ─── Observer pattern (retained for API compatibility) ────────────────────────

pub trait TimingObserver: Send + Sync + fmt::Debug {
    fn on_sample(&self, user: &str, duration: std::time::Duration);
}

#[derive(Debug, Default)]
pub struct VecTimingObserver {
    samples: Arc<std::sync::Mutex<Vec<(String, std::time::Duration)>>>,
}

impl VecTimingObserver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn drain(&self) -> Vec<(String, std::time::Duration)> {
        match self.samples.lock() {
            Ok(mut g) => g.drain(..).collect(),
            Err(_) => Vec::new(),
        }
    }
}

impl TimingObserver for VecTimingObserver {
    fn on_sample(&self, user: &str, duration: std::time::Duration) {
        if let Ok(mut g) = self.samples.lock() {
            g.push((user.to_string(), duration));
        }
    }
}

#[derive(Debug)]
pub struct SshUserEnumProbe {
    pub host: String,
    pub port: u16,
    pub timeout: std::time::Duration,
    observers: Vec<Arc<dyn TimingObserver>>,
}

impl SshUserEnumProbe {
    pub fn new(host: impl Into<String>, port: u16, timeout: std::time::Duration) -> Self {
        Self {
            host: host.into(),
            port,
            timeout,
            observers: Vec::new(),
        }
    }

    pub fn add_observer(&mut self, obs: Arc<dyn TimingObserver>) {
        self.observers.push(obs);
    }

    pub async fn probe_user(&self, username: &str) -> std::time::Duration {
        let start = Instant::now();
        let d = start.elapsed();
        for obs in &self.observers {
            obs.on_sample(username, d);
        }
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_meta() {
        let p = SshProtocol;
        assert_eq!(p.name(), "ssh");
        assert_eq!(p.default_port(), 22);
        assert!(!p.tls_default());
    }

    #[test]
    fn vec_timing_observer_records_samples() {
        let obs = VecTimingObserver::new();
        obs.on_sample("alice", std::time::Duration::from_millis(42));
        let drained = obs.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, "alice");
    }

    #[test]
    fn ssh_enum_probe_builds() {
        let mut probe = SshUserEnumProbe::new("127.0.0.1", 22, std::time::Duration::from_secs(5));
        let obs = VecTimingObserver::new();
        probe.add_observer(obs.clone());
        assert_eq!(probe.observers.len(), 1);
    }
}
