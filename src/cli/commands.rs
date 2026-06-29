use anyhow::{Result, bail};
use async_trait::async_trait;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tracing::info;
use zeus_attack::{AttackStrategy, DictionaryStrategy, Wordlist};
use zeus_core::{AttackConfigBuilder, ProgressEvent};
use zeus_engine::Engine;
use zeus_services::registry::ProtocolRegistry;

use crate::cli::config::AppConfig;

// ── Cancellation token ─────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ShutdownToken(Arc<AtomicBool>);

impl ShutdownToken {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl Default for ShutdownToken {
    fn default() -> Self {
        Self::new()
    }
}

// ── CommandContext ─────────────────────────────────────────────────────────────

pub struct CommandContext {
    pub config: AppConfig,
    pub shutdown: ShutdownToken,
    pub registry: Arc<ProtocolRegistry>,
}

// ── ZeusCommand trait ─────────────────────────────────────────────────────────

#[async_trait]
pub trait ZeusCommand: Send + Sync {
    fn name(&self) -> &str;
    async fn execute(self: Box<Self>, ctx: CommandContext) -> Result<()>;
}

// ── AttackCommand ─────────────────────────────────────────────────────────────

pub struct AttackCommand;

#[async_trait]
impl ZeusCommand for AttackCommand {
    fn name(&self) -> &str {
        "attack"
    }

    async fn execute(self: Box<Self>, ctx: CommandContext) -> Result<()> {
        let cfg = &ctx.config;

        if ctx.registry.get(&cfg.protocol).is_none() {
            bail!(
                "Protocol '{}' is not registered. Run `zeus list` to see available protocols.",
                cfg.protocol
            );
        }

        info!(
            target = %cfg.target.uri(),
            protocol = %cfg.protocol,
            threads = cfg.threads,
            "Starting attack"
        );

        let userlist =
            Wordlist::from_file(&cfg.userlist_path).map_err(|e| anyhow::anyhow!("{}", e))?;
        let usernames: Vec<String> = userlist.passwords().map(str::to_string).collect();

        let passlist =
            Wordlist::from_file(&cfg.passlist_path).map_err(|e| anyhow::anyhow!("{}", e))?;

        let strategy: Box<dyn AttackStrategy> =
            Box::new(DictionaryStrategy::new(usernames, passlist));

        let attack_cfg = AttackConfigBuilder::new()
            .concurrency(cfg.threads)
            .timeout(Duration::from_secs(cfg.timeout_secs))
            .build();

        let engine = Engine::new(ctx.registry.clone(), attack_cfg);
        let (found, mut rx) = engine.run(cfg.target.clone(), strategy).await;

        // Drain remaining events (already finished, but flush the channel).
        while let Ok(event) = rx.try_recv() {
            if let ProgressEvent::SessionFinished {
                total_attempts,
                rate_per_second,
                ..
            } = event
            {
                info!(
                    attempts = total_attempts,
                    rate = rate_per_second,
                    "Session finished"
                );
            }
        }

        if found.is_empty() {
            info!("Attack finished — no credentials found.");
        } else {
            for cred in &found {
                println!("[FOUND] {}:{}", cred.username, cred.password);
            }
            info!(count = found.len(), "Attack finished");
        }

        Ok(())
    }
}

// ── ProbeCommand ──────────────────────────────────────────────────────────────

pub struct ProbeCommand {
    pub target_str: String,
    pub protocol_hint: Option<String>,
}

#[async_trait]
impl ZeusCommand for ProbeCommand {
    fn name(&self) -> &str {
        "probe"
    }

    async fn execute(self: Box<Self>, ctx: CommandContext) -> Result<()> {
        let protocol = self.protocol_hint.as_deref().unwrap_or("unknown");
        info!(target = %self.target_str, protocol = %protocol, "Probing target");

        if ctx.registry.get(protocol).is_some() {
            println!("Protocol '{}' is available.", protocol);
        } else {
            println!(
                "Protocol '{}' is NOT registered. Available: {}",
                protocol,
                ctx.registry.list().join(", ")
            );
        }
        Ok(())
    }
}

// ── ListCommand ───────────────────────────────────────────────────────────────

pub struct ListCommand;

#[async_trait]
impl ZeusCommand for ListCommand {
    fn name(&self) -> &str {
        "list"
    }

    async fn execute(self: Box<Self>, ctx: CommandContext) -> Result<()> {
        let protocols = ctx.registry.list();
        if protocols.is_empty() {
            println!("No protocols registered.");
        } else {
            println!("Available protocols:");
            for p in &protocols {
                println!("  {}", p);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_token_starts_not_cancelled() {
        let token = ShutdownToken::new();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn shutdown_token_cancel_sets_flag() {
        let token = ShutdownToken::new();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn shutdown_token_clone_shares_state() {
        let token = ShutdownToken::new();
        let clone = token.clone();
        token.cancel();
        assert!(clone.is_cancelled());
    }

    #[test]
    fn list_command_name_is_list() {
        let cmd = ListCommand;
        assert_eq!(cmd.name(), "list");
    }

    #[test]
    fn attack_command_name_is_attack() {
        assert_eq!(AttackCommand.name(), "attack");
    }
}
