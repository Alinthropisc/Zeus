use zeus::cli;
use zeus::tui;

use anyhow::Result;
use clap::Parser;
use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{io, sync::Arc};
use tracing_subscriber::{EnvFilter, fmt};
use zeus_services::registry::ProtocolRegistry;

use cli::{
    args::{ZeusArgs, ZeusSubcommand},
    commands::{
        AttackCommand, CommandContext, ListCommand, ProbeCommand, ShutdownToken, ZeusCommand,
    },
    config::AppConfig,
};

#[tokio::main]
async fn main() -> Result<()> {
    let args = ZeusArgs::parse();

    // Determine early whether TUI mode is requested (suppress logs if so).
    let use_tui = matches!(&args.command, ZeusSubcommand::Attack(a) if a.tui);

    if !use_tui {
        fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_target(false)
            .init();
    }

    // Build shared protocol registry (empty by default; services can register
    // protocols at startup here).
    let registry = Arc::new(ProtocolRegistry::new());

    let shutdown = ShutdownToken::new();

    // Install Ctrl-C handler.
    {
        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                shutdown_clone.cancel();
            }
        });
    }

    match args.command {
        ZeusSubcommand::Attack(ref attack_args) => {
            let config = AppConfig::from_args(attack_args)?;
            let use_tui_flag = config.use_tui;

            if use_tui_flag {
                // Launch engine in the background and attach TUI.
                let registry_clone = registry.clone();
                let config_clone = config.clone();
                let shutdown_clone = shutdown.clone();

                // Run engine task to get the progress channel.
                let (tx, rx) = tokio::sync::broadcast::channel(1024);
                let engine_handle = tokio::spawn(async move {
                    let ctx = CommandContext {
                        config: config_clone,
                        shutdown: shutdown_clone,
                        registry: registry_clone,
                    };
                    let cmd: Box<dyn ZeusCommand> = Box::new(AttackCommand);
                    if let Err(e) = cmd.execute(ctx).await {
                        tracing::error!("Attack error: {}", e);
                    }
                    // Signal done by sending a dummy broadcast — TUI will see
                    // SessionFinished via the engine's own channel.  The tx
                    // here is unused; the engine creates its own channel.
                    drop(tx);
                });

                // Set up the TUI terminal.
                enable_raw_mode()?;
                let mut stdout = io::stdout();
                execute!(stdout, EnterAlternateScreen)?;
                let backend = CrosstermBackend::new(stdout);
                let mut terminal = Terminal::new(backend)?;

                let tui_app = tui::app::TuiApp::new(rx);
                let result = tui_app.run(&mut terminal).await;

                // Restore terminal unconditionally.
                disable_raw_mode()?;
                execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
                terminal.show_cursor()?;

                engine_handle.abort();
                result?;
            } else {
                let ctx = CommandContext {
                    config,
                    shutdown,
                    registry,
                };
                let cmd: Box<dyn ZeusCommand> = Box::new(AttackCommand);
                cmd.execute(ctx).await?;
            }
        }

        ZeusSubcommand::Probe(ref probe_args) => {
            // AppConfig is not needed for probe; we use minimal config.
            let ctx = CommandContext {
                config: AppConfig {
                    target: zeus_core::Target::new("", 0, ""),
                    protocol: probe_args.protocol.clone().unwrap_or_default(),
                    threads: 1,
                    timeout_secs: 5,
                    use_tui: false,
                    userlist_path: Default::default(),
                    passlist_path: Default::default(),
                },
                shutdown,
                registry,
            };
            let cmd: Box<dyn ZeusCommand> = Box::new(ProbeCommand {
                target_str: probe_args.target.clone(),
                protocol_hint: probe_args.protocol.clone(),
            });
            cmd.execute(ctx).await?;
        }

        ZeusSubcommand::List => {
            let ctx = CommandContext {
                config: AppConfig {
                    target: zeus_core::Target::new("", 0, ""),
                    protocol: String::new(),
                    threads: 1,
                    timeout_secs: 5,
                    use_tui: false,
                    userlist_path: Default::default(),
                    passlist_path: Default::default(),
                },
                shutdown,
                registry,
            };
            let cmd: Box<dyn ZeusCommand> = Box::new(ListCommand);
            cmd.execute(ctx).await?;
        }
    }

    Ok(())
}
