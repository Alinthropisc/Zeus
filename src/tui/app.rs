use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io::Stdout;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use zeus_core::ProgressEvent;

use crate::tui::events::{AppEvent, next_event};
use crate::tui::screens::{AttackStats, DashboardScreen, Screen, ScreenTransition};

const TICK: Duration = Duration::from_millis(100);

/// Facade — hides the Engine progress channel and ratatui terminal behind a
/// single `run()` call.
///
/// The dashboard is kept as a concrete field so we can always update its stats
/// without downcasting. Overlay screens (results, help) sit on `overlay_stack`.
pub struct TuiApp {
    pub dashboard: DashboardScreen,
    /// Overlay screens pushed on top of the dashboard (Help, Results, …).
    overlay_stack: Vec<Box<dyn Screen>>,
    progress_rx: broadcast::Receiver<ProgressEvent>,
}

impl TuiApp {
    pub fn new(progress_rx: broadcast::Receiver<ProgressEvent>) -> Self {
        Self {
            dashboard: DashboardScreen::new(),
            overlay_stack: Vec::new(),
            progress_rx,
        }
    }

    pub async fn run(
        mut self,
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    ) -> Result<()> {
        loop {
            // Draw whichever screen is on top.
            terminal.draw(|frame| {
                let area = frame.area();
                if let Some(overlay) = self.overlay_stack.last() {
                    overlay.render(frame, area);
                } else {
                    self.dashboard.render(frame, area);
                }
            })?;

            let event = next_event(&mut self.progress_rx, TICK).await;

            match event {
                AppEvent::Progress(ev) => self.apply_progress(ev),

                AppEvent::Key(key) => {
                    // Ctrl-C always quits.
                    if key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                    {
                        break;
                    }

                    let transition = if let Some(overlay) = self.overlay_stack.last_mut() {
                        overlay.handle_key(key)
                    } else {
                        self.dashboard.handle_key(key)
                    };

                    match transition {
                        ScreenTransition::Stay => {}
                        ScreenTransition::Push(s) => self.overlay_stack.push(s),
                        ScreenTransition::Pop => {
                            self.overlay_stack.pop();
                        }
                        ScreenTransition::Quit => break,
                    }
                }

                AppEvent::Tick => {}
            }
        }
        Ok(())
    }

    pub fn apply_progress(&mut self, event: ProgressEvent) {
        match event {
            ProgressEvent::SessionStarted { estimated_total, .. } => {
                self.dashboard.stats.total = estimated_total;
                self.dashboard.stats.started_at = Some(Instant::now());
            }
            ProgressEvent::Attempt { credential, result, attempts_done, .. } => {
                self.dashboard.stats.attempts = attempts_done;
                if result.is_success() {
                    self.dashboard.stats.found.push(credential.clone());
                    self.dashboard.push_log(format!("[FOUND] {}", credential));
                }
            }
            ProgressEvent::Stats { attempts_per_sec, .. } => {
                self.dashboard.stats.rate_per_sec = attempts_per_sec;
            }
            ProgressEvent::SessionFinished {
                found,
                total_attempts,
                rate_per_second,
                ..
            } => {
                self.dashboard.stats.found = found;
                self.dashboard.stats.attempts = total_attempts;
                self.dashboard.stats.rate_per_sec = rate_per_second;
                self.dashboard.push_log("[SESSION] Finished.".to_string());
            }
            ProgressEvent::Warning(msg) => {
                self.dashboard.push_log(format!("[WARN] {}", msg));
            }
        }
    }
}
