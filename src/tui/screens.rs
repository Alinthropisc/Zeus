use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use std::time::{Duration, Instant};
use zeus_core::Credential;

use crate::tui::widgets::{LogPane, ProgressBar, StatsTable};

/// What the active screen wants to do after handling a key.
pub enum ScreenTransition {
    Stay,
    Push(Box<dyn Screen>),
    Pop,
    Quit,
}

/// Strategy pattern — each logical screen implements this.
pub trait Screen: Send {
    fn render(&self, frame: &mut Frame, area: Rect);
    fn handle_key(&mut self, key: KeyEvent) -> ScreenTransition;
}

// ── AttackStats ───────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct AttackStats {
    pub found: Vec<Credential>,
    pub attempts: u64,
    pub rate_per_sec: f64,
    pub started_at: Option<Instant>,
    pub total: Option<u64>,
}

impl AttackStats {
    pub fn elapsed(&self) -> Duration {
        self.started_at
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO)
    }
}

// ── DashboardScreen ───────────────────────────────────────────────────────────

pub struct DashboardScreen {
    pub stats: AttackStats,
    pub log_lines: Vec<String>,
}

impl DashboardScreen {
    pub fn new() -> Self {
        Self {
            stats: AttackStats {
                started_at: Some(Instant::now()),
                ..Default::default()
            },
            log_lines: Vec::new(),
        }
    }

    pub fn push_log(&mut self, line: impl Into<String>) {
        self.log_lines.push(line.into());
        if self.log_lines.len() > 200 {
            self.log_lines.drain(..100);
        }
    }
}

impl Default for DashboardScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl Screen for DashboardScreen {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(1),
            ])
            .split(area);

        let elapsed = self.stats.elapsed();
        let header_text = format!(
            " Found: {}  |  Attempts: {}  |  Rate: {:.1}/s  |  Elapsed: {:.0?} ",
            self.stats.found.len(),
            self.stats.attempts,
            self.stats.rate_per_sec,
            elapsed,
        );
        let header = Paragraph::new(header_text)
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Zeus Attack Dashboard"),
            );
        frame.render_widget(header, chunks[0]);

        let pb = ProgressBar {
            label: format!("{:.1} attempts/sec", self.stats.rate_per_sec),
            done: self.stats.attempts,
            total: self.stats.total,
        };
        pb.render(frame, chunks[1]);

        let mid = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(chunks[2]);

        let last_five: Vec<Credential> = self
            .stats
            .found
            .iter()
            .rev()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        StatsTable { found: &last_five }.render(frame, mid[0]);

        let log_height = mid[1].height.saturating_sub(2) as usize;
        let last_log: Vec<String> = self
            .log_lines
            .iter()
            .rev()
            .take(log_height)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        LogPane { lines: &last_log }.render(frame, mid[1]);

        let help = Paragraph::new(Line::from(vec![
            Span::styled(
                " q",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" quit  "),
            Span::styled(" r", Style::default().fg(Color::Green)),
            Span::raw(" results  "),
            Span::styled(" ?", Style::default().fg(Color::Cyan)),
            Span::raw(" help "),
        ]));
        frame.render_widget(help, chunks[3]);
    }

    fn handle_key(&mut self, key: KeyEvent) -> ScreenTransition {
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => ScreenTransition::Quit,
            KeyCode::Char('r') => ScreenTransition::Push(Box::new(ResultsScreen {
                stats: self.stats.clone(),
            })),
            KeyCode::Char('?') => ScreenTransition::Push(Box::new(HelpScreen)),
            _ => ScreenTransition::Stay,
        }
    }
}

// ── ResultsScreen ─────────────────────────────────────────────────────────────

pub struct ResultsScreen {
    pub stats: AttackStats,
}

impl Screen for ResultsScreen {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(5), Constraint::Length(1)])
            .split(area);

        StatsTable {
            found: &self.stats.found,
        }
        .render(frame, chunks[0]);

        let help = Paragraph::new(" ESC / q — back");
        frame.render_widget(help, chunks[1]);
    }

    fn handle_key(&mut self, key: KeyEvent) -> ScreenTransition {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => ScreenTransition::Pop,
            _ => ScreenTransition::Stay,
        }
    }
}

// ── HelpScreen ────────────────────────────────────────────────────────────────

pub struct HelpScreen;

impl Screen for HelpScreen {
    fn render(&self, frame: &mut Frame, area: Rect) {
        let text = vec![
            Line::from("Zeus TUI Keybindings"),
            Line::from(""),
            Line::from("  q / Ctrl-C  — quit"),
            Line::from("  r           — show all found credentials"),
            Line::from("  ?           — this help screen"),
            Line::from("  ESC         — go back"),
        ];
        let para = Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("Help"));
        frame.render_widget(para, area);
    }

    fn handle_key(&mut self, key: KeyEvent) -> ScreenTransition {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => ScreenTransition::Pop,
            _ => ScreenTransition::Stay,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn help_screen_q_returns_pop() {
        let mut screen = HelpScreen;
        let t = screen.handle_key(key(KeyCode::Char('q')));
        assert!(matches!(t, ScreenTransition::Pop));
    }

    #[test]
    fn help_screen_esc_returns_pop() {
        let mut screen = HelpScreen;
        let t = screen.handle_key(key(KeyCode::Esc));
        assert!(matches!(t, ScreenTransition::Pop));
    }

    #[test]
    fn help_screen_other_key_stays() {
        let mut screen = HelpScreen;
        let t = screen.handle_key(key(KeyCode::Char('x')));
        assert!(matches!(t, ScreenTransition::Stay));
    }

    #[test]
    fn dashboard_initial_state_is_empty() {
        let dash = DashboardScreen::new();
        assert_eq!(dash.stats.found.len(), 0);
        assert_eq!(dash.stats.attempts, 0);
        assert!(dash.log_lines.is_empty());
    }

    #[test]
    fn dashboard_q_returns_quit() {
        let mut dash = DashboardScreen::new();
        let t = dash.handle_key(key(KeyCode::Char('q')));
        assert!(matches!(t, ScreenTransition::Quit));
    }
}
