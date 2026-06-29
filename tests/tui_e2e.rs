//! End-to-end tests for the TUI layer.
//!
//! We cannot drive a real terminal in CI, so these tests exercise the TUI
//! state machine (screen transitions, progress application, log buffer) without
//! actually rendering to a CrosstermBackend.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use zeus_core::{Credential, ProgressEvent, Target};

use zeus::tui::{
    app::TuiApp,
    screens::{DashboardScreen, HelpScreen, ResultsScreen, Screen, ScreenTransition},
    widgets::LogBuffer,
};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

// ── LogBuffer ─────────────────────────────────────────────────────────────────

#[test]
fn log_buffer_starts_empty() {
    let buf = LogBuffer::new(10);
    assert!(buf.is_empty());
    assert_eq!(buf.len(), 0);
    assert_eq!(buf.capacity(), 10);
}

#[test]
fn log_buffer_push_and_len() {
    let mut buf = LogBuffer::new(10);
    buf.push("line 1");
    buf.push("line 2");
    assert_eq!(buf.len(), 2);
}

#[test]
fn log_buffer_evicts_oldest_at_capacity() {
    let mut buf = LogBuffer::new(3);
    buf.push("a");
    buf.push("b");
    buf.push("c");
    buf.push("d"); // evicts "a"
    let lines: Vec<&str> = buf.lines().collect();
    assert_eq!(lines, vec!["b", "c", "d"]);
}

#[test]
fn log_buffer_never_exceeds_capacity() {
    let mut buf = LogBuffer::new(5);
    for i in 0..20 {
        buf.push(format!("line {i}"));
    }
    assert_eq!(buf.len(), 5);
}

// ── DashboardScreen key handling ──────────────────────────────────────────────

#[test]
fn dashboard_q_returns_quit() {
    let mut dash = DashboardScreen::new();
    assert!(matches!(
        dash.handle_key(key(KeyCode::Char('q'))),
        ScreenTransition::Quit
    ));
}

#[test]
fn dashboard_capital_q_returns_quit() {
    let mut dash = DashboardScreen::new();
    assert!(matches!(
        dash.handle_key(key(KeyCode::Char('Q'))),
        ScreenTransition::Quit
    ));
}

#[test]
fn dashboard_r_pushes_results_screen() {
    let mut dash = DashboardScreen::new();
    let t = dash.handle_key(key(KeyCode::Char('r')));
    assert!(matches!(t, ScreenTransition::Push(_)));
}

#[test]
fn dashboard_question_mark_pushes_help_screen() {
    let mut dash = DashboardScreen::new();
    let t = dash.handle_key(key(KeyCode::Char('?')));
    assert!(matches!(t, ScreenTransition::Push(_)));
}

#[test]
fn dashboard_unrecognised_key_stays() {
    let mut dash = DashboardScreen::new();
    assert!(matches!(
        dash.handle_key(key(KeyCode::Char('x'))),
        ScreenTransition::Stay
    ));
}

// ── HelpScreen key handling ───────────────────────────────────────────────────

#[test]
fn help_esc_pops() {
    let mut h = HelpScreen;
    assert!(matches!(
        h.handle_key(key(KeyCode::Esc)),
        ScreenTransition::Pop
    ));
}

#[test]
fn help_q_pops() {
    let mut h = HelpScreen;
    assert!(matches!(
        h.handle_key(key(KeyCode::Char('q'))),
        ScreenTransition::Pop
    ));
}

#[test]
fn help_question_mark_pops() {
    let mut h = HelpScreen;
    assert!(matches!(
        h.handle_key(key(KeyCode::Char('?'))),
        ScreenTransition::Pop
    ));
}

#[test]
fn help_other_key_stays() {
    let mut h = HelpScreen;
    assert!(matches!(
        h.handle_key(key(KeyCode::Enter)),
        ScreenTransition::Stay
    ));
}

// ── ResultsScreen key handling ────────────────────────────────────────────────

#[test]
fn results_esc_pops() {
    let mut r = ResultsScreen {
        stats: Default::default(),
    };
    assert!(matches!(
        r.handle_key(key(KeyCode::Esc)),
        ScreenTransition::Pop
    ));
}

#[test]
fn results_q_pops() {
    let mut r = ResultsScreen {
        stats: Default::default(),
    };
    assert!(matches!(
        r.handle_key(key(KeyCode::Char('q'))),
        ScreenTransition::Pop
    ));
}

// ── TuiApp::apply_progress (state machine) ───────────────────────────────────

#[test]
fn tuiapp_session_started_sets_total() {
    let (_tx, rx) = broadcast::channel(8);
    let mut app = TuiApp::new(rx);

    app.apply_progress(ProgressEvent::SessionStarted {
        target: Target::new("localhost", 22, "ssh"),
        estimated_total: Some(42),
    });

    assert_eq!(app.dashboard.stats.total, Some(42));
    assert!(app.dashboard.stats.started_at.is_some());
}

#[test]
fn tuiapp_attempt_success_appends_to_found() {
    let (_tx, rx) = broadcast::channel(8);
    let mut app = TuiApp::new(rx);

    let cred = Credential::new("admin".to_string(), "pass".to_string());
    app.apply_progress(ProgressEvent::Attempt {
        credential: cred.clone(),
        result: zeus_core::AttackResult::Success {
            credential: cred.clone(),
            elapsed: Duration::from_millis(5),
        },
        attempts_done: 1,
        started_at: Instant::now(),
    });

    assert_eq!(app.dashboard.stats.found.len(), 1);
    assert_eq!(app.dashboard.stats.attempts, 1);
}

#[test]
fn tuiapp_warning_appends_to_log() {
    let (_tx, rx) = broadcast::channel(8);
    let mut app = TuiApp::new(rx);

    app.apply_progress(ProgressEvent::Warning("test warning".to_string()));

    assert!(
        app.dashboard
            .log_lines
            .iter()
            .any(|l| l.contains("test warning"))
    );
}

#[test]
fn tuiapp_session_finished_updates_stats() {
    let (_tx, rx) = broadcast::channel(8);
    let mut app = TuiApp::new(rx);

    let cred = Credential::new("root".to_string(), "toor".to_string());
    app.apply_progress(ProgressEvent::SessionFinished {
        found: vec![cred],
        total_attempts: 100,
        rate_per_second: 33.3,
        elapsed: Duration::from_secs(3),
        successes: 1,
        failures: 99,
        errors: 0,
        rate_limits: 0,
        timeouts: 0,
    });

    assert_eq!(app.dashboard.stats.found.len(), 1);
    assert_eq!(app.dashboard.stats.attempts, 100);
}
