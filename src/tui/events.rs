use crossterm::event::{self, Event, KeyEvent};
use std::time::Duration;
use tokio::sync::broadcast;
use zeus_core::ProgressEvent;

/// Unified event type for the TUI event loop.
#[derive(Debug)]
pub enum AppEvent {
    Key(KeyEvent),
    Tick,
    Progress(ProgressEvent),
}

/// Poll for the next event.  Returns immediately with `Tick` if nothing arrives
/// within `timeout`.
pub async fn next_event(
    rx: &mut broadcast::Receiver<ProgressEvent>,
    timeout: Duration,
) -> AppEvent {
    // Check for a progress event without blocking.
    match rx.try_recv() {
        Ok(ev) => return AppEvent::Progress(ev),
        Err(broadcast::error::TryRecvError::Lagged(_)) => {}
        Err(_) => {}
    }

    // Poll crossterm for terminal input.
    if event::poll(timeout).unwrap_or(false)
        && let Ok(Event::Key(key)) = event::read()
    {
        return AppEvent::Key(key);
    }

    AppEvent::Tick
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn tick_and_key_are_distinct_variants() {
        let tick = AppEvent::Tick;
        assert!(matches!(tick, AppEvent::Tick));
        // Key variant needs a KeyEvent — just verify the enum compiles and Tick is not Key.
        assert!(!matches!(tick, AppEvent::Key(_)));
    }

    #[test]
    fn progress_variant_wraps_event() {
        let ev = ProgressEvent::Warning("test".to_string());
        let app_ev = AppEvent::Progress(ev);
        assert!(matches!(app_ev, AppEvent::Progress(_)));
    }

    #[tokio::test]
    async fn next_event_returns_progress_when_broadcast_has_message() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(8);
        tx.send(ProgressEvent::Warning("hello".to_string()))
            .unwrap();

        let event = next_event(&mut rx, Duration::from_millis(0)).await;
        assert!(matches!(event, AppEvent::Progress(_)));
    }
}
