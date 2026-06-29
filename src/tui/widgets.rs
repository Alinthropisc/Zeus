use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph, Row, Table},
};
use zeus_core::Credential;

/// A simple percentage-based progress bar.
pub struct ProgressBar {
    pub label: String,
    pub done: u64,
    pub total: Option<u64>,
}

impl ProgressBar {
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let ratio = self
            .total
            .filter(|&t| t > 0)
            .map(|t| (self.done as f64 / t as f64).min(1.0))
            .unwrap_or(0.0);

        let label = if let Some(t) = self.total {
            format!("{} / {} — {}", self.done, t, &self.label)
        } else {
            format!("{} attempts — {}", self.done, &self.label)
        };

        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Progress"))
            .gauge_style(Style::default().fg(Color::Cyan))
            .ratio(ratio)
            .label(label);

        frame.render_widget(gauge, area);
    }
}

/// Table showing found credentials.
pub struct StatsTable<'a> {
    pub found: &'a [Credential],
}

impl<'a> StatsTable<'a> {
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let rows: Vec<Row> = self
            .found
            .iter()
            .map(|c| Row::new(vec![c.username.clone(), c.password.clone()]))
            .collect();

        let header = Row::new(vec!["Username", "Password"])
            .style(Style::default().add_modifier(Modifier::BOLD));

        let table = Table::new(
            rows,
            [
                ratatui::layout::Constraint::Percentage(50),
                ratatui::layout::Constraint::Percentage(50),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Found Credentials"),
        );

        frame.render_widget(table, area);
    }
}

/// An owned, capacity-bounded log buffer.  Oldest entries are evicted when
/// the buffer exceeds `capacity`.
pub struct LogBuffer {
    capacity: usize,
    entries: std::collections::VecDeque<String>,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: std::collections::VecDeque::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, line: impl Into<String>) {
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(line.into());
    }

    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// A scrolling pane showing the last N log lines.
pub struct LogPane<'a> {
    pub lines: &'a [String],
}

impl<'a> LogPane<'a> {
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let text: Vec<Line> = self
            .lines
            .iter()
            .map(|l| Line::from(Span::raw(l.clone())))
            .collect();

        let para = Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title("Log"))
            .wrap(ratatui::widgets::Wrap { trim: true });

        frame.render_widget(para, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_buffer_new_capacity() {
        let buf = LogBuffer::new(5);
        assert_eq!(buf.capacity(), 5);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn log_buffer_push_within_capacity() {
        let mut buf = LogBuffer::new(5);
        buf.push("a");
        buf.push("b");
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn log_buffer_push_beyond_capacity_evicts_oldest() {
        let mut buf = LogBuffer::new(3);
        buf.push("first");
        buf.push("second");
        buf.push("third");
        buf.push("fourth"); // should evict "first"
        assert_eq!(buf.len(), 3);
        let lines: Vec<&str> = buf.lines().collect();
        assert_eq!(lines, vec!["second", "third", "fourth"]);
    }

    #[test]
    fn stats_table_starts_empty() {
        let found: Vec<Credential> = vec![];
        let table = StatsTable { found: &found };
        assert!(table.found.is_empty());
    }
}
