//! Status screen for T-Deck (320x240 / ~40x30 chars).
//!
//! Layout:
//!   +----------------------------------------+
//!   | [B]87%  [G]3D  [P]5 online             |
//!   |----------------------------------------|
//!   |                                        |
//!   |   LICHEN                               |
//!   |   Ready                                |
//!   |                                        |
//!   | Last: KJ6QOH 2m ago                    |
//!   | "heading to summit"                    |
//!   +----------------------------------------+

use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
};

/// GPS fix quality.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GpsFix {
    #[default]
    None,
    Fix2D,
    Fix3D,
}

impl GpsFix {
    pub fn as_str(self) -> &'static str {
        match self {
            GpsFix::None => "--",
            GpsFix::Fix2D => "2D",
            GpsFix::Fix3D => "3D",
        }
    }
}

/// Connection/ready state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ReadyState {
    #[default]
    Connecting,
    Ready,
    Error(String),
}

/// Last received message info.
#[derive(Clone, Debug, Default)]
pub struct LastMessage {
    pub from: String,
    pub ago_secs: u64,
    pub text: String,
}

/// Device state for the status screen.
#[derive(Clone, Debug, Default)]
pub struct DeviceState {
    pub battery_pct: Option<u8>,
    pub gps: GpsFix,
    pub peer_count: u16,
    pub state: ReadyState,
    pub last_msg: Option<LastMessage>,
}

/// Compact status screen widget for T-Deck.
#[derive(Debug)]
pub struct StatusScreen<'a> {
    state: &'a DeviceState,
}

impl<'a> StatusScreen<'a> {
    pub fn new(state: &'a DeviceState) -> Self {
        Self { state }
    }
}

impl Widget for StatusScreen<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Outer block with border
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));
        let inner = block.inner(area);
        block.render(area, buf);

        // Split: status bar (1) | divider (1) | body (rest)
        let chunks = Layout::vertical([
            Constraint::Length(1), // status bar
            Constraint::Length(1), // divider
            Constraint::Min(0),    // body
        ])
        .split(inner);

        // ── Status bar: battery, GPS, peers ──
        let bat_str = self
            .state
            .battery_pct
            .map(|p| format!("{}%", p))
            .unwrap_or_else(|| "--".into());
        let bat_color = match self.state.battery_pct {
            Some(p) if p <= 20 => Color::Red,
            Some(p) if p <= 50 => Color::Yellow,
            _ => Color::Green,
        };

        let gps_color = match self.state.gps {
            GpsFix::Fix3D => Color::Green,
            GpsFix::Fix2D => Color::Yellow,
            GpsFix::None => Color::Red,
        };

        let peer_color = if self.state.peer_count > 0 {
            Color::Green
        } else {
            Color::DarkGray
        };

        let status_line = Line::from(vec![
            Span::styled("[B]", Style::default().fg(bat_color)),
            Span::styled(format!("{:<4}", bat_str), Style::default().fg(bat_color)),
            Span::raw(" "),
            Span::styled("[G]", Style::default().fg(gps_color)),
            Span::styled(
                format!("{:<3}", self.state.gps.as_str()),
                Style::default().fg(gps_color),
            ),
            Span::raw(" "),
            Span::styled("[P]", Style::default().fg(peer_color)),
            Span::styled(
                format!("{} online", self.state.peer_count),
                Style::default().fg(peer_color),
            ),
        ]);
        Paragraph::new(status_line).render(chunks[0], buf);

        // ── Divider line ──
        let divider = "-".repeat(chunks[1].width as usize);
        Paragraph::new(divider)
            .style(Style::default().fg(Color::DarkGray))
            .render(chunks[1], buf);

        // ── Body: title, state, last message ──
        let body_chunks = Layout::vertical([
            Constraint::Length(1), // spacer
            Constraint::Length(1), // LICHEN title
            Constraint::Length(1), // state
            Constraint::Length(1), // spacer
            Constraint::Length(1), // last msg header
            Constraint::Length(1), // last msg text
            Constraint::Min(0),    // remaining space
        ])
        .split(chunks[2]);

        // Title
        let title = Paragraph::new(Line::from(vec![Span::styled(
            "LICHEN",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )]))
        .alignment(Alignment::Center);
        title.render(body_chunks[1], buf);

        // Connection state
        let (state_text, state_color) = match &self.state.state {
            ReadyState::Connecting => ("Connecting...", Color::Yellow),
            ReadyState::Ready => ("Ready", Color::Green),
            ReadyState::Error(e) => (e.as_str(), Color::Red),
        };
        let state_para = Paragraph::new(Line::from(vec![Span::styled(
            state_text,
            Style::default().fg(state_color),
        )]))
        .alignment(Alignment::Center);
        state_para.render(body_chunks[2], buf);

        // Last message
        if let Some(msg) = &self.state.last_msg {
            let ago = fmt_ago(msg.ago_secs);
            let header = Line::from(vec![
                Span::styled("Last: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&msg.from, Style::default().fg(Color::Cyan)),
                Span::styled(format!(" {}", ago), Style::default().fg(Color::DarkGray)),
            ]);
            Paragraph::new(header).render(body_chunks[4], buf);

            // Truncate message text to fit (safe for multi-byte UTF-8)
            let max_len = body_chunks[5].width.saturating_sub(2) as usize;
            let text = if msg.text.len() > max_len {
                // Account for quotes and ellipsis: "..."
                let target = max_len.saturating_sub(5); // 2 quotes + 3 ellipsis
                // Find the last char boundary at or before `target` bytes
                let boundary = msg
                    .text
                    .char_indices()
                    .take_while(|(i, _)| *i <= target)
                    .last()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                format!("\"{}...\"", &msg.text[..boundary])
            } else {
                format!("\"{}\"", msg.text)
            };
            let msg_line =
                Paragraph::new(text).style(Style::default().fg(Color::White).add_modifier(Modifier::ITALIC));
            msg_line.render(body_chunks[5], buf);
        }
    }
}

/// Format seconds ago as human-readable string.
fn fmt_ago(secs: u64) -> String {
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fmt_ago() {
        assert_eq!(fmt_ago(30), "30s ago");
        assert_eq!(fmt_ago(120), "2m ago");
        assert_eq!(fmt_ago(3700), "1h ago");
        assert_eq!(fmt_ago(90000), "1d ago");
    }

    #[test]
    fn test_gps_fix_str() {
        assert_eq!(GpsFix::None.as_str(), "--");
        assert_eq!(GpsFix::Fix2D.as_str(), "2D");
        assert_eq!(GpsFix::Fix3D.as_str(), "3D");
    }

    #[test]
    fn test_device_state_defaults() {
        let state = DeviceState::default();
        assert_eq!(state.battery_pct, None);
        assert_eq!(state.gps, GpsFix::None);
        assert_eq!(state.peer_count, 0);
        assert_eq!(state.state, ReadyState::Connecting);
        assert!(state.last_msg.is_none());
    }
}
