//! Message list and compose screens for LICHEN TUI.
//!
//! Screens:
//!   - MessageList: List of conversations with last message preview
//!   - Thread: Full conversation with a single contact
//!   - Compose: Text input for new message

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

// ── data types ────────────────────────────────────────────────────────────────

/// Message delivery status for outgoing messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DeliveryStatus {
    /// Message queued but not yet transmitted.
    #[default]
    Pending,
    /// Message transmitted over the air.
    Sent,
    /// Delivery acknowledgment received from recipient.
    Delivered,
    /// Read receipt received (recipient opened the message).
    Read,
    /// Delivery failed after retries exhausted.
    Failed,
}

impl DeliveryStatus {
    /// ASCII indicator for display (e.g., "v" for sent, "vv" for delivered).
    pub fn indicator(&self) -> &'static str {
        match self {
            DeliveryStatus::Pending => "...",
            DeliveryStatus::Sent => "v",
            DeliveryStatus::Delivered => "vv",
            DeliveryStatus::Read => "vv",
            DeliveryStatus::Failed => "x",
        }
    }

    /// Terminal color for status indicator.
    pub fn color(&self) -> Color {
        match self {
            DeliveryStatus::Pending => Color::DarkGray,
            DeliveryStatus::Sent => Color::Gray,
            DeliveryStatus::Delivered => Color::Cyan,
            DeliveryStatus::Read => Color::Blue,
            DeliveryStatus::Failed => Color::Red,
        }
    }
}

/// A single message in a conversation.
#[derive(Clone, Debug)]
pub struct Message {
    /// Unique message identifier (local to this conversation).
    pub id: u64,
    /// True if this message was sent by us, false if received.
    pub outgoing: bool,
    /// Message text content.
    pub content: String,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,
    /// Delivery status (only meaningful for outgoing messages).
    pub status: DeliveryStatus,
}

/// A conversation thread with a single contact.
#[derive(Clone, Debug)]
pub struct Conversation {
    /// Contact identifier (IPv6 address or callsign).
    pub contact: String,
    /// Messages in chronological order.
    pub messages: Vec<Message>,
    /// Count of unread incoming messages.
    pub unread: usize,
}

impl Conversation {
    /// Get the last message preview (truncated).
    /// Safe for multi-byte UTF-8: always cuts at a valid character boundary.
    pub fn last_preview(&self, max_len: usize) -> String {
        self.messages.last().map_or_else(
            || "(no messages)".into(),
            |m| {
                if m.content.len() <= max_len {
                    m.content.clone()
                } else {
                    let suffix = "...";
                    let target = max_len.saturating_sub(suffix.len());
                    // Find the last char boundary at or before `target` bytes
                    let boundary = m
                        .content
                        .char_indices()
                        .take_while(|(i, _)| *i <= target)
                        .last()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    format!("{}{}", &m.content[..boundary], suffix)
                }
            },
        )
    }
}

// ── message state ─────────────────────────────────────────────────────────────

/// UI state for the messages screens (list, thread, and compose).
#[derive(Debug)]
pub struct MessagesState {
    /// All conversations, sorted by most recent activity.
    pub conversations: Vec<Conversation>,
    /// Selection state for the conversation list.
    pub list_state: ListState,
    /// Selection state for messages within a thread.
    pub thread_state: ListState,
    /// Text buffer for the compose input.
    pub compose_buffer: String,
    /// Cursor position in compose buffer (byte offset).
    pub cursor_pos: usize,
}

impl Default for MessagesState {
    fn default() -> Self {
        Self::new()
    }
}

impl MessagesState {
    /// Create a new messages state (empty in release, demo data in debug).
    pub fn new() -> Self {
        let mut state = Self {
            conversations: Vec::new(),
            list_state: ListState::default(),
            thread_state: ListState::default(),
            compose_buffer: String::new(),
            cursor_pos: 0,
        };

        #[cfg(debug_assertions)]
        {
            // Demo data for development/testing only
            state.conversations = vec![
                Conversation {
                    contact: "fe80::1".into(),
                    messages: vec![
                        Message {
                            id: 1,
                            outgoing: false,
                            content: "Hey, are you on the mesh?".into(),
                            timestamp: 1700000000,
                            status: DeliveryStatus::Read,
                        },
                        Message {
                            id: 2,
                            outgoing: true,
                            content: "Yes! Just connected.".into(),
                            timestamp: 1700000060,
                            status: DeliveryStatus::Delivered,
                        },
                    ],
                    unread: 0,
                },
                Conversation {
                    contact: "fe80::2".into(),
                    messages: vec![Message {
                        id: 3,
                        outgoing: false,
                        content: "Node status check".into(),
                        timestamp: 1700000120,
                        status: DeliveryStatus::Read,
                    }],
                    unread: 1,
                },
            ];
        }

        if !state.conversations.is_empty() {
            state.list_state.select(Some(0));
        }
        state
    }

    /// Get the currently selected conversation, if any.
    pub fn selected_conversation(&self) -> Option<&Conversation> {
        self.list_state.selected().and_then(|i| self.conversations.get(i))
    }

    /// Get mutable reference to the currently selected conversation.
    pub fn selected_conversation_mut(&mut self) -> Option<&mut Conversation> {
        self.list_state.selected().and_then(|i| self.conversations.get_mut(i))
    }

    /// Move selection up in the conversation list.
    pub fn nav_up(&mut self) {
        if let Some(i) = self.list_state.selected() {
            self.list_state.select(Some(i.saturating_sub(1)));
        }
    }

    /// Move selection down in the conversation list.
    pub fn nav_down(&mut self) {
        let n = self.conversations.len();
        if n > 0 {
            let i = self.list_state.selected().unwrap_or(0);
            self.list_state.select(Some((i + 1).min(n - 1)));
        }
    }

    /// Move selection up within the current thread.
    pub fn thread_nav_up(&mut self) {
        if let Some(i) = self.thread_state.selected() {
            self.thread_state.select(Some(i.saturating_sub(1)));
        }
    }

    /// Move selection down within the current thread.
    pub fn thread_nav_down(&mut self) {
        if let Some(conv) = self.selected_conversation() {
            let n = conv.messages.len();
            if n > 0 {
                let i = self.thread_state.selected().unwrap_or(0);
                self.thread_state.select(Some((i + 1).min(n - 1)));
            }
        }
    }

    /// Enter thread view, selecting the most recent message.
    pub fn enter_thread(&mut self) {
        if let Some(conv) = self.selected_conversation() {
            let n = conv.messages.len();
            if n > 0 {
                self.thread_state.select(Some(n - 1)); // Start at bottom
            }
        }
    }

    /// Insert a character at the cursor position.
    pub fn type_char(&mut self, c: char) {
        self.compose_buffer.insert(self.cursor_pos, c);
        self.cursor_pos += c.len_utf8();
    }

    /// Delete the character before the cursor.
    pub fn backspace(&mut self) {
        if self.cursor_pos > 0 {
            let prev = self.compose_buffer[..self.cursor_pos]
                .chars()
                .last()
                .map(|c| c.len_utf8())
                .unwrap_or(0);
            self.cursor_pos -= prev;
            self.compose_buffer.remove(self.cursor_pos);
        }
    }

    /// Move cursor left by one character.
    pub fn cursor_left(&mut self) {
        if self.cursor_pos > 0 {
            let prev = self.compose_buffer[..self.cursor_pos]
                .chars()
                .last()
                .map(|c| c.len_utf8())
                .unwrap_or(0);
            self.cursor_pos -= prev;
        }
    }

    /// Move cursor right by one character.
    pub fn cursor_right(&mut self) {
        if self.cursor_pos < self.compose_buffer.len() {
            let next = self.compose_buffer[self.cursor_pos..]
                .chars()
                .next()
                .map(|c| c.len_utf8())
                .unwrap_or(0);
            self.cursor_pos += next;
        }
    }

    /// "Send" the composed message (adds to conversation, clears buffer).
    pub fn send_message(&mut self) -> bool {
        if self.compose_buffer.trim().is_empty() {
            return false;
        }
        let Some(idx) = self.list_state.selected() else {
            return false;
        };
        let Some(conv) = self.conversations.get_mut(idx) else {
            return false;
        };
        let id = conv.messages.iter().map(|m| m.id).max().unwrap_or(0) + 1;
        let content = std::mem::take(&mut self.compose_buffer);
        conv.messages.push(Message {
            id,
            outgoing: true,
            content,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            status: DeliveryStatus::Pending,
        });
        self.cursor_pos = 0;
        // Scroll to bottom
        let msg_count = conv.messages.len();
        self.thread_state.select(Some(msg_count - 1));
        true
    }
}

// ── rendering ─────────────────────────────────────────────────────────────────

/// Render the conversation list screen.
pub fn render_message_list(f: &mut Frame, area: Rect, state: &mut MessagesState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    let items: Vec<ListItem> = if state.conversations.is_empty() {
        vec![ListItem::new(Span::styled(
            " No conversations",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        state
            .conversations
            .iter()
            .map(|conv| {
                let preview = conv.last_preview(20);
                let unread_marker = if conv.unread > 0 { "*" } else { " " };
                ListItem::new(Line::from(vec![
                    Span::styled(unread_marker, Style::default().fg(Color::Yellow)),
                    Span::styled(
                        format!("{:<15}", truncate(&conv.contact, 15)),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(preview, Style::default().fg(Color::Gray)),
                ]))
            })
            .collect()
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Messages ")
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(list, chunks[0], &mut state.list_state);

    // Status bar
    let status = Paragraph::new(Line::from(vec![
        Span::styled(" MSG ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw("  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::raw(":open  "),
        Span::styled("n", Style::default().fg(Color::Yellow)),
        Span::raw(":new  "),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::raw(":back"),
    ]));
    f.render_widget(status, chunks[1]);
}

/// Render the thread view for a single conversation.
pub fn render_thread(f: &mut Frame, area: Rect, state: &mut MessagesState) {
    let Some(idx) = state.list_state.selected() else {
        return;
    };
    let Some(conv) = state.conversations.get(idx) else {
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

    // Header
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled(&*conv.contact, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    ]))
    .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(header, chunks[0]);

    // Messages - build items before releasing borrow
    let items: Vec<ListItem> = conv
        .messages
        .iter()
        .map(|msg| {
            let prefix = if msg.outgoing { "> " } else { "< " };
            let status_str = if msg.outgoing {
                format!(" {}", msg.status.indicator())
            } else {
                String::new()
            };
            let status_color = msg.status.color();
            ListItem::new(Line::from(vec![
                Span::styled(
                    prefix,
                    Style::default().fg(if msg.outgoing { Color::Green } else { Color::Blue }),
                ),
                Span::raw(&*msg.content),
                Span::styled(status_str, Style::default().fg(status_color)),
            ]))
        })
        .collect();

    // Now we can mutably borrow thread_state
    let list = List::new(items)
        .block(Block::default().borders(Borders::NONE))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(list, chunks[1], &mut state.thread_state);

    // Compose input
    let input = Paragraph::new(Line::from(vec![
        Span::raw(&state.compose_buffer),
        Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Compose ")
            .border_style(Style::default().fg(Color::Green)),
    )
    .wrap(Wrap { trim: false });
    f.render_widget(input, chunks[2]);

    // Status bar
    let status = Paragraph::new(Line::from(vec![
        Span::styled(" CHAT ", Style::default().fg(Color::Black).bg(Color::Green)),
        Span::raw("  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::raw(":send  "),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::raw(":back"),
    ]));
    f.render_widget(status, chunks[3]);
}

/// Truncate a string to at most `max` bytes, appending "..." if truncated.
/// Safe for multi-byte UTF-8: always cuts at a valid character boundary.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        let suffix = "...";
        let target = max.saturating_sub(suffix.len());
        // Find the last char boundary at or before `target` bytes
        let boundary = s
            .char_indices()
            .take_while(|(i, _)| *i <= target)
            .last()
            .map(|(i, _)| i)
            .unwrap_or(0);
        format!("{}{}", &s[..boundary], suffix)
    }
}
