//! lichen-tui — terminal dashboard for a LICHEN mesh node.
//!
//! Layout:
//!   ┌─ Contacts ────┬─ Messages ──────────────────────────────┐
//!   │ Alice   now   │ [12:31] fe80::1   anyone on mesh?       │
//!   │ Bob     2m    │ [12:33] local     here — 3 hops, SF10   │
//!   │ Carol   8m    │ ...                                      │
//!   ├───────────────┴──────────────────────────────────────────┤
//!   │ LICHEN  node: [::1]:5683  SF10/125kHz  Tab:focus  q:quit │
//!   └──────────────────────────────────────────────────────────┘
//!
//! Keys: Tab — switch focus  ↑↓/jk — navigate  q/Ctrl-C — quit

use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};
use std::{io, net::SocketAddr, time::Duration};

use clap::Parser;

/// LICHEN terminal user interface.
#[derive(Parser)]
#[command(name = "lichen-tui", version, about)]
struct Cli {
    /// CoAP endpoint address of the target node.
    #[arg(short, long, default_value = "[::1]:5683", env = "LICHEN_NODE")]
    node: SocketAddr,
}

// ── app state ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pane {
    Contacts,
    Messages,
}

struct Contact {
    addr: &'static str,
    alias: &'static str,
    last_seen: &'static str,
}

struct Message {
    time: &'static str,
    from: &'static str,
    text: &'static str,
}

struct App {
    contacts: Vec<Contact>,
    messages: Vec<Message>,
    contact_state: ListState,
    message_state: ListState,
    focus: Pane,
    node: SocketAddr,
    should_quit: bool,
}

impl App {
    fn new(node: SocketAddr) -> Self {
        let mut contact_state = ListState::default();
        contact_state.select(Some(0));
        let mut message_state = ListState::default();
        message_state.select(Some(0));
        Self {
            contacts: vec![
                Contact {
                    addr: "fe80::1",
                    alias: "Alice",
                    last_seen: "now",
                },
                Contact {
                    addr: "fe80::2",
                    alias: "Bob",
                    last_seen: "2m",
                },
                Contact {
                    addr: "fe80::3",
                    alias: "Carol",
                    last_seen: "8m",
                },
            ],
            messages: vec![
                Message {
                    time: "12:31",
                    from: "fe80::1",
                    text: "anyone on mesh?",
                },
                Message {
                    time: "12:33",
                    from: "local",
                    text: "here — 3 hops, SF10",
                },
                Message {
                    time: "12:34",
                    from: "fe80::2",
                    text: "solid signal tonight",
                },
                Message {
                    time: "12:35",
                    from: "fe80::1",
                    text: "RSSI -108, SNR +4",
                },
            ],
            contact_state,
            message_state,
            focus: Pane::Contacts,
            node,
            should_quit: false,
        }
    }

    fn on_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        match (code, mods) {
            (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }
            (KeyCode::Tab, _) => {
                self.focus = match self.focus {
                    Pane::Contacts => Pane::Messages,
                    Pane::Messages => Pane::Contacts,
                };
            }
            (KeyCode::Down, _) | (KeyCode::Char('j'), _) => match self.focus {
                Pane::Contacts => {
                    let i = self.contact_state.selected().unwrap_or(0);
                    self.contact_state
                        .select(Some((i + 1).min(self.contacts.len().saturating_sub(1))));
                }
                Pane::Messages => {
                    let i = self.message_state.selected().unwrap_or(0);
                    self.message_state
                        .select(Some((i + 1).min(self.messages.len().saturating_sub(1))));
                }
            },
            (KeyCode::Up, _) | (KeyCode::Char('k'), _) => match self.focus {
                Pane::Contacts => {
                    let i = self.contact_state.selected().unwrap_or(0);
                    self.contact_state.select(Some(i.saturating_sub(1)));
                }
                Pane::Messages => {
                    let i = self.message_state.selected().unwrap_or(0);
                    self.message_state.select(Some(i.saturating_sub(1)));
                }
            },
            _ => {}
        }
    }
}

// ── drawing ───────────────────────────────────────────────────────────────────

fn ui(f: &mut ratatui::Frame, app: &mut App) {
    let area = f.area();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(22), Constraint::Min(0)])
        .split(outer[0]);

    // Contacts
    let contact_focused = app.focus == Pane::Contacts;
    let contact_items: Vec<ListItem> = app
        .contacts
        .iter()
        .map(|c| {
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(format!("{:<8}", c.alias), Style::default().fg(Color::Cyan)),
                    Span::styled(
                        format!(" {}", c.last_seen),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
                Line::from(Span::styled(
                    format!("  {}", c.addr),
                    Style::default().fg(Color::DarkGray),
                )),
            ])
        })
        .collect();
    let contacts = List::new(contact_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Contacts ")
                .border_style(focus_style(contact_focused)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(contacts, body[0], &mut app.contact_state);

    // Messages
    let msg_focused = app.focus == Pane::Messages;
    let msg_items: Vec<ListItem> = app
        .messages
        .iter()
        .map(|m| {
            let from_color = if m.from == "local" {
                Color::Green
            } else {
                Color::Cyan
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("[{}] ", m.time),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(format!("{:<10} ", m.from), Style::default().fg(from_color)),
                Span::raw(m.text),
            ]))
        })
        .collect();
    let messages = List::new(msg_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Messages ")
                .border_style(focus_style(msg_focused)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(messages, body[1], &mut app.message_state);

    // Status bar
    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            " LICHEN ",
            Style::default().fg(Color::Black).bg(Color::Green),
        ),
        Span::raw(format!("  node: {}  ", app.node)),
        Span::styled("SF10/125kHz  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Tab", Style::default().fg(Color::Yellow)),
        Span::raw(":focus  "),
        Span::styled("↑↓/jk", Style::default().fg(Color::Yellow)),
        Span::raw(":nav  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(":quit"),
    ]));
    f.render_widget(status, outer[1]);
}

fn focus_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    }
}

// ── entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let mut app = App::new(cli.node);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run(&mut terminal, &mut app).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                app.on_key(key.code, key.modifiers);
            }
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}
