//! Terminal UI for envctl.
//!
//! The UI is organized around a single mental model: pick a **context**
//! (an active project and an active environment), then work a focused
//! secrets table. The table is a coverage matrix — every secret is a row,
//! every environment is a column, and each cell shows whether that secret
//! has a value in that environment. The active environment column is the
//! one you edit and preview.
//!
//! Store errors never propagate out of the event loop: they land in the
//! status line so a duplicate name (or any other failure) can never tear
//! the terminal down.

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use envctl_core::{Environment, Id, Project, Secret, SecretRegistry};
use envctl_store::{Store, StoreError};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap};
use std::collections::BTreeMap;
use std::io;

pub fn run(store: Store) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut terminal, App::new(store)?);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, mut app: App) -> Result<()> {
    loop {
        terminal.draw(|frame| draw(frame, &app))?;
        if app.should_quit {
            return Ok(());
        }
        if let Event::Key(key) = event::read()? {
            // Only errors from the terminal/event layer are fatal. Store
            // failures are captured into the status line inside handlers.
            app.handle_key(key)?;
        }
    }
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// A secret plus its decrypted variants, keyed by environment id. Cached on
/// `reload()` so rendering never touches the database or the cipher.
struct SecretRow {
    secret: Secret,
    variants: BTreeMap<Id, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Browse,
    Detail,
    Editor,
    Switcher,
    Confirm,
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Info,
    Ok,
    Error,
}

struct Status {
    text: String,
    level: Level,
}

impl Status {
    fn idle() -> Self {
        Self {
            text: String::new(),
            level: Level::Info,
        }
    }

    fn ok(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            level: Level::Ok,
        }
    }

    fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            level: Level::Error,
        }
    }
}

/// What a text-input popup is collecting.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EditTarget {
    /// Live secret search; the buffer is mirrored into `App::filter`.
    Search,
    /// Value for a secret in the active environment. Empty input clears it.
    SecretValue {
        key: String,
        environment: String,
    },
    AddSecret,
    RenameSecret {
        old: String,
    },
    Description {
        key: String,
    },
    AddProject,
    RenameProject {
        old: String,
    },
    AddEnvironment,
    RenameEnvironment {
        old: String,
    },
}

struct Editor {
    target: EditTarget,
    title: String,
    buffer: Vec<char>,
    cursor: usize,
    masked: bool,
    reveal: bool,
    /// Mode to restore when the editor closes (lets the detail view round-trip).
    return_to: Mode,
}

impl Editor {
    fn new(target: EditTarget, title: impl Into<String>, initial: &str, masked: bool) -> Self {
        let buffer: Vec<char> = initial.chars().collect();
        let cursor = buffer.len();
        Self {
            target,
            title: title.into(),
            buffer,
            cursor,
            masked,
            reveal: false,
            return_to: Mode::Browse,
        }
    }

    fn returning_to(mut self, mode: Mode) -> Self {
        self.return_to = mode;
        self
    }

    fn value(&self) -> String {
        self.buffer.iter().collect()
    }

    fn insert(&mut self, ch: char) {
        self.buffer.insert(self.cursor, ch);
        self.cursor += 1;
    }

    fn backspace(&mut self) {
        if self.cursor > 0 {
            self.buffer.remove(self.cursor - 1);
            self.cursor -= 1;
        }
    }

    fn delete(&mut self) {
        if self.cursor < self.buffer.len() {
            self.buffer.remove(self.cursor);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwitcherKind {
    Project,
    Environment,
}

struct Switcher {
    kind: SwitcherKind,
    filter: String,
    selected: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConfirmTarget {
    Secret(String),
    Project(String),
    Environment(String),
}

/// Per-secret inspector: lists every environment's value for one secret and
/// lets you reveal, edit, and copy values between environments.
struct Detail {
    secret_key: String,
    selected_env: usize,
    reveal: bool,
    /// A value yanked from one environment, ready to paste into another.
    yank: Option<Yank>,
}

struct Yank {
    source_env: String,
    value: String,
}

struct App {
    store: Store,
    projects: Vec<Project>,
    environments: Vec<Environment>,
    rows: Vec<SecretRow>,
    active_project: usize,
    active_env: usize,
    selected_row: usize,
    filter: String,
    assigned_only: bool,
    reveal_cell: bool,
    sync_ops: usize,
    mode: Mode,
    editor: Option<Editor>,
    switcher: Option<Switcher>,
    confirm: Option<ConfirmTarget>,
    detail: Option<Detail>,
    status: Status,
    /// Project/environment to select once a just-created entity has loaded.
    pending_active_project: Option<String>,
    pending_active_env: Option<String>,
    should_quit: bool,
}

impl App {
    fn new(store: Store) -> Result<Self> {
        let mut app = Self {
            store,
            projects: Vec::new(),
            environments: Vec::new(),
            rows: Vec::new(),
            active_project: 0,
            active_env: 0,
            selected_row: 0,
            filter: String::new(),
            assigned_only: false,
            reveal_cell: false,
            sync_ops: 0,
            mode: Mode::Browse,
            editor: None,
            switcher: None,
            confirm: None,
            detail: None,
            status: Status::idle(),
            pending_active_project: None,
            pending_active_env: None,
            should_quit: false,
        };
        app.reload()?;
        Ok(app)
    }

    fn reload(&mut self) -> Result<(), StoreError> {
        self.projects = self.store.list_projects()?;
        self.environments = self.store.list_environments()?;
        let secrets = self.store.list_secrets()?;
        let mut rows = Vec::with_capacity(secrets.len());
        for secret in secrets {
            let mut variants = BTreeMap::new();
            for variant in self.store.variants_for_secret(&secret.key)? {
                variants.insert(variant.environment_id, variant.value);
            }
            rows.push(SecretRow { secret, variants });
        }
        self.rows = rows;
        self.sync_ops = self
            .store
            .sync_status()
            .map(|status| status.operation_count)
            .unwrap_or(0);
        clamp_index(&mut self.active_project, self.projects.len());
        clamp_index(&mut self.active_env, self.environments.len());
        let visible = self.filtered_rows().len();
        clamp_index(&mut self.selected_row, visible);
        Ok(())
    }

    /// Reload and surface any failure in the status line instead of crashing.
    fn refresh(&mut self) {
        if let Err(err) = self.reload() {
            self.status = Status::error(format!("reload failed: {err}"));
        }
    }

    // -- context accessors --------------------------------------------------

    fn active_project(&self) -> Option<&Project> {
        self.projects.get(self.active_project)
    }

    fn active_environment(&self) -> Option<&Environment> {
        self.environments.get(self.active_env)
    }

    fn filtered_rows(&self) -> Vec<usize> {
        let query = self.filter.to_ascii_lowercase();
        let project_id = self.active_project().map(|project| project.id);
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                let matches_query = query.is_empty()
                    || row.secret.key.to_ascii_lowercase().contains(&query)
                    || row
                        .secret
                        .description
                        .as_deref()
                        .unwrap_or_default()
                        .to_ascii_lowercase()
                        .contains(&query);
                let matches_scope = if self.assigned_only {
                    project_id
                        .map(|id| row.secret.assigned_project_ids.contains(&id))
                        .unwrap_or(false)
                } else {
                    true
                };
                matches_query && matches_scope
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn focused_row(&self) -> Option<&SecretRow> {
        let index = *self.filtered_rows().get(self.selected_row)?;
        self.rows.get(index)
    }

    /// (resolved, total assigned, missing keys) for the active context.
    fn coverage(&self) -> Option<(usize, usize, Vec<String>)> {
        let project = self.active_project()?;
        let environment = self.active_environment()?;
        let mut total = 0;
        let mut resolved = 0;
        let mut missing = Vec::new();
        for row in &self.rows {
            if row.secret.assigned_project_ids.contains(&project.id) {
                total += 1;
                if row.variants.contains_key(&environment.id) {
                    resolved += 1;
                } else {
                    missing.push(row.secret.key.clone());
                }
            }
        }
        Some((resolved, total, missing))
    }

    // -- key dispatch -------------------------------------------------------

    fn handle_key(&mut self, key: KeyEvent) -> Result<()> {
        match self.mode {
            Mode::Browse => self.browse_key(key),
            Mode::Detail => self.detail_key(key),
            Mode::Editor => self.editor_key(key),
            Mode::Switcher => self.switcher_key(key),
            Mode::Confirm => self.confirm_key(key),
            Mode::Help => {
                if matches!(
                    key.code,
                    KeyCode::Char('?') | KeyCode::Esc | KeyCode::Char('q')
                ) {
                    self.mode = Mode::Browse;
                }
            }
        }
        Ok(())
    }

    fn browse_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') => self.mode = Mode::Help,
            KeyCode::Char('j') | KeyCode::Down => self.move_row(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_row(-1),
            KeyCode::PageDown => self.move_row(10),
            KeyCode::PageUp => self.move_row(-10),
            KeyCode::Home => self.select_row(0),
            KeyCode::End => {
                let last = self.filtered_rows().len().saturating_sub(1);
                self.select_row(last);
            }
            KeyCode::Left | KeyCode::Char('h') => self.move_env(-1),
            KeyCode::Right | KeyCode::Char('l') => self.move_env(1),
            KeyCode::Enter => self.open_detail(),
            KeyCode::Char('v') => self.start_edit_value(),
            KeyCode::Char(' ') => self.toggle_assignment(),
            KeyCode::Char('p') => self.open_switcher(SwitcherKind::Project),
            KeyCode::Char('e') => self.open_switcher(SwitcherKind::Environment),
            KeyCode::Char('a') => self.open_editor(Editor::new(
                EditTarget::AddSecret,
                "New secret key",
                "",
                false,
            )),
            KeyCode::Char('R') => self.start_rename_secret(),
            KeyCode::Char('c') => self.start_edit_description(),
            KeyCode::Char('d') => self.start_delete_secret(),
            KeyCode::Char('f') => {
                self.assigned_only = !self.assigned_only;
                self.selected_row = 0;
                self.status = Status::ok(if self.assigned_only {
                    "Showing secrets assigned to the active project"
                } else {
                    "Showing all secrets"
                });
            }
            KeyCode::Char('r') => {
                self.reveal_cell = !self.reveal_cell;
            }
            KeyCode::Char('/') => self.open_editor(Editor::new(
                EditTarget::Search,
                "Search secrets",
                &self.filter.clone(),
                false,
            )),
            KeyCode::Char('S') => self.show_sync_status(),
            _ => {}
        }
    }

    fn move_row(&mut self, delta: isize) {
        // Reveal is column-scoped, so it persists while scanning down rows.
        let len = self.filtered_rows().len();
        move_index(&mut self.selected_row, len, delta);
    }

    fn select_row(&mut self, index: usize) {
        self.selected_row = index;
    }

    fn move_env(&mut self, delta: isize) {
        move_index(&mut self.active_env, self.environments.len(), delta);
        self.reveal_cell = false;
    }

    fn toggle_assignment(&mut self) {
        let Some(project) = self.active_project().cloned() else {
            self.status = Status::error("No active project. Press p to pick one.");
            return;
        };
        let Some(row) = self.focused_row() else {
            self.status = Status::error("No secret selected.");
            return;
        };
        let key = row.secret.key.clone();
        let assigned = row.secret.assigned_project_ids.contains(&project.id);
        let result = if assigned {
            self.store.unassign_secret(&key, &project.name)
        } else {
            self.store.assign_secret(&key, &project.name)
        };
        match result {
            Ok(()) => {
                self.status = Status::ok(if assigned {
                    format!("Unassigned {key} from {}", project.name)
                } else {
                    format!("Assigned {key} to {}", project.name)
                });
                self.refresh();
            }
            Err(err) => self.status = Status::error(short_error(&err)),
        }
    }

    fn start_edit_value(&mut self) {
        let Some(environment) = self.active_environment().cloned() else {
            self.status = Status::error("No active environment. Press e to pick one.");
            return;
        };
        let Some(row) = self.focused_row() else {
            self.status = Status::error("No secret selected.");
            return;
        };
        let key = row.secret.key.clone();
        let current = row
            .variants
            .get(&environment.id)
            .cloned()
            .unwrap_or_default();
        self.open_editor(Editor::new(
            EditTarget::SecretValue {
                key: key.clone(),
                environment: environment.name.clone(),
            },
            format!("{key} · {}  (empty clears)", environment.name),
            &current,
            true,
        ));
    }

    fn start_rename_secret(&mut self) {
        let Some(row) = self.focused_row() else {
            self.status = Status::error("No secret selected.");
            return;
        };
        let old = row.secret.key.clone();
        self.open_editor(Editor::new(
            EditTarget::RenameSecret { old: old.clone() },
            "Rename secret",
            &old,
            false,
        ));
    }

    fn start_edit_description(&mut self) {
        let Some(row) = self.focused_row() else {
            self.status = Status::error("No secret selected.");
            return;
        };
        let key = row.secret.key.clone();
        let current = row.secret.description.clone().unwrap_or_default();
        self.open_editor(Editor::new(
            EditTarget::Description { key: key.clone() },
            format!("Description · {key}"),
            &current,
            false,
        ));
    }

    fn start_delete_secret(&mut self) {
        let Some(row) = self.focused_row() else {
            self.status = Status::error("No secret selected.");
            return;
        };
        self.confirm = Some(ConfirmTarget::Secret(row.secret.key.clone()));
        self.mode = Mode::Confirm;
    }

    fn show_sync_status(&mut self) {
        match self.store.sync_status() {
            Ok(status) => {
                self.status = Status::ok(match status.latest_operation {
                    Some(op) => format!(
                        "sync: {} op(s), latest {} at {}",
                        status.operation_count, op.kind, op.created_at
                    ),
                    None => "sync: no local operations yet".to_string(),
                });
            }
            Err(err) => self.status = Status::error(short_error(&err)),
        }
    }

    fn open_editor(&mut self, editor: Editor) {
        self.editor = Some(editor);
        self.mode = Mode::Editor;
    }

    // -- detail (per-secret value inspector) --------------------------------

    fn open_detail(&mut self) {
        let Some(row) = self.focused_row() else {
            self.status = Status::error("No secret selected.");
            return;
        };
        if self.environments.is_empty() {
            self.status = Status::error("No environments yet. Press e to add one.");
            return;
        }
        self.detail = Some(Detail {
            secret_key: row.secret.key.clone(),
            selected_env: self.active_env,
            reveal: false,
            yank: None,
        });
        self.mode = Mode::Detail;
    }

    /// Value of a secret in a given environment, if set.
    fn variant_value(&self, secret_key: &str, environment_id: Id) -> Option<String> {
        self.rows
            .iter()
            .find(|row| row.secret.key == secret_key)
            .and_then(|row| row.variants.get(&environment_id).cloned())
    }

    fn detail_key(&mut self, key: KeyEvent) {
        let Some(mut detail) = self.detail.take() else {
            self.mode = Mode::Browse;
            return;
        };
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.mode = Mode::Browse;
                return;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                detail.selected_env = detail.selected_env.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let max = self.environments.len().saturating_sub(1);
                detail.selected_env = (detail.selected_env + 1).min(max);
            }
            KeyCode::Char('r') => detail.reveal = !detail.reveal,
            KeyCode::Enter | KeyCode::Char('v') => {
                self.detail = Some(detail);
                self.start_detail_edit();
                return;
            }
            KeyCode::Char('y') => {
                match self.environments.get(detail.selected_env).cloned() {
                    Some(environment) => match self
                        .variant_value(&detail.secret_key, environment.id)
                    {
                        Some(value) => {
                            self.status = Status::ok(format!(
                                "Copied {} value — press p on another environment to paste",
                                environment.name
                            ));
                            detail.yank = Some(Yank {
                                source_env: environment.name,
                                value,
                            });
                        }
                        None => {
                            self.status =
                                Status::error(format!("{} has no value to copy.", environment.name))
                        }
                    },
                    None => self.status = Status::error("No environment selected."),
                }
                self.detail = Some(detail);
                return;
            }
            KeyCode::Char('p') => {
                let key = detail.secret_key.clone();
                match (
                    self.environments.get(detail.selected_env).cloned(),
                    detail.yank.as_ref(),
                ) {
                    (Some(target), Some(yank)) => {
                        let value = yank.value.clone();
                        let source = yank.source_env.clone();
                        match self.store.set_variant(&key, &target.name, &value) {
                            Ok(()) => {
                                self.status =
                                    Status::ok(format!("Copied {source} → {}", target.name));
                                self.refresh();
                            }
                            Err(err) => self.status = Status::error(short_error(&err)),
                        }
                    }
                    (_, None) => {
                        self.status = Status::error("Nothing to paste — press y to copy first.")
                    }
                    (None, _) => self.status = Status::error("No environment selected."),
                }
                self.detail = Some(detail);
                return;
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                let key = detail.secret_key.clone();
                if let Some(environment) = self.environments.get(detail.selected_env).cloned() {
                    match self.store.unset_variant(&key, &environment.name) {
                        Ok(()) => {
                            self.status =
                                Status::ok(format!("Cleared {key} for {}", environment.name));
                            self.refresh();
                        }
                        Err(err) => self.status = Status::error(short_error(&err)),
                    }
                }
                self.detail = Some(detail);
                return;
            }
            _ => {}
        }
        clamp_index(&mut detail.selected_env, self.environments.len());
        self.detail = Some(detail);
    }

    fn start_detail_edit(&mut self) {
        let Some(detail) = self.detail.as_ref() else {
            return;
        };
        let Some(environment) = self.environments.get(detail.selected_env).cloned() else {
            self.status = Status::error("No environment selected.");
            return;
        };
        let key = detail.secret_key.clone();
        let current = self
            .rows
            .iter()
            .find(|row| row.secret.key == key)
            .and_then(|row| row.variants.get(&environment.id).cloned())
            .unwrap_or_default();
        let editor = Editor::new(
            EditTarget::SecretValue {
                key: key.clone(),
                environment: environment.name.clone(),
            },
            format!("{key} · {}  (empty clears)", environment.name),
            &current,
            true,
        )
        .returning_to(Mode::Detail);
        self.open_editor(editor);
    }

    fn open_switcher(&mut self, kind: SwitcherKind) {
        let selected = match kind {
            SwitcherKind::Project => self.active_project,
            SwitcherKind::Environment => self.active_env,
        };
        self.switcher = Some(Switcher {
            kind,
            filter: String::new(),
            selected,
        });
        self.mode = Mode::Switcher;
    }

    // -- editor mode --------------------------------------------------------

    fn editor_key(&mut self, key: KeyEvent) {
        let Some(mut editor) = self.editor.take() else {
            self.mode = Mode::Browse;
            return;
        };
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => {
                self.mode = editor.return_to;
                return;
            }
            KeyCode::Enter => {
                self.commit_editor(&editor);
                self.mode = editor.return_to;
                return;
            }
            KeyCode::Left => editor.cursor = editor.cursor.saturating_sub(1),
            KeyCode::Right => editor.cursor = (editor.cursor + 1).min(editor.buffer.len()),
            KeyCode::Home => editor.cursor = 0,
            KeyCode::End => editor.cursor = editor.buffer.len(),
            KeyCode::Backspace => editor.backspace(),
            KeyCode::Delete => editor.delete(),
            KeyCode::Char('u') if ctrl => {
                editor.buffer.clear();
                editor.cursor = 0;
            }
            KeyCode::Char('r') if ctrl && editor.masked => editor.reveal = !editor.reveal,
            KeyCode::Char(ch) => editor.insert(ch),
            _ => {}
        }
        // Live search: update the filter as the user types.
        if matches!(editor.target, EditTarget::Search) {
            self.filter = editor.value();
            self.selected_row = 0;
        }
        self.editor = Some(editor);
    }

    fn commit_editor(&mut self, editor: &Editor) {
        let value = editor.value();
        let trimmed = value.trim().to_string();

        if matches!(editor.target, EditTarget::Search) {
            self.filter = value;
            self.selected_row = 0;
            return;
        }

        // Names must not be blank; values may be (to clear them).
        let needs_nonempty = !matches!(
            editor.target,
            EditTarget::Search | EditTarget::SecretValue { .. } | EditTarget::Description { .. }
        );
        if needs_nonempty && trimmed.is_empty() {
            self.status = Status::error("Value cannot be empty.");
            return;
        }

        let result: Result<String, StoreError> = match &editor.target {
            EditTarget::Search => return,
            EditTarget::SecretValue { key, environment } => {
                if value.is_empty() {
                    self.store
                        .unset_variant(key, environment)
                        .map(|()| format!("Cleared {key} for {environment}"))
                } else {
                    self.store
                        .set_variant(key, environment, &value)
                        .map(|()| format!("Set {key} for {environment}"))
                }
            }
            EditTarget::AddSecret => self
                .store
                .add_secret(&trimmed, None)
                .map(|_| format!("Added secret {trimmed}")),
            EditTarget::RenameSecret { old } => self
                .store
                .rename_secret(old, &trimmed)
                .map(|_| format!("Renamed {old} to {trimmed}")),
            EditTarget::Description { key } => {
                let description = if value.trim().is_empty() {
                    None
                } else {
                    Some(value.trim())
                };
                self.store
                    .set_secret_description(key, description)
                    .map(|_| format!("Updated description for {key}"))
            }
            EditTarget::AddProject => self.store.add_project(&trimmed, None).map(|_| {
                self.pending_active_project = Some(trimmed.clone());
                format!("Added project {trimmed}")
            }),
            EditTarget::RenameProject { old } => self
                .store
                .rename_project(old, &trimmed)
                .map(|_| format!("Renamed project {old} to {trimmed}")),
            EditTarget::AddEnvironment => self.store.add_environment(&trimmed, None).map(|_| {
                self.pending_active_env = Some(trimmed.clone());
                format!("Added environment {trimmed}")
            }),
            EditTarget::RenameEnvironment { old } => self
                .store
                .rename_environment(old, &trimmed)
                .map(|_| format!("Renamed environment {old} to {trimmed}")),
        };

        match result {
            Ok(message) => {
                self.status = Status::ok(message);
                self.refresh();
                self.apply_pending_selection();
            }
            Err(err) => self.status = Status::error(short_error(&err)),
        }
    }

    fn apply_pending_selection(&mut self) {
        if let Some(name) = self.pending_active_project.take()
            && let Some(index) = self.projects.iter().position(|p| p.name == name)
        {
            self.active_project = index;
        }
        if let Some(name) = self.pending_active_env.take()
            && let Some(index) = self.environments.iter().position(|e| e.name == name)
        {
            self.active_env = index;
        }
    }

    // -- switcher mode ------------------------------------------------------

    fn switcher_items(&self, switcher: &Switcher) -> Vec<(usize, String)> {
        let query = switcher.filter.to_ascii_lowercase();
        let names: Vec<String> = match switcher.kind {
            SwitcherKind::Project => self.projects.iter().map(|p| p.name.clone()).collect(),
            SwitcherKind::Environment => self.environments.iter().map(|e| e.name.clone()).collect(),
        };
        names
            .into_iter()
            .enumerate()
            .filter(|(_, name)| query.is_empty() || name.to_ascii_lowercase().contains(&query))
            .collect()
    }

    fn switcher_key(&mut self, key: KeyEvent) {
        let Some(mut switcher) = self.switcher.take() else {
            self.mode = Mode::Browse;
            return;
        };
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let items = self.switcher_items(&switcher);

        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Browse;
                return;
            }
            KeyCode::Up => switcher.selected = switcher.selected.saturating_sub(1),
            KeyCode::Down => {
                let max = items.len().saturating_sub(1);
                switcher.selected = (switcher.selected + 1).min(max);
            }
            KeyCode::Enter => {
                if let Some((actual_index, _)) = items.get(switcher.selected).cloned() {
                    match switcher.kind {
                        SwitcherKind::Project => self.active_project = actual_index,
                        SwitcherKind::Environment => self.active_env = actual_index,
                    }
                    self.selected_row = 0;
                    self.reveal_cell = false;
                }
                self.mode = Mode::Browse;
                return;
            }
            KeyCode::Char('n') if ctrl => {
                let target = match switcher.kind {
                    SwitcherKind::Project => EditTarget::AddProject,
                    SwitcherKind::Environment => EditTarget::AddEnvironment,
                };
                let title = match switcher.kind {
                    SwitcherKind::Project => "New project",
                    SwitcherKind::Environment => "New environment",
                };
                self.open_editor(Editor::new(target, title, "", false));
                return;
            }
            KeyCode::Char('r') if ctrl => {
                if let Some((_, name)) = items.get(switcher.selected).cloned() {
                    let (target, title) = match switcher.kind {
                        SwitcherKind::Project => (
                            EditTarget::RenameProject { old: name.clone() },
                            "Rename project",
                        ),
                        SwitcherKind::Environment => (
                            EditTarget::RenameEnvironment { old: name.clone() },
                            "Rename environment",
                        ),
                    };
                    self.open_editor(Editor::new(target, title, &name, false));
                }
                return;
            }
            KeyCode::Char('d') if ctrl => {
                if let Some((_, name)) = items.get(switcher.selected).cloned() {
                    self.confirm = Some(match switcher.kind {
                        SwitcherKind::Project => ConfirmTarget::Project(name),
                        SwitcherKind::Environment => ConfirmTarget::Environment(name),
                    });
                    self.mode = Mode::Confirm;
                }
                return;
            }
            KeyCode::Backspace => {
                switcher.filter.pop();
                switcher.selected = 0;
            }
            KeyCode::Char(ch) => {
                switcher.filter.push(ch);
                switcher.selected = 0;
            }
            _ => {}
        }

        // Keep the selection within the (possibly filtered) list.
        let len = self.switcher_items(&switcher).len();
        clamp_index(&mut switcher.selected, len);
        self.switcher = Some(switcher);
    }

    // -- confirm mode -------------------------------------------------------

    fn confirm_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') => {
                let target = self.confirm.take();
                self.apply_delete(target);
                self.mode = Mode::Browse;
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.confirm = None;
                self.mode = Mode::Browse;
            }
            _ => {}
        }
    }

    fn apply_delete(&mut self, target: Option<ConfirmTarget>) {
        let result = match &target {
            Some(ConfirmTarget::Secret(key)) => self
                .store
                .remove_secret(key)
                .map(|()| format!("Deleted secret {key}")),
            Some(ConfirmTarget::Project(name)) => self
                .store
                .remove_project(name)
                .map(|()| format!("Deleted project {name}")),
            Some(ConfirmTarget::Environment(name)) => self
                .store
                .remove_environment(name, true)
                .map(|()| format!("Deleted environment {name}")),
            None => return,
        };
        match result {
            Ok(message) => {
                self.status = Status::ok(message);
                self.refresh();
            }
            Err(err) => self.status = Status::error(short_error(&err)),
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn draw(frame: &mut ratatui::Frame<'_>, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(4),
        ])
        .split(frame.area());

    draw_context_bar(frame, app, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(16), Constraint::Min(24)])
        .split(chunks[1]);

    draw_rail(frame, app, body[0]);
    draw_table(frame, app, body[1]);
    draw_footer(frame, app, chunks[2]);

    match app.mode {
        Mode::Detail => draw_detail(frame, app),
        Mode::Editor => draw_editor(frame, app),
        Mode::Switcher => draw_switcher(frame, app),
        Mode::Confirm => draw_confirm(frame, app),
        Mode::Help => draw_help(frame),
        Mode::Browse => {}
    }
}

fn draw_context_bar(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let mut spans = vec![
        Span::styled("envctl", bold.fg(Color::Cyan)),
        Span::raw("   Project "),
        Span::styled(
            app.active_project().map(|p| p.name.as_str()).unwrap_or("—"),
            bold,
        ),
        Span::raw("   Env "),
        Span::styled(
            app.active_environment()
                .map(|e| e.name.as_str())
                .unwrap_or("—"),
            bold,
        ),
        Span::raw("   "),
    ];

    match app.coverage() {
        Some((resolved, total, missing)) if missing.is_empty() => {
            spans.push(Span::styled(
                format!("Coverage {resolved}/{total} ✓"),
                Style::default().fg(Color::Green),
            ));
        }
        Some((resolved, total, missing)) => {
            spans.push(Span::styled(
                format!("Coverage {resolved}/{total} ⚠ "),
                Style::default().fg(Color::Red),
            ));
            spans.push(Span::styled(
                truncate(&missing.join(", "), 32),
                Style::default().fg(Color::Red),
            ));
        }
        None => spans.push(Span::raw("Coverage —")),
    }

    spans.push(Span::raw(format!("   sync {}", app.sync_ops)));

    let paragraph = Paragraph::new(Line::from(spans))
        .block(Block::default().borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn draw_rail(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let mut lines = vec![Line::styled(
        "PROJECTS",
        Style::default().add_modifier(Modifier::BOLD),
    )];
    if app.projects.is_empty() {
        lines.push(Line::styled(
            "  (none)",
            Style::default().fg(Color::DarkGray),
        ));
    }
    for (index, project) in app.projects.iter().enumerate() {
        lines.push(rail_line(&project.name, index == app.active_project));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "ENVIRONMENTS",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    if app.environments.is_empty() {
        lines.push(Line::styled(
            "  (none)",
            Style::default().fg(Color::DarkGray),
        ));
    }
    for (index, environment) in app.environments.iter().enumerate() {
        lines.push(rail_line(&environment.name, index == app.active_env));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn rail_line(name: &str, active: bool) -> Line<'static> {
    if active {
        Line::from(vec![
            Span::styled("▸ ", Style::default().fg(Color::Cyan)),
            Span::styled(
                name.to_string(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ])
    } else {
        Line::raw(format!("  {name}"))
    }
}

fn draw_table(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let filtered = app.filtered_rows();
    let active_project_id = app.active_project().map(|p| p.id);
    let active_env_id = app.active_environment().map(|e| e.id);

    // Header: KEY | ✓ | <env>… | value
    let mut header_cells = vec![Cell::from("KEY"), Cell::from("✓")];
    for (index, environment) in app.environments.iter().enumerate() {
        let style = if index == app.active_env {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::DIM)
        };
        header_cells.push(Cell::from(Span::styled(short(&environment.name, 4), style)));
    }
    let value_header = match app.active_environment() {
        Some(environment) => format!("value · {}", environment.name),
        None => "value".to_string(),
    };
    header_cells.push(Cell::from(value_header));
    let header = Row::new(header_cells).style(Style::default().add_modifier(Modifier::BOLD));

    let mut body = Vec::with_capacity(filtered.len());
    for &row_index in &filtered {
        let row = &app.rows[row_index];
        let assigned = active_project_id
            .map(|id| row.secret.assigned_project_ids.contains(&id))
            .unwrap_or(false);

        let mut cells = vec![
            Cell::from(row.secret.key.clone()),
            Cell::from(if assigned { "◆" } else { " " }),
        ];

        for (index, environment) in app.environments.iter().enumerate() {
            let present = row.variants.contains_key(&environment.id);
            let mut style = if present {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            if index == app.active_env {
                style = style.add_modifier(Modifier::BOLD);
            }
            cells.push(Cell::from(Span::styled(
                if present { "●" } else { "○" },
                style,
            )));
        }

        // Value preview for the active environment column. `r` reveals the
        // whole column so you can scan an environment's values at a glance.
        let preview = match active_env_id.and_then(|id| row.variants.get(&id)) {
            Some(value) => {
                if app.reveal_cell {
                    Span::raw(truncate(value, 24))
                } else {
                    Span::styled("••••••••", Style::default().fg(Color::DarkGray))
                }
            }
            None if assigned => Span::styled("— missing", Style::default().fg(Color::Red)),
            None => Span::styled("—", Style::default().fg(Color::DarkGray)),
        };
        cells.push(Cell::from(preview));

        let row_style = if assigned {
            Style::default()
        } else {
            Style::default().add_modifier(Modifier::DIM)
        };
        body.push(Row::new(cells).style(row_style));
    }

    let mut widths = vec![Constraint::Min(14), Constraint::Length(1)];
    for _ in &app.environments {
        widths.push(Constraint::Length(4));
    }
    widths.push(Constraint::Min(10));

    let scope = if app.assigned_only {
        format!(
            "Secrets · assigned to {}",
            app.active_project().map(|p| p.name.as_str()).unwrap_or("—")
        )
    } else {
        "Secrets · all".to_string()
    };
    let title = if app.filter.is_empty() {
        scope
    } else {
        format!("{scope}   /{}", app.filter)
    };

    let table = Table::new(body, widths)
        .header(header)
        .column_spacing(1)
        .block(Block::default().title(title).borders(Borders::ALL))
        .row_highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Color::Rgb(40, 44, 52)),
        )
        .highlight_symbol("▸ ");

    let mut state = TableState::default();
    if !filtered.is_empty() {
        state.select(Some(app.selected_row.min(filtered.len() - 1)));
    }
    frame.render_stateful_widget(table, area, &mut state);

    if filtered.is_empty() {
        let hint = if app.rows.is_empty() {
            "No secrets yet. Press a to add one."
        } else {
            "No secrets match. Press f to show all, or / to clear the search."
        };
        let inner = Rect {
            x: area.x + 2,
            y: area.y + 2,
            width: area.width.saturating_sub(4),
            height: 1,
        };
        frame.render_widget(
            Paragraph::new(Span::styled(hint, Style::default().fg(Color::DarkGray))),
            inner,
        );
    }
}

fn draw_footer(frame: &mut ratatui::Frame<'_>, app: &App, area: Rect) {
    let status_line = if app.status.text.is_empty() {
        Line::raw("")
    } else {
        let style = match app.status.level {
            Level::Ok => Style::default().fg(Color::Green),
            Level::Error => Style::default().fg(Color::Red),
            Level::Info => Style::default().fg(Color::Gray),
        };
        Line::styled(app.status.text.clone(), style)
    };

    let hints = "↑↓ move  ←→ env  enter details  v edit  space assign  p project  e env  a add  d delete  / search  f scope  r reveal  ? help  q quit";
    let hint_line = Line::styled(hints, Style::default().fg(Color::DarkGray));

    frame.render_widget(
        Paragraph::new(vec![status_line, hint_line])
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_detail(frame: &mut ratatui::Frame<'_>, app: &App) {
    let Some(detail) = app.detail.as_ref() else {
        return;
    };
    let Some(row) = app
        .rows
        .iter()
        .find(|row| row.secret.key == detail.secret_key)
    else {
        return;
    };

    let area = centered_rect(78, 74, frame.area());
    frame.render_widget(Clear, area);

    let bold = Style::default().add_modifier(Modifier::BOLD);
    let dim = Style::default().fg(Color::DarkGray);

    let assigned: Vec<String> = app
        .projects
        .iter()
        .filter(|project| row.secret.assigned_project_ids.contains(&project.id))
        .map(|project| project.name.clone())
        .collect();

    // Group environments that share an identical value so the user can see
    // which ones match without revealing the value itself. Only values shared
    // by 2+ environments get a group letter.
    let group_letters = value_groups(row);

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Description: ", bold),
            Span::raw(
                row.secret
                    .description
                    .clone()
                    .unwrap_or_else(|| "—".to_string()),
            ),
        ]),
        Line::from(vec![
            Span::styled("Assigned to: ", bold),
            Span::raw(if assigned.is_empty() {
                "(no projects)".to_string()
            } else {
                assigned.join(", ")
            }),
        ]),
    ];
    if let Some(yank) = detail.yank.as_ref() {
        lines.push(Line::from(vec![
            Span::styled("Clipboard:   ", bold),
            Span::styled(
                format!("{} value (press p to paste)", yank.source_env),
                Style::default().fg(Color::Yellow),
            ),
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("VALUES", bold),
        Span::styled(
            if detail.reveal {
                "   (revealed — r to hide)   ≡ = same value"
            } else {
                "   (r to reveal)   ≡ = same value"
            },
            dim,
        ),
    ]));

    for (index, environment) in app.environments.iter().enumerate() {
        let selected = index == detail.selected_env;
        let marker = if selected { "▸ " } else { "  " };
        let value = row.variants.get(&environment.id);
        let value_span = match value {
            Some(value) if detail.reveal => Span::raw(truncate(value, 44)),
            Some(_) => Span::styled("••••••••", dim),
            None => Span::styled("— not set", Style::default().fg(Color::Red)),
        };
        let name_style = if selected {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let mut spans = vec![Span::styled(
            format!("{marker}{:<14}", environment.name),
            name_style,
        )];
        // Sameness badge (e.g. "≡A"), colored per group.
        if let Some(letter) = value.and_then(|value| group_letters.get(value)) {
            spans.push(Span::styled(
                format!("≡{letter} "),
                Style::default().fg(group_color(*letter)),
            ));
        } else {
            spans.push(Span::raw("   "));
        }
        spans.push(value_span);
        lines.push(Line::from(spans));
    }

    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "↑↓ env · enter edit · y copy · p paste · r reveal · d clear · esc back",
        dim,
    ));

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title(format!(" {} ", detail.secret_key))
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_editor(frame: &mut ratatui::Frame<'_>, app: &App) {
    let Some(editor) = app.editor.as_ref() else {
        return;
    };
    let area = centered_rect(72, 24, frame.area());
    frame.render_widget(Clear, area);

    let display: Vec<char> = if editor.masked && !editor.reveal {
        vec!['•'; editor.buffer.len()]
    } else {
        editor.buffer.clone()
    };
    let before: String = display[..editor.cursor].iter().collect();
    let (cursor_ch, after): (String, String) = if editor.cursor < display.len() {
        (
            display[editor.cursor].to_string(),
            display[editor.cursor + 1..].iter().collect(),
        )
    } else {
        (" ".to_string(), String::new())
    };

    let input = Line::from(vec![
        Span::raw(before),
        Span::styled(cursor_ch, Style::default().add_modifier(Modifier::REVERSED)),
        Span::raw(after),
    ]);

    let hint = if editor.masked {
        "enter save · esc cancel · ctrl-r reveal · ctrl-u clear"
    } else {
        "enter save · esc cancel · ctrl-u clear"
    };
    let body = vec![
        input,
        Line::raw(""),
        Line::styled(hint, Style::default().fg(Color::DarkGray)),
    ];

    frame.render_widget(
        Paragraph::new(body)
            .block(
                Block::default()
                    .title(editor.title.clone())
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_switcher(frame: &mut ratatui::Frame<'_>, app: &App) {
    let Some(switcher) = app.switcher.as_ref() else {
        return;
    };
    let area = centered_rect(54, 60, frame.area());
    frame.render_widget(Clear, area);

    let title = match switcher.kind {
        SwitcherKind::Project => "Select project",
        SwitcherKind::Environment => "Select environment",
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("filter: ", Style::default().fg(Color::DarkGray)),
            Span::raw(if switcher.filter.is_empty() {
                "—".to_string()
            } else {
                switcher.filter.clone()
            }),
        ]),
        Line::raw(""),
    ];

    let items = app.switcher_items(switcher);
    if items.is_empty() {
        lines.push(Line::styled(
            "  (no matches — ctrl-n to add)",
            Style::default().fg(Color::DarkGray),
        ));
    }
    for (visible_index, (_, name)) in items.iter().enumerate() {
        if visible_index == switcher.selected {
            lines.push(Line::from(Span::styled(
                format!("▸ {name}"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
        } else {
            lines.push(Line::raw(format!("  {name}")));
        }
    }

    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "enter select · type to filter · ctrl-n new · ctrl-r rename · ctrl-d delete · esc",
        Style::default().fg(Color::DarkGray),
    ));

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_confirm(frame: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered_rect(56, 22, frame.area());
    let description = match &app.confirm {
        Some(ConfirmTarget::Secret(key)) => format!("secret \"{key}\" and its variants"),
        Some(ConfirmTarget::Project(name)) => format!("project \"{name}\""),
        Some(ConfirmTarget::Environment(name)) => {
            format!("environment \"{name}\" and its variants")
        }
        None => "this item".to_string(),
    };
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::raw(format!("Delete {description}?")),
            Line::raw(""),
            Line::styled(
                "y: confirm   n/esc: cancel",
                Style::default().fg(Color::DarkGray),
            ),
        ])
        .block(
            Block::default()
                .title("Confirm delete")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_help(frame: &mut ratatui::Frame<'_>) {
    let area = centered_rect(64, 80, frame.area());
    frame.render_widget(Clear, area);
    let rows = [
        ("↑ ↓ / j k", "Move between secrets"),
        ("← → / h l", "Change the active environment column"),
        ("PgUp/PgDn Home/End", "Jump through the list"),
        (
            "enter",
            "Detail view: per-env values, edit, copy (y/p), reveal",
        ),
        ("v", "Quick-edit the value for the active environment"),
        ("r", "Reveal the active environment's value column"),
        (
            "space",
            "Assign / unassign the secret to the active project",
        ),
        ("p", "Switch active project (ctrl-n/r/d inside to manage)"),
        (
            "e",
            "Switch active environment (ctrl-n/r/d inside to manage)",
        ),
        ("a", "Add a secret"),
        ("R", "Rename the focused secret"),
        ("c", "Edit the focused secret's description"),
        ("d", "Delete the focused secret"),
        ("/", "Search secrets by key or description"),
        ("f", "Toggle assigned-only / all secrets"),
        ("S", "Show sync status"),
        ("? / esc", "Close this help"),
        ("q", "Quit"),
    ];
    let mut lines = vec![Line::styled(
        "Keys",
        Style::default().add_modifier(Modifier::BOLD),
    )];
    for (keys, description) in rows {
        lines.push(Line::from(vec![
            Span::styled(format!("  {keys:<20}"), Style::default().fg(Color::Cyan)),
            Span::raw(description),
        ]));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title("Help").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Assign a group letter to every value shared by 2+ of a secret's
/// environments, in order of first appearance. Singletons are omitted.
fn value_groups(row: &SecretRow) -> BTreeMap<String, char> {
    let mut counts: BTreeMap<&String, usize> = BTreeMap::new();
    for value in row.variants.values() {
        *counts.entry(value).or_default() += 1;
    }
    let mut letters = BTreeMap::new();
    let mut next = b'A';
    // Iterate the variants in a stable order so letters are deterministic.
    for value in row.variants.values() {
        if counts.get(value).copied().unwrap_or(0) >= 2 && !letters.contains_key(value) {
            letters.insert(value.clone(), next as char);
            next += 1;
        }
    }
    letters
}

fn group_color(letter: char) -> Color {
    const PALETTE: [Color; 6] = [
        Color::Yellow,
        Color::Magenta,
        Color::Blue,
        Color::Green,
        Color::Cyan,
        Color::LightRed,
    ];
    let index = (letter as u8).wrapping_sub(b'A') as usize;
    PALETTE[index % PALETTE.len()]
}

fn short_error(err: &StoreError) -> String {
    match err {
        StoreError::Domain(domain) => domain.to_string(),
        other => other.to_string(),
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        let kept: String = value.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
    }
}

fn short(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn move_index(index: &mut usize, len: usize, delta: isize) {
    if len == 0 {
        *index = 0;
        return;
    }
    let max = len.saturating_sub(1) as isize;
    *index = (*index as isize + delta).clamp(0, max) as usize;
}

fn clamp_index(index: &mut usize, len: usize) {
    if len == 0 {
        *index = 0;
    } else if *index >= len {
        *index = len - 1;
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded() -> App {
        let mut store = Store::open_memory_for_tests().unwrap();
        store.add_project("bowtieduck", None).unwrap();
        store.add_environment("dev", None).unwrap();
        store.add_secret("DATABASE_URL", None).unwrap();
        store.add_secret("OPENAI_API_KEY", None).unwrap();
        App::new(store).unwrap()
    }

    #[test]
    fn search_filters_rows() {
        let mut app = seeded();
        app.filter = "openai".to_string();
        let filtered = app.filtered_rows();
        assert_eq!(filtered.len(), 1);
        assert_eq!(app.rows[filtered[0]].secret.key, "OPENAI_API_KEY");
    }

    #[test]
    fn assignment_toggle_updates_store() {
        let mut app = seeded();
        app.selected_row = 0;
        app.toggle_assignment();
        let secret = app.store.get_secret("DATABASE_URL").unwrap();
        assert_eq!(secret.assigned_project_ids.len(), 1);
    }

    #[test]
    fn coverage_reflects_assignment_and_variants() {
        let mut app = seeded();
        app.store
            .assign_secret("DATABASE_URL", "bowtieduck")
            .unwrap();
        app.store
            .set_variant("DATABASE_URL", "dev", "postgres://localhost/dev")
            .unwrap();
        app.refresh();
        let (resolved, total, missing) = app.coverage().unwrap();
        assert_eq!((resolved, total), (1, 1));
        assert!(missing.is_empty());
    }

    #[test]
    fn detail_edit_writes_value_and_returns_to_detail() {
        let mut app = seeded();
        app.selected_row = 0; // DATABASE_URL (secrets are sorted by key)

        // enter -> detail, then enter -> edit the selected environment's value.
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        assert_eq!(app.mode, Mode::Detail);
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        assert_eq!(app.mode, Mode::Editor);

        for ch in "postgres://localhost/dev".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE))
                .unwrap();
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();

        assert_eq!(
            app.mode,
            Mode::Detail,
            "editor should return to the detail view"
        );
        assert_eq!(
            app.store
                .get_variant("DATABASE_URL", "dev")
                .unwrap()
                .as_deref(),
            Some("postgres://localhost/dev")
        );
    }

    #[test]
    fn copy_value_between_environments() {
        let mut store = Store::open_memory_for_tests().unwrap();
        store.add_environment("dev", None).unwrap();
        store.add_environment("prod", None).unwrap();
        store.add_secret("DATABASE_URL", None).unwrap();
        store
            .set_variant("DATABASE_URL", "dev", "postgres://localhost/dev")
            .unwrap();
        let mut app = App::new(store).unwrap();
        app.selected_row = 0;

        // Enter detail, yank the "dev" value (selected_env starts at 0 = dev),
        // move to "prod", and paste.
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE))
            .unwrap();
        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE))
            .unwrap();
        app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE))
            .unwrap();

        assert_eq!(
            app.store
                .get_variant("DATABASE_URL", "prod")
                .unwrap()
                .as_deref(),
            Some("postgres://localhost/dev")
        );

        // Both environments now share a value, so they form one group.
        let row = app
            .rows
            .iter()
            .find(|row| row.secret.key == "DATABASE_URL")
            .unwrap();
        let groups = value_groups(row);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups.get("postgres://localhost/dev").copied(), Some('A'));
    }

    #[test]
    fn duplicate_add_reports_error_without_crashing() {
        let mut app = seeded();
        let editor = Editor::new(
            EditTarget::AddSecret,
            "New secret key",
            "DATABASE_URL",
            false,
        );
        app.commit_editor(&editor);
        assert_eq!(app.status.level, Level::Error);
        assert!(app.status.text.contains("already exists"));
    }
}
