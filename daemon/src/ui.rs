//! Telling the app that a signature is in flight.
//!
//! The system Touch ID sheet cannot be restyled, reparented or screenshotted —
//! it belongs to `coreautha` and sits at window layer 1000 precisely so no app
//! can dress it up or fake it. What we can do is put a card *behind* it. So the
//! daemon asks the app to raise that card, waits briefly for confirmation so
//! the ordering looks deliberate, signs (the sheet appears on top), and tells
//! the app to take it away.
//!
//! Best-effort throughout: if the app is not running the connection simply
//! fails and the signature proceeds. The card is context, never a gate — making
//! it one would mean quitting the UI breaks SSH.

use crate::attrib::Attribution;
use serde::Serialize;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Serialize)]
struct Show<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    headline: &'a str,
    app: Option<String>,
    app_bundle: Option<String>,
    process: Option<String>,
    key: Option<String>,
    fingerprint: Option<String>,
    host: Option<String>,
    repo: Option<String>,
    branch: Option<String>,
    subject: Option<String>,
    /// The actual command or operation — the card has room for it, the sheet
    /// does not, and "run a command" without saying which is useless.
    command: Option<String>,
    /// True when `command` is a script recovered from stdin rather than argv.
    script: bool,
    chain: Vec<String>,
    session: Option<String>,
}

fn socket_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join("Library/Application Support/Keyward/ui.sock")
}

/// Raise the card. Returns the live connection; dropping it hides the card.
pub struct Card(Option<UnixStream>);

impl Card {
    pub fn done(mut self) {
        if let Some(s) = self.0.as_mut() {
            let _ = s.write_all(b"{\"type\":\"done\"}\n");
            let _ = s.flush();
        }
    }
}

/// `ssh host bash -s` names the shell, not the work — the work is on stdin.
fn reads_stdin(cmd: &str) -> bool {
    matches!(
        cmd.trim(),
        "bash -s" | "sh -s" | "zsh -s" | "bash" | "sh" | "zsh" | "bash -" | "sh -" | "cat"
    )
}

/// The script a stdin-reading shell was handed, when it is recoverable.
///
/// zsh writes a heredoc to a temp file, so fd 0 is a plain vnode we can read.
/// Anything genuinely piped is a pipe with no backing file and stays unknown —
/// this returns None there rather than inventing something.
fn stdin_script(pid: i32) -> Option<String> {
    const MAX: u64 = 64 * 1024;
    let path = crate::attrib::fd_path(pid, 0)?;
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX {
        return None;
    }
    let text = std::fs::read_to_string(&path).ok()?;
    let t = text.trim();
    if t.is_empty() { None } else { Some(t.to_string()) }
}

pub fn show(who: &Attribution, headline: &str, key: Option<&str>, fp: Option<&str>) -> Card {
    let mut stream = match UnixStream::connect(socket_path()) {
        Ok(s) => s,
        Err(_) => return Card(None), // app not running; sign without the card
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(600)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(600)));

    let git = who.context.git.as_ref();

    let raw = who
        .purpose
        .remote_command
        .clone()
        .or_else(|| who.process.as_ref().map(|p| p.commandline()));
    let (command, is_script) = match raw {
        Some(c) if reads_stdin(&c) => match who.process.as_ref().and_then(|p| stdin_script(p.pid)) {
            Some(script) => (Some(script), true),
            // Honest about the gap: a pipe leaves nothing to read.
            None => (Some(format!("{c}   (script piped on stdin — not readable)")), false),
        },
        other => (other, false),
    };
    let msg = Show {
        kind: "show",
        headline,
        app: who.app.as_ref().map(|a| a.name.clone()),
        app_bundle: who.app.as_ref().map(|a| a.bundle_path.clone()),
        process: who.process.as_ref().and_then(|p| p.name.clone()),
        key: key.map(str::to_string),
        fingerprint: fp.map(str::to_string),
        host: who.purpose.host.clone(),
        repo: who.purpose.repo.clone(),
        branch: git.and_then(|g| g.branch.clone()),
        subject: git.and_then(|g| g.subject.clone()),
        command: command.clone(),
        script: is_script,
        chain: who
            .ancestry
            .iter()
            .rev()
            .filter_map(|p| p.name.clone())
            .collect(),
        // The title if we could resolve it, the raw id only as a last resort.
        session: who
            .context
            .session_title
            .clone()
            .or_else(|| who.context.env.get("CLAUDE_CODE_HOST_SESSION_ID").cloned()),
    };

    let Ok(mut line) = serde_json::to_vec(&msg) else {
        return Card(Some(stream));
    };
    line.push(b'\n');
    if stream.write_all(&line).is_err() {
        return Card(None);
    }
    let _ = stream.flush();

    // Wait for the card to actually be on screen before triggering the sheet,
    // so it never flashes up after the sheet it is meant to sit behind.
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return Card(Some(stream)),
    });
    let mut ack = String::new();
    let _ = reader.read_line(&mut ack);

    Card(Some(stream))
}
