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

pub fn show(who: &Attribution, headline: &str, key: Option<&str>, fp: Option<&str>) -> Card {
    let mut stream = match UnixStream::connect(socket_path()) {
        Ok(s) => s,
        Err(_) => return Card(None), // app not running; sign without the card
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(600)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(600)));

    let git = who.context.git.as_ref();
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
        command: who
            .purpose
            .remote_command
            .clone()
            .or_else(|| who.process.as_ref().map(|p| p.commandline())),
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
