//! Event log. Append-only JSONL that the SwiftUI app tails.

use crate::attrib::Attribution;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A client asked which keys exist. Cheap, frequent, no signature.
    ListIdentities,
    /// A real signature — the event that matters.
    Sign,
    /// ssh telling the agent which host this session is bound to.
    SessionBind,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts: f64,
    pub kind: Kind,
    pub who: Attribution,
    /// SHA256:… of the key involved, when there is one.
    pub key_fp: Option<String>,
    pub key_comment: Option<String>,
    /// Which upstream actually holds the key.
    pub upstream: Option<String>,
    /// Host key fingerprint from session-bind, when ssh offered one.
    pub bound_host_fp: Option<String>,
    pub outcome: String,
    pub duration_ms: u64,
}

pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub struct Log {
    path: PathBuf,
    file: Mutex<Option<File>>,
    max_bytes: u64,
}

impl Log {
    pub fn new(path: PathBuf, max_bytes: u64) -> Self {
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        Log {
            path,
            file: Mutex::new(None),
            max_bytes,
        }
    }

    pub fn append(&self, ev: &Event) {
        let line = match serde_json::to_string(ev) {
            Ok(l) => l,
            Err(_) => return,
        };
        let mut guard = match self.file.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if guard.is_none() {
            *guard = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .ok();
        }
        if let Some(f) = guard.as_mut() {
            let _ = writeln!(f, "{line}");
            let _ = f.flush();
            if let Ok(md) = f.metadata() {
                if md.len() > self.max_bytes {
                    // Keep one generation, then start clean. The UI reads both.
                    let rotated = self.path.with_extension("jsonl.1");
                    let _ = fs::rename(&self.path, rotated);
                    *guard = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&self.path)
                        .ok();
                }
            }
        }
    }
}
