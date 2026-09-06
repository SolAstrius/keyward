//! Extra context an agent (or a human) can attach to a request.
//!
//! Three channels, none of which require ssh's cooperation:
//!
//! 1. **Environment of the nearest readable ancestor.** The kernel hides the
//!    environment of platform binaries, so `ssh` and `/bin/zsh` give nothing —
//!    but an agent's own binary does, and that is where session identity lives
//!    (`CLAUDE_CODE_HOST_SESSION_ID`, `OTEL_SERVICE_NAME`, W3C `BAGGAGE`).
//!    Strictly allow-listed: the same environment also holds OAuth tokens.
//!
//! 2. **A sidecar file keyed by pid.** Anything that wants to explain a
//!    specific action writes JSON to `context/<pid>.json` first. This is the
//!    only channel that can carry a per-request reason, because a variable set
//!    as `FOO=bar ssh …` lands only in ssh's own hidden environment.
//!
//! 3. **The repository itself.** For git work the commit message, branch and
//!    remote are readable from disk, so "what was signed" needs no cooperation
//!    from anyone.

use crate::attrib::{proc_argv_env, ProcInfo};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Environment variables worth surfacing. Everything else is ignored — an
/// allow-list, so a new secret in the agent's environment can never leak in.
const ENV_ALLOW: &[&str] = &[
    "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_CODE_HOST_SESSION_ID",
    "CLAUDE_AGENT_SDK_VERSION",
    "CLAUDE_CODE_SUBSCRIPTION_TYPE",
    "OTEL_SERVICE_NAME",
    "OTEL_RESOURCE_ATTRIBUTES",
    "BAGGAGE",
    "TERM_PROGRAM",
    "__CFBundleIdentifier",
    "SSH_CONNECTION",
];

/// Belt and braces on top of the allow-list.
fn looks_secret(key: &str) -> bool {
    let k = key.to_ascii_uppercase();
    ["TOKEN", "SECRET", "PASSWORD", "PASSWD", "APIKEY", "API_KEY", "CREDENTIAL", "COOKIE"]
        .iter()
        .any(|needle| k.contains(needle))
}

fn wanted(key: &str) -> bool {
    if looks_secret(key) {
        return false;
    }
    // KEYWARD_* is the deliberate free-form channel for anyone who wants to
    // label a long-running process.
    key.starts_with("KEYWARD_") || ENV_ALLOW.contains(&key)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GitContext {
    pub branch: Option<String>,
    pub remote: Option<String>,
    /// Subject line of the message being signed.
    pub subject: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Context {
    /// Allow-listed environment of the nearest ancestor that exposes one.
    pub env: BTreeMap<String, String>,
    /// Which process the environment came from.
    pub env_from_pid: Option<i32>,
    pub env_from: Option<String>,
    /// Free-form JSON dropped by an agent for one of the pids in the chain.
    pub declared: Option<serde_json::Value>,
    pub declared_from_pid: Option<i32>,
    pub git: Option<GitContext>,
    /// Human title of the agent session, when one can be resolved.
    pub session_title: Option<String>,
}

/// Turn `local_fbfbe49b-…` into "SSH handshakes failing over mesh".
///
/// Claude Code keeps a record per session under its application support
/// directory, named for the session id and carrying the title it displays.
/// A raw UUID tells a human nothing; the title tells them which conversation
/// asked for the key.
fn session_title(id: &str) -> Option<String> {
    if id.is_empty() || id.contains('/') || id.contains("..") {
        return None;
    }
    let home = std::env::var("HOME").ok()?;
    let root = PathBuf::from(home).join("Library/Application Support/Claude/claude-code-sessions");
    let target = format!("{id}.json");

    // <root>/<workspace>/<project>/<session>.json
    for a in std::fs::read_dir(&root).ok()?.flatten() {
        let Ok(inner) = std::fs::read_dir(a.path()) else { continue };
        for b in inner.flatten() {
            let f = b.path().join(&target);
            if !f.is_file() {
                continue;
            }
            let text = std::fs::read_to_string(&f).ok()?;
            let v: serde_json::Value = serde_json::from_str(&text).ok()?;
            return v
                .get("title")
                .and_then(|t| t.as_str())
                .filter(|t| !t.is_empty())
                .map(|t| truncate(t, 90));
        }
    }
    None
}

fn context_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join("Library/Application Support/Keyward/context")
}

/// Walk the chain and take the environment of the first process that exposes
/// one — the caller itself if it is not a platform binary, otherwise whatever
/// launched it.
fn env_from_chain(chain: &[ProcInfo]) -> (BTreeMap<String, String>, Option<i32>, Option<String>) {
    for p in chain {
        let (_, env) = proc_argv_env(p.pid);
        if env.is_empty() {
            continue;
        }
        let picked: BTreeMap<String, String> = env
            .into_iter()
            .filter(|(k, _)| wanted(k))
            .map(|(k, v)| (k, truncate(&v, 400)))
            .collect();
        return (picked, Some(p.pid), p.name.clone());
    }
    (BTreeMap::new(), None, None)
}

/// A declaration filed against any pid in the chain. Nearest wins, so a
/// per-command wrapper overrides a long-lived session's own label.
fn declared_for(chain: &[ProcInfo]) -> (Option<serde_json::Value>, Option<i32>) {
    let dir = context_dir();
    for p in chain {
        let f = dir.join(format!("{}.json", p.pid));
        if let Ok(s) = std::fs::read_to_string(&f) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                return (Some(v), Some(p.pid));
            }
        }
    }
    (None, None)
}

/// `.git` is a directory in a normal clone and a pointer file in a worktree.
fn git_dir(repo: &Path) -> Option<PathBuf> {
    let dot = repo.join(".git");
    if dot.is_dir() {
        return Some(dot);
    }
    let s = std::fs::read_to_string(&dot).ok()?;
    let p = s.trim().strip_prefix("gitdir:")?.trim();
    Some(PathBuf::from(p))
}

fn origin_url(gitdir: &Path) -> Option<String> {
    let cfg = std::fs::read_to_string(gitdir.join("config")).ok()?;
    let mut in_origin = false;
    for line in cfg.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_origin = t.starts_with("[remote \"origin\"]");
            continue;
        }
        if in_origin {
            if let Some(v) = t.strip_prefix("url") {
                return Some(v.trim().trim_start_matches('=').trim().to_string());
            }
        }
    }
    None
}

pub fn git_context(repo_path: &str, want_message: bool) -> Option<GitContext> {
    let gitdir = git_dir(Path::new(repo_path))?;

    let branch = std::fs::read_to_string(gitdir.join("HEAD")).ok().map(|h| {
        let h = h.trim();
        h.strip_prefix("ref: refs/heads/")
            .map(str::to_string)
            .unwrap_or_else(|| h.chars().take(12).collect())
    });

    // git writes COMMIT_EDITMSG before it asks for the signature, so at this
    // moment it holds exactly the message about to be signed.
    let subject = if want_message {
        std::fs::read_to_string(gitdir.join("COMMIT_EDITMSG"))
            .ok()
            .and_then(|m| {
                m.lines()
                    .map(str::trim)
                    .find(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(|l| truncate(l, 200))
            })
    } else {
        None
    };

    Some(GitContext {
        branch,
        remote: origin_url(&gitdir),
        subject,
    })
}

pub fn gather(chain: &[ProcInfo], repo_path: Option<&str>, signing_commit: bool) -> Context {
    let (env, env_from_pid, env_from) = env_from_chain(chain);
    let (declared, declared_from_pid) = declared_for(chain);
    let git = repo_path.and_then(|r| git_context(r, signing_commit));
    let title = env
        .get("CLAUDE_CODE_HOST_SESSION_ID")
        .and_then(|id| session_title(id));
    Context {
        env,
        env_from_pid,
        env_from,
        declared,
        declared_from_pid,
        git,
        session_title: title,
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect::<String>() + "…"
    }
}
