//! What is this signature actually *for*?
//!
//! "Claude asked" is true but useless — the interesting distinction is between
//! logging into a server, pushing a branch, and signing a commit, which look
//! identical at the agent socket. They are separable from the caller's argv:
//! git signs commits by running `ssh-keygen -Y sign -n git`, and moves objects
//! by running `ssh <host> git-receive-pack '<repo>'`. Neither ever names the
//! local repository, so that comes from the caller's working directory.

use crate::attrib::ProcInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    SshLogin,
    RemoteCommand,
    GitFetch,
    GitPush,
    GitOverSsh,
    CommitSigning,
    Signing,
    FileTransfer,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Purpose {
    pub kind: Kind,
    /// One line a human can read without decoding anything.
    pub summary: String,
    pub host: Option<String>,
    /// Local repository name, when the request came from inside one.
    pub repo: Option<String>,
    pub repo_path: Option<String>,
    /// Remote repository path, e.g. SolAstrius/nixos-config.git
    pub remote_repo: Option<String>,
    /// ssh-keygen -Y sign namespace ("git" for commits and tags).
    pub namespace: Option<String>,
    pub remote_command: Option<String>,
}

/// Flags that consume the following argument, so it is never the destination.
const SSH_TAKES_ARG: &[&str] = &[
    "-o", "-i", "-p", "-l", "-F", "-b", "-c", "-D", "-E", "-e", "-I", "-J", "-L", "-m", "-O", "-Q",
    "-R", "-S", "-W", "-w",
];

/// Split an ssh argv into its destination and the remote command after it.
fn split_ssh(args: &[String]) -> (Option<String>, Option<String>) {
    let mut i = 1;
    let mut dest: Option<String> = None;
    while i < args.len() {
        let a = &args[i];
        if dest.is_none() {
            if SSH_TAKES_ARG.contains(&a.as_str()) {
                i += 2;
                continue;
            }
            if a.starts_with('-') {
                i += 1;
                continue;
            }
            dest = Some(a.clone());
            i += 1;
            continue;
        }
        break;
    }
    let rest: Vec<String> = args.iter().skip(i).cloned().collect();
    let cmd = if rest.is_empty() {
        None
    } else {
        Some(rest.join(" "))
    };
    (dest, cmd)
}

/// Nearest enclosing git repository of a path.
fn repo_root(start: &str) -> Option<String> {
    let mut p = std::path::Path::new(start);
    loop {
        if p.join(".git").exists() {
            return Some(p.to_string_lossy().into_owned());
        }
        p = p.parent()?;
    }
}

fn basename(p: &str) -> String {
    std::path::Path::new(p)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.to_string())
}

/// Pull `SolAstrius/nixos-config.git` out of `git-receive-pack 'SolAstrius/…'`.
fn pack_repo(arg: &str) -> Option<String> {
    let rest = arg
        .split_once("git-upload-pack")
        .or_else(|| arg.split_once("git-receive-pack"))
        .map(|(_, r)| r)?;
    let trimmed = rest.trim().trim_matches(|c| c == '\'' || c == '"');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// The working directory of the nearest git process in the chain, falling back
/// to the caller's own — `git` spawns ssh from inside the repository.
fn git_cwd(chain: &[ProcInfo]) -> Option<String> {
    chain
        .iter()
        .find(|p| p.name.as_deref() == Some("git"))
        .and_then(|p| p.cwd.clone())
        .or_else(|| chain.first().and_then(|p| p.cwd.clone()))
}

fn arg_after(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

pub fn classify(chain: &[ProcInfo]) -> Purpose {
    let caller = match chain.first() {
        Some(c) => c,
        None => {
            return Purpose {
                kind: Kind::Unknown,
                summary: "Unknown request".into(),
                host: None,
                repo: None,
                repo_path: None,
                remote_repo: None,
                namespace: None,
                remote_command: None,
            }
        }
    };
    let name = caller.name.clone().unwrap_or_default();
    let args = &caller.args;

    let local = git_cwd(chain).and_then(|c| repo_root(&c));
    let repo = local.as_deref().map(basename);

    // git commit / tag signing: ssh-keygen -Y sign -n git
    if name == "ssh-keygen" && args.iter().any(|a| a == "-Y") {
        let op = arg_after(args, "-Y").unwrap_or_default();
        let ns = arg_after(args, "-n");
        if op == "sign" {
            let (kind, summary) = match (ns.as_deref(), repo.as_deref()) {
                (Some("git"), Some(r)) => (
                    Kind::CommitSigning,
                    format!("Signed a git commit in {r}"),
                ),
                (Some("git"), None) => (Kind::CommitSigning, "Signed a git commit".to_string()),
                (Some(other), _) => (Kind::Signing, format!("Signed data (namespace {other})")),
                (None, _) => (Kind::Signing, "Signed data".to_string()),
            };
            return Purpose {
                kind,
                summary,
                host: None,
                repo,
                repo_path: local,
                remote_repo: None,
                namespace: ns,
                remote_command: None,
            };
        }
    }

    if name == "scp" || name == "sftp" {
        let (dest, _) = split_ssh(args);
        let summary = match dest.as_deref() {
            Some(h) => format!("File transfer with {h}"),
            None => "File transfer".to_string(),
        };
        return Purpose {
            kind: Kind::FileTransfer,
            summary,
            host: dest,
            repo,
            repo_path: local,
            remote_repo: None,
            namespace: None,
            remote_command: None,
        };
    }

    if name == "ssh" {
        let (dest, cmd) = split_ssh(args);
        let host = dest.clone().unwrap_or_else(|| "unknown host".into());
        let remote_repo = cmd.as_deref().and_then(pack_repo);

        if let Some(c) = cmd.as_deref() {
            if c.contains("git-receive-pack") {
                return Purpose {
                    kind: Kind::GitPush,
                    summary: match &remote_repo {
                        Some(r) => format!("git push to {host} — {r}"),
                        None => format!("git push to {host}"),
                    },
                    host: dest,
                    repo,
                    repo_path: local,
                    remote_repo,
                    namespace: None,
                    remote_command: cmd,
                };
            }
            if c.contains("git-upload-pack") {
                return Purpose {
                    kind: Kind::GitFetch,
                    summary: match &remote_repo {
                        Some(r) => format!("git fetch from {host} — {r}"),
                        None => format!("git fetch from {host}"),
                    },
                    host: dest,
                    repo,
                    repo_path: local,
                    remote_repo,
                    namespace: None,
                    remote_command: cmd,
                };
            }
            return Purpose {
                kind: Kind::RemoteCommand,
                summary: format!("Ran `{}` on {host}", truncate(c, 60)),
                host: dest,
                repo,
                repo_path: local,
                remote_repo: None,
                namespace: None,
                remote_command: cmd,
            };
        }

        let via_git = chain.iter().any(|p| p.name.as_deref() == Some("git"));
        return Purpose {
            kind: if via_git { Kind::GitOverSsh } else { Kind::SshLogin },
            summary: if via_git {
                format!("git over SSH to {host}")
            } else {
                format!("SSH login to {host}")
            },
            host: dest,
            repo,
            repo_path: local,
            remote_repo: None,
            namespace: None,
            remote_command: None,
        };
    }

    Purpose {
        kind: Kind::Unknown,
        summary: format!("{} used your key", if name.is_empty() { "A process" } else { &name }),
        host: None,
        repo,
        repo_path: local,
        remote_repo: None,
        namespace: None,
        remote_command: None,
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n).collect();
        format!("{t}…")
    }
}
