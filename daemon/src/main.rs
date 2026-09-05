mod agent;
mod attrib;
mod event;
mod purpose;
mod upstream;
mod wire;

use agent::Ctx;
use event::Log;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use upstream::Upstream;

#[derive(Debug, Serialize, Deserialize)]
struct UpstreamCfg {
    name: String,
    path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    listen: String,
    log: String,
    upstreams: Vec<UpstreamCfg>,
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
    #[serde(default = "default_max_log")]
    max_log_bytes: u64,
}

fn default_timeout() -> u64 {
    10
}
fn default_max_log() -> u64 {
    32 * 1024 * 1024
}

fn home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/tmp".into())
}

impl Default for Config {
    fn default() -> Self {
        let h = home();
        Config {
            listen: format!("{h}/.ssh/keyward.sock"),
            log: format!("{h}/Library/Application Support/Keyward/events.jsonl"),
            upstreams: vec![
                UpstreamCfg {
                    name: "Secretive".into(),
                    path: format!(
                        "{h}/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh"
                    ),
                },
                UpstreamCfg {
                    name: "gpg-agent".into(),
                    path: format!("{h}/.gnupg/S.gpg-agent.ssh"),
                },
            ],
            timeout_secs: default_timeout(),
            max_log_bytes: default_max_log(),
        }
    }
}

fn load_config(path: Option<&str>) -> Config {
    let p = path
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("{}/.config/keyward/config.json", home())));
    match std::fs::read_to_string(&p) {
        Ok(s) => match serde_json::from_str(&s) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("keywardd: bad config {}: {e} — using defaults", p.display());
                Config::default()
            }
        },
        Err(_) => Config::default(),
    }
}

/// Bind the listen socket, clearing a stale one but never stealing a live one.
///
/// ssh-agent-mux crash-looped forever on "Address already in use" because it
/// treated any existing socket file as fatal. A socket file that nothing is
/// listening on is just debris; one with a live listener means we should stand
/// down.
fn bind(path: &str) -> std::io::Result<UnixListener> {
    if std::path::Path::new(path).exists() {
        match UnixStream::connect(path) {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "another keywardd is already listening here",
                ));
            }
            Err(_) => {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let l = UnixListener::bind(path)?;
    let _ = std::fs::set_permissions(
        path,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    );
    Ok(l)
}

/// Ask our own socket for its identity list. This is what a watchdog runs:
/// it catches the failure launchd cannot see — a process that is alive and
/// accepting connections but no longer answering them.
fn health(path: &str, timeout: Duration) -> i32 {
    let mut s = match UnixStream::connect(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("unhealthy: cannot connect to {path}: {e}");
            return 1;
        }
    };
    if s.set_read_timeout(Some(timeout)).is_err() || s.set_write_timeout(Some(timeout)).is_err() {
        return 1;
    }
    if s.write_all(&wire::frame(&[agent::REQUEST_IDENTITIES])).is_err() {
        eprintln!("unhealthy: write failed");
        return 1;
    }
    let mut len = [0u8; 4];
    match s.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("unhealthy: no answer within {timeout:?}: {e}");
            return 1;
        }
    }
    let n = u32::from_be_bytes(len);
    let mut body = vec![0u8; n as usize];
    if s.read_exact(&mut body).is_err() {
        eprintln!("unhealthy: truncated answer");
        return 1;
    }
    let mut r = wire::Reader::new(&body);
    match (r.u8(), r.u32()) {
        (Some(agent::IDENTITIES_ANSWER), Some(count)) => {
            println!("healthy: {count} keys");
            0
        }
        _ => {
            eprintln!("unhealthy: unexpected reply");
            1
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg_path: Option<String> = None;
    let mut want_health = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                cfg_path = args.get(i + 1).cloned();
                i += 1;
            }
            "--health" => want_health = true,
            "--help" | "-h" => {
                println!("keywardd [--config PATH] [--health]");
                return;
            }
            other => eprintln!("keywardd: ignoring unknown argument {other}"),
        }
        i += 1;
    }

    let cfg = load_config(cfg_path.as_deref());
    let timeout = Duration::from_secs(cfg.timeout_secs);

    if want_health {
        std::process::exit(health(&cfg.listen, timeout));
    }

    let listener = match bind(&cfg.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("keywardd: cannot listen on {}: {e}", cfg.listen);
            std::process::exit(1);
        }
    };

    let ctx = Arc::new(Ctx {
        upstreams: cfg
            .upstreams
            .iter()
            .map(|u| Upstream {
                name: u.name.clone(),
                path: u.path.clone(),
            })
            .collect(),
        routes: RwLock::new(HashMap::new()),
        comments: RwLock::new(HashMap::new()),
        log: Log::new(PathBuf::from(&cfg.log), cfg.max_log_bytes),
        timeout,
        conns: AtomicUsize::new(0),
    });

    eprintln!(
        "keywardd: listening on {} with {} upstream(s)",
        cfg.listen,
        ctx.upstreams.len()
    );

    for stream in listener.incoming() {
        match stream {
            Ok(s) => agent::spawn(s, Arc::clone(&ctx)),
            Err(e) => eprintln!("keywardd: accept failed: {e}"),
        }
    }
}
