mod agent;
mod attrib;
mod context;
mod enclave;
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
    /// Where the SEP-wrapped handle for our own key lives.
    #[serde(default)]
    log_list_identities: bool,
    #[serde(default)]
    enclave_key: Option<String>,
    #[serde(default = "default_enclave_comment")]
    enclave_comment: String,
}

fn default_enclave_comment() -> String {
    let host = std::process::Command::new("scutil")
        .arg("--get")
        .arg("LocalHostName")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "mac".into());
    format!("{host}@keyward")
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
            log_list_identities: false,
            enclave_key: None,
            enclave_comment: default_enclave_comment(),
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
    let mut want_generate = false;
    let mut want_pubkey = false;
    let mut force = false;
    let mut policy = enclave::Policy::UserPresence;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                cfg_path = args.get(i + 1).cloned();
                i += 1;
            }
            "--health" => want_health = true,
            "--generate-key" => want_generate = true,
            "--pubkey" => want_pubkey = true,
            "--force" => force = true,
            "--policy" => {
                let v = args.get(i + 1).cloned().unwrap_or_default();
                match enclave::Policy::parse(&v) {
                    Some(p) => policy = p,
                    None => {
                        eprintln!("keywardd: --policy must be none, presence or biometry");
                        std::process::exit(2);
                    }
                }
                i += 1;
            }
            "--help" | "-h" => {
                println!(
                    "keywardd [--config PATH]\n                       --health                    probe the socket, non-zero if unanswered\n                       --generate-key              create a Secure Enclave key (once)\n                       --policy none|presence|biometry   auth required per signature\n                       --pubkey                    print the authorized_keys line\n                       --force                     allow overwriting an existing key"
                );
                return;
            }
            other => eprintln!("keywardd: ignoring unknown argument {other}"),
        }
        i += 1;
    }

    let cfg = load_config(cfg_path.as_deref());
    let timeout = Duration::from_secs(cfg.timeout_secs);

    let key_path = cfg
        .enclave_key
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(enclave::default_key_path);

    if want_generate {
        match enclave::generate(&key_path, policy, force) {
            Ok(()) => {
                println!("created a Secure Enclave key ({} policy)", policy.label());
                println!("  handle: {}", key_path.display());
                println!("\nIt cannot be exported or backed up. Authorise it before you rely on it:");
                if let Some(e) = enclave::Enclave::load(&key_path, cfg.enclave_comment.clone()) {
                    println!("\n{}\n", e.authorized_key_line());
                }
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("keywardd: {e}");
                std::process::exit(1);
            }
        }
    }

    let enclave = enclave::Enclave::load(&key_path, cfg.enclave_comment.clone());

    if want_pubkey {
        match &enclave {
            Some(e) => println!("{}", e.authorized_key_line()),
            None => {
                eprintln!("keywardd: no enclave key yet — run keywardd --generate-key");
                std::process::exit(1);
            }
        }
        std::process::exit(0);
    }

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
        enclave,
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
        log_lists: cfg.log_list_identities,
    });

    eprintln!(
        "keywardd: listening on {} with {} upstream(s){}",
        cfg.listen,
        ctx.upstreams.len(),
        if ctx.enclave.is_some() {
            " + its own Secure Enclave key"
        } else {
            ""
        }
    );

    for stream in listener.incoming() {
        match stream {
            Ok(s) => agent::spawn(s, Arc::clone(&ctx)),
            Err(e) => eprintln!("keywardd: accept failed: {e}"),
        }
    }
}
