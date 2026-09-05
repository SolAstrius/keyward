//! The proxy itself.

use crate::attrib::{self, Attribution};
use crate::enclave::Enclave;
use crate::purpose::Kind as PurposeKind;
use crate::event::{Event, Kind, Log};
use crate::upstream::Upstream;
use crate::wire::{self, Reader, Writer};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

pub const FAILURE: u8 = 5;
pub const REQUEST_IDENTITIES: u8 = 11;
pub const IDENTITIES_ANSWER: u8 = 12;
pub const SIGN_REQUEST: u8 = 13;
pub const SIGN_RESPONSE: u8 = 14;
pub const EXTENSION: u8 = 27;

const MAX_MSG: u32 = 1 << 20;
const MAX_CONNS: usize = 512;

pub struct Ctx {
    /// The key Keyward holds in the Secure Enclave itself, if one exists.
    pub enclave: Option<Enclave>,
    pub upstreams: Vec<Upstream>,
    /// key blob -> index into `upstreams`
    pub routes: RwLock<HashMap<Vec<u8>, usize>>,
    pub comments: RwLock<HashMap<Vec<u8>, String>>,
    pub log: Log,
    pub timeout: Duration,
    pub conns: AtomicUsize,
    /// Identity listings carry no signature and happen several times per ssh
    /// connection, so they are noise by default. Signatures are the record.
    pub log_lists: bool,
    /// Seconds during which one Touch ID authentication covers further
    /// signatures. 0 asks every time.
    pub touch_id_reuse_secs: f64,
}

pub fn fingerprint(blob: &[u8]) -> String {
    let digest = Sha256::digest(blob);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}

fn failure() -> Vec<u8> {
    vec![FAILURE]
}

/// The line shown in the Touch ID prompt.
///
/// macOS draws this in a ~260pt-wide panel, so it has to survive being read at
/// a glance: no shell fragments, no quotes, no backticks, and short enough not
/// to wrap into a paragraph. The full command, commit message and process
/// chain are in the app — the prompt only has to answer "consent to what?".
const PROMPT_MAX: usize = 56;

fn prompt_text(who: &Attribution) -> String {
    let p = &who.purpose;
    let host = p.host.clone().unwrap_or_else(|| "unknown host".into());

    let action = match p.kind {
        PurposeKind::CommitSigning => match &p.repo {
            // The commit subject is the interesting part but also the long
            // part; it stays in the app rather than the dialog.
            Some(repo) => format!("Sign a commit in {repo}"),
            None => "Sign a git commit".to_string(),
        },
        PurposeKind::GitPush => match &p.remote_repo {
            Some(r) => format!("git push to {}", short_repo(r)),
            None => format!("git push to {host}"),
        },
        PurposeKind::GitFetch => match &p.remote_repo {
            Some(r) => format!("git fetch from {}", short_repo(r)),
            None => format!("git fetch from {host}"),
        },
        PurposeKind::GitOverSsh => format!("git on {host}"),
        PurposeKind::SshLogin => format!("SSH to {host}"),
        // Deliberately omits the command itself: it is arbitrary shell text and
        // was the single worst thing to read in a narrow dialog.
        PurposeKind::RemoteCommand => format!("Run a command on {host}"),
        PurposeKind::FileTransfer => format!("Copy files with {host}"),
        PurposeKind::Signing => match &p.namespace {
            Some(ns) => format!("Sign data ({ns})"),
            None => "Sign data".to_string(),
        },
        PurposeKind::Unknown => "Authorise a signature".to_string(),
    };

    let action = sanitise(&action);
    match who.app.as_ref().map(|a| sanitise(&a.name)) {
        Some(app) if action.chars().count() + app.chars().count() + 3 <= PROMPT_MAX => {
            format!("{action} · {app}")
        }
        _ => crate::purpose::shorten(&action, PROMPT_MAX),
    }
}

/// owner/repo.git -> owner/repo, and just repo when that is still long.
fn short_repo(r: &str) -> String {
    let r = r.trim_end_matches(".git");
    if r.chars().count() <= 28 {
        return r.to_string();
    }
    r.rsplit('/').next().unwrap_or(r).to_string()
}

/// Strip anything that turns the dialog into noise.
fn sanitise(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '`' | '"' | '\'' | '\n' | '\r' | '\t' => ' ',
            c => c,
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn refresh_identities(ctx: &Ctx) -> Vec<(Vec<u8>, String)> {
    let mut merged: Vec<(Vec<u8>, String)> = Vec::new();
    let mut routes = HashMap::new();
    let mut comments = HashMap::new();

    for (idx, up) in ctx.upstreams.iter().enumerate() {
        match up.identities(ctx.timeout) {
            Ok(ids) => {
                for (blob, comment) in ids {
                    if routes.contains_key(&blob) {
                        continue; // first upstream to claim a key wins
                    }
                    routes.insert(blob.clone(), idx);
                    comments.insert(blob.clone(), comment.clone());
                    merged.push((blob, comment));
                }
            }
            Err(e) => {
                eprintln!("keywardd: upstream {} identities failed: {e}", up.name);
            }
        }
    }

    if let Ok(mut w) = ctx.routes.write() {
        *w = routes;
    }
    if let Ok(mut w) = ctx.comments.write() {
        *w = comments;
    }
    merged
}

fn handle_request_identities(ctx: &Ctx, who: &Attribution) -> Vec<u8> {
    let started = Instant::now();
    let mut ids = refresh_identities(ctx);

    // Our own enclave key is offered first, so ssh tries it before falling
    // back to whatever the upstream agents hold.
    if let Some(e) = &ctx.enclave {
        ids.insert(0, (e.ssh_public_blob(), e.comment.clone()));
    }

    let mut w = Writer::new();
    w.u8(IDENTITIES_ANSWER);
    w.u32(ids.len() as u32);
    for (blob, comment) in &ids {
        w.string(blob);
        w.string(comment.as_bytes());
    }

    let is_self_probe = who.process.as_ref().and_then(|p| p.name.as_deref()) == Some("keywardd");
    if ctx.log_lists && !is_self_probe {
        ctx.log.append(&Event {
        ts: crate::event::now(),
        kind: Kind::ListIdentities,
        who: who.clone(),
        key_fp: None,
        key_comment: None,
        upstream: None,
        bound_host_fp: None,
        outcome: format!("{} keys", ids.len()),
        duration_ms: started.elapsed().as_millis() as u64,
        });
    }

    w.buf
}

fn handle_sign(ctx: &Ctx, payload: &[u8], who: &Attribution, bound: &Option<String>) -> Vec<u8> {
    let started = Instant::now();

    let mut r = Reader::new(payload);
    let _ = r.u8();
    let blob = match r.string() {
        Some(b) => b.to_vec(),
        None => return failure(),
    };

    // Is this our own key? Then we sign it here, and we get to write the
    // prompt the user actually sees.
    if let Some(e) = &ctx.enclave {
        if e.ssh_public_blob() == blob {
            let mut r2 = Reader::new(payload);
            let _ = r2.u8();
            let _ = r2.string();
            let data = r2.string().unwrap_or(&[]).to_vec();

            let reason = prompt_text(who);
            let (reply, outcome) = match e.sign(&data, &reason, ctx.touch_id_reuse_secs) {
                Ok(sig) => {
                    let mut w = Writer::new();
                    w.u8(SIGN_RESPONSE);
                    w.string(&sig);
                    (w.buf, "ok".to_string())
                }
                Err(err) => (failure(), err),
            };

            ctx.log.append(&Event {
                ts: crate::event::now(),
                kind: Kind::Sign,
                who: who.clone(),
                key_fp: Some(fingerprint(&blob)),
                key_comment: Some(e.comment.clone()),
                upstream: Some("Secure Enclave".to_string()),
                bound_host_fp: bound.clone(),
                outcome,
                duration_ms: started.elapsed().as_millis() as u64,
            });
            return reply;
        }
    }

    let mut idx = ctx.routes.read().ok().and_then(|m| m.get(&blob).copied());
    if idx.is_none() {
        refresh_identities(ctx);
        idx = ctx.routes.read().ok().and_then(|m| m.get(&blob).copied());
    }
    let comment = ctx
        .comments
        .read()
        .ok()
        .and_then(|m| m.get(&blob).cloned())
        .filter(|c| !c.is_empty());

    let (reply, upstream_name, outcome) = match idx.and_then(|i| ctx.upstreams.get(i)) {
        Some(up) => match up.request(payload, ctx.timeout) {
            Ok(resp) => {
                let ok = resp.first().copied() != Some(FAILURE);
                (
                    resp,
                    Some(up.name.clone()),
                    if ok { "ok" } else { "denied" }.to_string(),
                )
            }
            Err(e) => {
                let kind = if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut
                {
                    "timeout".to_string()
                } else {
                    format!("error: {e}")
                };
                (failure(), Some(up.name.clone()), kind)
            }
        },
        None => (failure(), None, "no upstream holds this key".to_string()),
    };

    ctx.log.append(&Event {
        ts: crate::event::now(),
        kind: Kind::Sign,
        who: who.clone(),
        key_fp: Some(fingerprint(&blob)),
        key_comment: comment,
        upstream: upstream_name,
        bound_host_fp: bound.clone(),
        outcome,
        duration_ms: started.elapsed().as_millis() as u64,
    });

    reply
}

/// `session-bind@openssh.com` carries the host key of the server ssh is talking
/// to. Neither Secretive nor gpg-agent implements it, so forwarding it only
/// produces upstream errors — we answer it here (a plain FAILURE, exactly what
/// a non-supporting agent returns and what ssh already tolerates) and keep the
/// host key as provenance for the signatures that follow on this connection.
fn handle_extension(
    ctx: &Ctx,
    payload: &[u8],
    who: &Attribution,
    bound: &mut Option<String>,
) -> Vec<u8> {
    let mut r = Reader::new(payload);
    let _ = r.u8();
    let name = r
        .string()
        .map(|n| String::from_utf8_lossy(n).into_owned())
        .unwrap_or_default();

    if name == "session-bind@openssh.com" {
        if let Some(hostkey) = r.string() {
            let fp = fingerprint(hostkey);
            if bound.as_deref() != Some(fp.as_str()) {
                *bound = Some(fp.clone());
                if ctx.log_lists {
                    ctx.log.append(&Event {
                    ts: crate::event::now(),
                    kind: Kind::SessionBind,
                    who: who.clone(),
                    key_fp: None,
                    key_comment: None,
                    upstream: None,
                    bound_host_fp: Some(fp),
                    outcome: "recorded".to_string(),
                    duration_ms: 0,
                    });
                }
            }
        }
    }
    failure()
}

fn serve(mut stream: UnixStream, ctx: Arc<Ctx>) -> io::Result<()> {
    let who = attrib::attribute(stream.as_raw_fd());
    // A client that opens the socket and then goes quiet must not hold a thread
    // forever; ssh keeps its agent connection only for the length of a session.
    stream.set_read_timeout(Some(Duration::from_secs(3600)))?;
    let mut bound: Option<String> = None;

    loop {
        let mut len = [0u8; 4];
        match stream.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let n = u32::from_be_bytes(len);
        if n == 0 || n > MAX_MSG {
            return Ok(());
        }
        let mut payload = vec![0u8; n as usize];
        stream.read_exact(&mut payload)?;

        let reply = match payload[0] {
            REQUEST_IDENTITIES => handle_request_identities(&ctx, &who),
            SIGN_REQUEST => handle_sign(&ctx, &payload, &who, &bound),
            EXTENSION => handle_extension(&ctx, &payload, &who, &mut bound),
            _ => failure(),
        };

        stream.write_all(&wire::frame(&reply))?;
        stream.flush()?;
    }
}

pub fn spawn(stream: UnixStream, ctx: Arc<Ctx>) {
    if ctx.conns.load(Ordering::Relaxed) >= MAX_CONNS {
        eprintln!("keywardd: refusing connection, {MAX_CONNS} already open");
        return;
    }
    ctx.conns.fetch_add(1, Ordering::Relaxed);
    std::thread::spawn(move || {
        if let Err(e) = serve(stream, Arc::clone(&ctx)) {
            if e.kind() != io::ErrorKind::UnexpectedEof {
                eprintln!("keywardd: connection ended: {e}");
            }
        }
        ctx.conns.fetch_sub(1, Ordering::Relaxed);
    });
}
