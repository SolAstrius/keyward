//! Caller attribution: who is actually asking for this signature?
//!
//! Secretive can only resolve a pid through `NSRunningApplication`, which knows
//! about GUI apps and nothing else. Every SSH caller is a CLI process, so it
//! always resolves to nil and the notification is blank. We walk the parent
//! chain instead: `ssh -> zsh -> Ghostty` reaches a real .app bundle, which is
//! the answer a human wants. Bundle detection is a path check rather than an
//! AppKit lookup, so it still works after the process has exited.

use crate::context::{self, Context};
use crate::purpose::{self, Kind as PurposeKind, Purpose};
use serde::{Deserialize, Serialize};
use std::ffi::CStr;
use std::os::unix::io::RawFd;

const SOL_LOCAL: libc::c_int = 0;
const LOCAL_PEERPID: libc::c_int = 2;
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
const KERN_PROCARGS2: libc::c_int = 49;
const PROC_PIDVNODEPATHINFO: libc::c_int = 9;
/// sizeof(struct proc_vnodepathinfo) and the offset of pvi_cdir.vip_path
/// within it, both taken from the SDK headers rather than derived by hand —
/// vinfo_stat packs to 136 bytes, not the 144 a naive reading suggests.
const VNODEPATHINFO_SIZE: usize = 2352;
const VIP_PATH_OFFSET: usize = 152;

const PROC_PIDTBSDINFO: libc::c_int = 3;

/// `struct proc_bsdinfo` from <sys/proc_info.h>. The libc crate does not export
/// `kinfo_proc` on Darwin, and libproc is the stabler interface regardless.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: libc::uid_t,
    pbi_gid: libc::gid_t,
    pbi_ruid: libc::uid_t,
    pbi_rgid: libc::gid_t,
    pbi_svuid: libc::uid_t,
    pbi_svgid: libc::gid_t,
    rfu_1: u32,
    pbi_comm: [libc::c_char; 16],
    pbi_name: [libc::c_char; 32],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

extern "C" {
    fn proc_pidpath(pid: libc::c_int, buffer: *mut libc::c_void, buffersize: u32) -> libc::c_int;
    fn proc_pidinfo(
        pid: libc::c_int,
        flavor: libc::c_int,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
}

fn bsd_info(pid: i32) -> Option<ProcBsdInfo> {
    let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<ProcBsdInfo>() as libc::c_int;
    let n = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    if n == size {
        Some(info)
    } else {
        None
    }
}

fn cstr_field(f: &[libc::c_char]) -> Option<String> {
    let bytes: Vec<u8> = f.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
    if bytes.is_empty() {
        None
    } else {
        String::from_utf8(bytes).ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcInfo {
    pub pid: i32,
    pub name: Option<String>,
    pub path: Option<String>,
    pub cwd: Option<String>,
    pub args: Vec<String>,
}

impl ProcInfo {
    /// The caller's full command line, for surfaces with room to show it.
    pub fn commandline(&self) -> String {
        if self.args.is_empty() {
            self.path.clone().unwrap_or_default()
        } else {
            self.args.join(" ")
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    /// e.g. /Applications/Ghostty.app
    pub bundle_path: String,
    /// e.g. Ghostty
    pub name: String,
    /// How many hops up the parent chain we had to walk to find it.
    pub depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribution {
    pub pid: i32,
    /// Immediate caller (almost always `ssh`).
    pub process: Option<ProcInfo>,
    /// Full chain from the caller up to launchd.
    pub ancestry: Vec<ProcInfo>,
    /// Outermost .app in the chain — the application a human would name.
    pub app: Option<AppInfo>,
    /// Every .app in the chain, innermost first (e.g. claude -> Claude).
    pub apps: Vec<AppInfo>,
    /// Best-effort SSH destination parsed out of the caller's argv.
    pub destination: Option<String>,
    /// What this request is for, in human terms.
    pub purpose: Purpose,
    /// Anything the caller's environment, a declaration file, or the repository
    /// itself can tell us about why.
    pub context: Context,
}

/// Peer pid of a connected unix socket, via LOCAL_PEERPID.
pub fn peer_pid(fd: RawFd) -> Option<i32> {
    let mut pid: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 && pid > 0 {
        Some(pid)
    } else {
        None
    }
}

pub fn proc_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    let n = unsafe { proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}

pub fn parent_pid(pid: i32) -> Option<i32> {
    let info = bsd_info(pid)?;
    let ppid = info.pbi_ppid as i32;
    if ppid > 0 {
        Some(ppid)
    } else {
        None
    }
}

/// Working directory of a process — this is how we learn *which repository* a
/// git operation belongs to, since git itself never puts that on the command
/// line of the ssh or ssh-keygen it spawns.
pub fn proc_cwd(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; VNODEPATHINFO_SIZE];
    let n = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDVNODEPATHINFO,
            0,
            buf.as_mut_ptr() as *mut libc::c_void,
            VNODEPATHINFO_SIZE as libc::c_int,
        )
    };
    if n as usize != VNODEPATHINFO_SIZE {
        return None;
    }
    let start = VIP_PATH_OFFSET;
    let end = buf[start..]
        .iter()
        .position(|b| *b == 0)
        .map(|i| start + i)
        .unwrap_or(buf.len());
    if end <= start {
        return None;
    }
    String::from_utf8(buf[start..end].to_vec()).ok()
}

/// Short process name (`ssh`, `zsh`), useful when the executable path is gone.
pub fn proc_name(pid: i32) -> Option<String> {
    let info = bsd_info(pid)?;
    cstr_field(&info.pbi_name).or_else(|| cstr_field(&info.pbi_comm))
}

/// Full argv of a process, via KERN_PROCARGS2.
pub fn proc_args(pid: i32) -> Vec<String> {
    proc_argv_env(pid).0
}

/// argv and environment of a process.
///
/// The kernel only hands back the environment when the target is not a platform
/// binary, so `/usr/bin/ssh` and `/bin/zsh` yield argv alone. A user-installed
/// binary further up the chain — an agent, a terminal — still exposes its own,
/// which is where the useful session context lives.
pub fn proc_argv_env(pid: i32) -> (Vec<String>, Vec<(String, String)>) {
    let mut argmax: libc::c_int = 0;
    let mut sz = std::mem::size_of::<libc::c_int>();
    let mut mib_max: [libc::c_int; 2] = [libc::CTL_KERN, libc::KERN_ARGMAX];
    let rc = unsafe {
        libc::sysctl(
            mib_max.as_mut_ptr(),
            2,
            &mut argmax as *mut _ as *mut libc::c_void,
            &mut sz,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || argmax <= 0 {
        return (Vec::new(), Vec::new());
    }

    let mut buf = vec![0u8; argmax as usize];
    let mut bsz = argmax as usize;
    let mut mib: [libc::c_int; 3] = [libc::CTL_KERN, KERN_PROCARGS2, pid];
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut bsz,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || bsz < 4 {
        return (Vec::new(), Vec::new());
    }
    buf.truncate(bsz);

    let argc = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let mut i = 4usize;
    // Skip the exec path, then the NUL padding that follows it.
    while i < buf.len() && buf[i] != 0 {
        i += 1;
    }
    while i < buf.len() && buf[i] == 0 {
        i += 1;
    }

    let mut take = |i: &mut usize| -> Option<String> {
        while *i < buf.len() && buf[*i] == 0 {
            *i += 1;
        }
        if *i >= buf.len() {
            return None;
        }
        let start = *i;
        while *i < buf.len() && buf[*i] != 0 {
            *i += 1;
        }
        std::str::from_utf8(&buf[start..*i]).ok().map(str::to_string)
    };

    let mut args = Vec::with_capacity(argc);
    while args.len() < argc {
        match take(&mut i) {
            Some(a) => args.push(a),
            None => break,
        }
    }

    // Whatever follows argv is the environment, then some dyld-private strings
    // that carry no "=" and fall out naturally.
    let mut env = Vec::new();
    while let Some(e) = take(&mut i) {
        if let Some((k, v)) = e.split_once('=') {
            if !k.is_empty() {
                env.push((k.to_string(), v.to_string()));
            }
        }
    }

    (args, env)
}

fn proc_info(pid: i32) -> ProcInfo {
    ProcInfo {
        pid,
        name: proc_name(pid),
        path: proc_path(pid),
        cwd: proc_cwd(pid),
        args: proc_args(pid),
    }
}

/// Every ancestor that lives inside a .app bundle, innermost first.
///
/// A helper can be nested inside its parent app (Claude Code's `claude.app`
/// lives under `Claude.app`), so we collect the whole set: the innermost names
/// the component, the outermost names the application the user launched.
fn apps_for(chain: &[ProcInfo]) -> Vec<AppInfo> {
    let mut out: Vec<AppInfo> = Vec::new();
    for (depth, p) in chain.iter().enumerate() {
        let path = match p.path.as_deref() {
            Some(p) => p,
            None => continue,
        };
        if let Some(idx) = path.find(".app/Contents/MacOS/") {
            let bundle = &path[..idx + 4];
            if out.iter().any(|a| a.bundle_path == bundle) {
                continue;
            }
            let name = std::path::Path::new(bundle)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| bundle.to_string());
            out.push(AppInfo {
                bundle_path: bundle.to_string(),
                name,
                depth,
            });
        }
    }
    out
}

/// Pull an ssh destination out of a caller's argv: the first non-flag operand
/// that isn't the program itself. Handles `ssh user@host`, `ssh host`, and
/// skips the option arguments of flags that take one.
fn destination_from(args: &[String]) -> Option<String> {
    const TAKES_ARG: &[&str] = &[
        "-o", "-i", "-p", "-l", "-F", "-b", "-c", "-D", "-E", "-e", "-I", "-J", "-L", "-m", "-O",
        "-Q", "-R", "-S", "-W", "-w",
    ];
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        if TAKES_ARG.contains(&a.as_str()) {
            it.next();
            continue;
        }
        if a.starts_with('-') {
            continue;
        }
        return Some(a.clone());
    }
    None
}

pub fn attribute(fd: RawFd) -> Attribution {
    let pid = match peer_pid(fd) {
        Some(p) => p,
        None => {
            return Attribution {
                pid: -1,
                process: None,
                ancestry: Vec::new(),
                app: None,
                apps: Vec::new(),
                destination: None,
                purpose: purpose::classify(&[]),
                context: Context::default(),
            }
        }
    };

    let mut chain = Vec::new();
    let mut cur = Some(pid);
    let mut depth = 0;
    while let Some(c) = cur {
        if c <= 1 || depth >= 16 {
            break;
        }
        chain.push(proc_info(c));
        cur = parent_pid(c);
        depth += 1;
    }

    let process = chain.first().cloned();
    let destination = process
        .as_ref()
        .filter(|p| {
            matches!(
                p.name.as_deref(),
                Some("ssh") | Some("scp") | Some("sftp") | Some("ssh-keyscan")
            )
        })
        .and_then(|p| destination_from(&p.args));
    let apps = apps_for(&chain);
    let app = apps.last().cloned();

    let purpose = purpose::classify(&chain);
    let signing_commit = matches!(purpose.kind, PurposeKind::CommitSigning);
    let ctx = context::gather(&chain, purpose.repo_path.as_deref(), signing_commit);

    Attribution {
        pid,
        process,
        ancestry: chain,
        app,
        apps,
        destination,
        purpose,
        context: ctx,
    }
}
