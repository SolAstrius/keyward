//! The Secure Enclave key Keyward holds itself.
//!
//! The private scalar never leaves the enclave; what lives on disk is a
//! SEP-wrapped 324-byte handle that is useless on any other machine. Because
//! Keyward performs the signature, it also writes the authentication prompt —
//! which is the entire point. Secretive can only ever say "a request from
//! launchd", since by the time it sees the request the caller's identity has
//! been laundered through the proxy.

use crate::wire::Writer;
use std::ffi::CString;
use std::path::PathBuf;

extern "C" {
    fn kwse_available() -> i32;
    fn kwse_generate(policy: i32, buf: *mut u8, cap: usize) -> isize;
    fn kwse_public(blob: *const u8, blob_len: usize, buf: *mut u8, cap: usize) -> isize;
    fn kwse_sign(
        blob: *const u8,
        blob_len: usize,
        msg: *const u8,
        msg_len: usize,
        reason: *const i8,
        reuse_seconds: f64,
        buf: *mut u8,
        cap: usize,
    ) -> isize;
}

pub const KEY_TYPE: &str = "ecdsa-sha2-nistp256";
pub const CURVE: &str = "nistp256";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// No authentication — anything that can read the blob can sign.
    None,
    /// Touch ID or password, and survives a change to enrolled fingerprints.
    UserPresence,
    /// Touch ID only; the key self-destructs if the fingerprint set changes.
    BiometryCurrentSet,
}

impl Policy {
    pub fn parse(s: &str) -> Option<Policy> {
        match s {
            "none" => Some(Policy::None),
            "presence" => Some(Policy::UserPresence),
            "biometry" => Some(Policy::BiometryCurrentSet),
            _ => None,
        }
    }
    fn code(self) -> i32 {
        match self {
            Policy::None => 0,
            Policy::UserPresence => 1,
            Policy::BiometryCurrentSet => 2,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Policy::None => "none",
            Policy::UserPresence => "presence",
            Policy::BiometryCurrentSet => "biometry",
        }
    }
}

pub fn available() -> bool {
    unsafe { kwse_available() == 1 }
}

pub fn default_key_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join("Library/Application Support/Keyward/enclave-key.blob")
}

pub struct Enclave {
    blob: Vec<u8>,
    /// The 65-byte uncompressed EC point.
    point: Vec<u8>,
    pub comment: String,
}

impl Enclave {
    pub fn load(path: &PathBuf, comment: String) -> Option<Enclave> {
        let blob = std::fs::read(path).ok()?;
        if blob.is_empty() {
            return None;
        }
        let mut point = vec![0u8; 256];
        let n = unsafe { kwse_public(blob.as_ptr(), blob.len(), point.as_mut_ptr(), point.len()) };
        if n <= 0 {
            eprintln!("keywardd: enclave key present but unreadable (code {n})");
            return None;
        }
        point.truncate(n as usize);
        Some(Enclave {
            blob,
            point,
            comment,
        })
    }

    /// SSH wire format: string(type), string(curve), string(point).
    pub fn ssh_public_blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(KEY_TYPE.as_bytes());
        w.string(CURVE.as_bytes());
        w.string(&self.point);
        w.buf
    }

    pub fn authorized_key_line(&self) -> String {
        use base64::Engine;
        format!(
            "{} {} {}",
            KEY_TYPE,
            base64::engine::general_purpose::STANDARD.encode(self.ssh_public_blob()),
            self.comment
        )
    }

    /// Sign `data`, showing `reason` in the authentication prompt.
    ///
    /// CryptoKit hashes with SHA-256 internally, which is what
    /// `ecdsa-sha2-nistp256` requires, and returns a raw r||s pair.
    pub fn sign(&self, data: &[u8], reason: &str, reuse_secs: f64) -> Result<Vec<u8>, String> {
        let c_reason = CString::new(reason).unwrap_or_else(|_| CString::new("").unwrap());
        let mut sig = vec![0u8; 256];
        let n = unsafe {
            kwse_sign(
                self.blob.as_ptr(),
                self.blob.len(),
                data.as_ptr(),
                data.len(),
                c_reason.as_ptr(),
                reuse_secs,
                sig.as_mut_ptr(),
                sig.len(),
            )
        };
        match n {
            -3 => return Err("declined or authentication failed".into()),
            n if n <= 0 => return Err(format!("enclave signing failed (code {n})")),
            _ => {}
        }
        sig.truncate(n as usize);
        if sig.len() != 64 {
            return Err(format!("unexpected signature length {}", sig.len()));
        }
        Ok(ssh_ecdsa_signature(&sig[..32], &sig[32..]))
    }
}

/// SSH encodes ECDSA signatures as string(type) + string(mpint r || mpint s).
fn ssh_ecdsa_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut inner = Writer::new();
    inner.string(&mpint(r));
    inner.string(&mpint(s));

    let mut out = Writer::new();
    out.string(KEY_TYPE.as_bytes());
    out.string(&inner.buf);
    out.buf
}

/// Two's-complement big integer: strip leading zeros, then re-add one if the
/// top bit is set so the value is never read as negative.
fn mpint(v: &[u8]) -> Vec<u8> {
    let first = v.iter().position(|b| *b != 0).unwrap_or(v.len());
    let trimmed = &v[first..];
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(trimmed);
    out
}

/// Create a key. Refuses to clobber an existing one: an enclave key cannot be
/// exported or backed up, so overwriting it destroys it beyond recovery.
pub fn generate(path: &PathBuf, policy: Policy, force: bool) -> Result<(), String> {
    if !available() {
        return Err("no Secure Enclave on this machine".into());
    }
    if path.exists() && !force {
        return Err(format!(
            "{} already exists. Overwriting destroys the existing key permanently \
             — it cannot be exported or restored. Pass --force only if you have \
             already rotated away from it.",
            path.display()
        ));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let mut blob = vec![0u8; 4096];
    let n = unsafe { kwse_generate(policy.code(), blob.as_mut_ptr(), blob.len()) };
    if n <= 0 {
        return Err(format!("enclave key generation failed (code {n})"));
    }
    blob.truncate(n as usize);
    std::fs::write(path, &blob).map_err(|e| e.to_string())?;
    std::fs::set_permissions(
        path,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
