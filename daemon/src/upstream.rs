//! Upstream agent connections (Secretive, gpg-agent, ...).
//!
//! Every call is bounded by a socket timeout and uses its own short-lived
//! connection. Nothing is shared between requests, so one unresponsive upstream
//! can never stall an unrelated caller — which is exactly the failure that took
//! ssh-agent-mux down (alive, accepting, answering nothing).

use crate::wire;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Upstream {
    pub name: String,
    pub path: String,
}

/// Agent messages are capped well below this; it only guards against a
/// malformed or hostile length prefix.
const MAX_MSG: u32 = 1 << 20;

impl Upstream {
    pub fn request(&self, payload: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
        let mut s = UnixStream::connect(&self.path)?;
        s.set_read_timeout(Some(timeout))?;
        s.set_write_timeout(Some(timeout))?;

        s.write_all(&wire::frame(payload))?;
        s.flush()?;

        let mut len = [0u8; 4];
        s.read_exact(&mut len)?;
        let n = u32::from_be_bytes(len);
        if n == 0 || n > MAX_MSG {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad reply length {n} from {}", self.name),
            ));
        }
        let mut body = vec![0u8; n as usize];
        s.read_exact(&mut body)?;
        Ok(body)
    }

    /// Ask this upstream for its identities. Returns (key blob, comment) pairs.
    pub fn identities(&self, timeout: Duration) -> io::Result<Vec<(Vec<u8>, String)>> {
        let reply = self.request(&[crate::agent::REQUEST_IDENTITIES], timeout)?;
        let mut r = wire::Reader::new(&reply);
        match r.u8() {
            Some(crate::agent::IDENTITIES_ANSWER) => {}
            _ => return Ok(Vec::new()),
        }
        let count = r.u32().unwrap_or(0);
        let mut out = Vec::new();
        for _ in 0..count {
            let blob = match r.string() {
                Some(b) => b.to_vec(),
                None => break,
            };
            let comment = r
                .string()
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .unwrap_or_default();
            out.push((blob, comment));
        }
        Ok(out)
    }
}
