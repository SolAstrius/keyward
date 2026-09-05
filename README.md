# Keyward

An SSH agent proxy that can tell you *what a signature was for*.

It sits where `ssh-agent-mux` sat — in front of Secretive and gpg-agent — and
answers the question neither of them can: not just "a key was used", but
"a git commit in `nixos-config` was signed", "a push went to `github.com`",
"someone logged into `arcturus`".

- `daemon/` — Rust. Speaks the SSH agent protocol, merges the upstream agents,
  attributes and logs every request.
- `app/` — SwiftUI. Live view and history, with app icons and full detail.

## Why

macOS gives an agent one way to identify its caller: resolve the peer pid with
`NSRunningApplication`. That API only knows GUI apps, and every SSH caller is a
CLI process, so it always returns nil — which is why Secretive's notification
never names anything. Two facts make it recoverable:

1. **The parent chain reaches a real app.** `ssh → zsh → Ghostty`. Keyward walks
   it and matches against `.app` bundles by path, so it works even after the
   process exits, and it reports the whole chain rather than one name.

2. **Intent is visible in the caller's argv.** git signs commits by running
   `ssh-keygen -Y sign -n git` and moves objects by running
   `ssh <host> git-receive-pack '<repo>'`. Neither ever names the *local*
   repository, so that comes from the caller's working directory
   (`proc_pidinfo`/`PROC_PIDVNODEPATHINFO`).

`session-bind@openssh.com` carries the destination host key, which would be the
ideal provenance channel — but neither Secretive nor gpg-agent implements it.
Keyward answers it locally (with the `FAILURE` a non-supporting agent returns,
which ssh already tolerates) and keeps the host key as evidence, instead of
forwarding it upstream to produce errors.

## Failure modes it is built to avoid

`ssh-agent-mux` wedged on 2026-09-06: alive, accepting connections, answering
none. Established ControlMaster sessions kept working while every new handshake
hung, which made a purely local fault look like a mesh outage. launchd never
noticed, because `KeepAlive.Crashed` only sees a process that died.

- **Thread per connection, no shared state across I/O.** One unresponsive
  upstream cannot stall an unrelated caller.
- **Every upstream call is timeout-bounded** (`timeout_secs`, default 10).
- **`keywardd --health`** performs a real request against the socket and exits
  non-zero if it is not answered — the check launchd cannot do. Run it from a
  periodic agent to make the wedge self-healing.
- **A stale socket is cleared, a live one is respected.** The old mux
  crash-looped on "Address already in use" forever; Keyward connects first and
  only removes the file if nothing answers.
- Connections are capped (512) so clients cannot pile up unbounded.

## Build

```sh
./build.sh          # -> dist/keywardd and dist/Keyward.app
```

## Configure

`~/.config/keyward/config.json` (all fields optional; these are the defaults):

```json
{
  "listen": "~/.ssh/keyward.sock",
  "log": "~/Library/Application Support/Keyward/events.jsonl",
  "upstreams": [
    { "name": "Secretive", "path": "~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh" },
    { "name": "gpg-agent", "path": "~/.gnupg/S.gpg-agent.ssh" }
  ],
  "timeout_secs": 10,
  "max_log_bytes": 33554432
}
```

Point ssh at it with `IdentityAgent ~/.ssh/keyward.sock`.

The first upstream to claim a key owns it, so ordering decides which agent signs
when both hold the same key.

## Log

One JSON object per request in `events.jsonl`, holding the purpose, the full
process ancestry, the key fingerprint, the upstream that signed, the destination
and the outcome. The app tails it; nothing else writes to it.
