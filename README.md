# Keyward

An SSH agent proxy that can tell you *what a signature was for*.

It sits where `ssh-agent-mux` sat — in front of Secretive and gpg-agent — and
answers the question neither of them can: not just "a key was used", but
"a git commit in `nixos-config` was signed", "a push went to `github.com`",
"someone logged into `arcturus`".

- `daemon/` — Rust. Speaks the SSH agent protocol, merges the upstream agents,
  attributes and logs every request.
- `app/` — SwiftUI. Live view and history, with app icons and full detail.

![Signing a commit](assets/screenshots/approval-commit.png)

The system Touch ID sheet cannot be restyled or moved, so Keyward lays a card
out *around* it — the sheet docks into a slot sized to fit, and everything worth
reading sits beside it.

![Running a remote command](assets/screenshots/approval-command.png)

A multi-line command is shown in full rather than as `bash -s`, with section
`echo`s rendered as comments.

*(Screenshots use example data.)*

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

## Passing context in

Three channels, none needing cooperation from `ssh` itself.

**1. The repository.** For git work, the branch, remote and the commit message
about to be signed are read from disk. git writes `COMMIT_EDITMSG` before it
asks for the signature, so the message is already there. Nothing to configure.

**2. A declaration file, keyed by pid.** Any process may explain itself:

```sh
echo '{"reason":"release cut","task":"ASTR-441"}' \
  > "$HOME/Library/Application Support/Keyward/context/$$.json"
```

The daemon walks the process ancestry and picks up the file belonging to the
nearest matching pid, so a wrapper can label a single command or a long-running
agent can label its whole session. Nearest wins. This is the only channel that
works for *every* request type.

**3. The environment of the nearest ancestor that exposes one.** Measured
behaviour on macOS 26, not documented policy:

| process | environment readable |
|---|---|
| `/usr/bin/ssh` | no |
| `/usr/bin/ssh-keygen` | **yes** |
| `/bin/zsh`, `/bin/sleep` | no |
| user-installed binaries (agents, terminals) | **yes** |

Both `ssh` and `ssh-keygen` carry identical code-signing flags
(`0x10000(runtime)`), so the code signature does not explain the difference —
treat the table as empirical.

The practical consequence:

- **Commit signing** goes through `ssh-keygen`, so a per-invocation variable
  works: `KEYWARD_REASON="release cut" git commit -S -m …`
- **SSH authentication** goes through `ssh`, which exposes nothing, so a
  per-invocation variable is invisible. Use channel 2 for those.
- Either way the daemon falls back to the nearest readable ancestor, which is
  usually the agent itself — that is where `CLAUDE_CODE_HOST_SESSION_ID`,
  `CLAUDE_CODE_ENTRYPOINT` and W3C `BAGGAGE` come from, with no setup at all.

`KEYWARD_*` is the free-form namespace. Everything else is a strict allow-list
(`ENV_ALLOW` in `daemon/src/context.rs`) with a secret-shaped-name denylist on
top, because the same environment also holds `CLAUDE_CODE_OAUTH_TOKEN`. Widen
the allow-list deliberately, never by dumping the environment.

## Holding the key itself

Keyward can own a Secure Enclave key instead of proxying to Secretive:

```sh
keywardd --generate-key --policy presence   # or: biometry, none
keywardd --pubkey                           # the authorized_keys line
```

The private scalar is generated inside the SEP and never leaves it. What lands
on disk (`enclave-key.blob`, mode 600) is a 324-byte SEP-wrapped handle that is
inert on any other machine.

**Why bother, when Secretive already does this.** Because the agent that
performs the signature is the one that writes the authentication prompt. A
proxy in front of Secretive makes this strictly worse — Secretive sees
`keywardd` as its peer and says *"a request from launchd"*. Keyward knows what
the request is for, so the prompt reads:

> Sign the commit “Read agent context from env, sidecar and repo” in keyward — requested by Ghostty

`--policy` decides what each signature costs:

| policy | prompt | survives a fingerprint change |
|---|---|---|
| `none` | none | yes |
| `presence` | Touch ID, password fallback | yes |
| `biometry` | Touch ID only | **no — the key is destroyed** |

### The trade-off, stated plainly

Secretive's key is bound to the SEP *and* to Secretive's team identity via the
keychain, so another program cannot use it even with full file access. Keyward's
handle is bound to the SEP only, because the keychain route needs an Apple
signing certificate. Anything running as you that can read the blob can ask the
enclave to sign — which is why `presence` or `biometry` matters: with those, a
silent background signature is impossible.

It remains far stronger than an on-disk private key. The key cannot be stolen;
an attacker has to stay resident on this Mac.

### There is no backup

An enclave key cannot be exported, copied or escrowed. If this machine is lost,
so is the key. Authorise a second, non-enclave key for recovery *before* you
depend on this one, and keep the old key in `allowed_signers` forever or
previously signed commits stop verifying.

`--generate-key` refuses to overwrite an existing handle for the same reason.

### Why there is Swift in a Rust daemon

Apple exposes Secure Enclave key *persistence* only through CryptoKit, which is
Swift-only. Everything reachable from C was tried: `SecKeyCreateRandomKey` with
`kSecAttrIsPermanent: true` needs a keychain entitlement (`errSecMissingEntitlement`,
and an ad-hoc signature carrying one gets the process killed), while a
non-permanent key cannot be exported — `SecKeyCopyExternalRepresentation`
returns "export not implemented for key". The `toid` attribute is the right size
(324 bytes) but feeding it back to `SecKeyCreateWithData` **silently generates a
different key**, which signs successfully and is therefore easy to mistake for
success. Check the public key, not the error code.

So `kwse.swift` is about eighty lines compiled to a static archive by `build.rs`
and linked into the daemon. There is no second process and no shipped dylib —
the Swift runtime lives in `/usr/lib/swift` on every macOS.

## The authentication prompt

macOS draws it in a ~260pt-wide panel, and it is a protected surface that
`screencapture` refuses, so it has to be legible without being seen first.
The reason string is therefore short (56 chars max), stripped of quotes,
backticks and newlines, and never carries the remote command — arbitrary shell
text was the single worst thing to read there. The command, the commit message
and the process chain all live in the app instead.

```
SSH to root@server.example · Ghostty
Sign a commit in nixos-config · Claude
git push to owner/repo · Ghostty
```

`touch_id_reuse_secs` (config, 0 = every signature, macOS caps it at 300) holds
one authenticated `LAContext` for that long, so a loop over the fleet asks once
instead of once per host. Setting only
`touchIDAuthenticationAllowableReuseDuration` on a fresh context per signature
does nothing — the window only applies within a single context.

## Never overwrite the daemon in place

`build.sh` writes `.keywardd.new`, signs it, and renames over the target.
Copying onto a running binary keeps the inode, so the kernel finds pages that
no longer match the cached signature and kills the process with
`CODESIGNING / "Invalid Page"` — and every later exec of that path with it. The
symptom is `Permission denied (publickey)` everywhere, because the agent is
simply gone.

## Install

Building from source is the recommended path, and needs nothing but the Xcode
command line tools plus Rust:

```sh
./build.sh      # daemon + app, daemon embedded in the bundle
./install.sh    # copy to ~/Applications and let it register its agents
```

A DMG is attached to each release. It is **ad-hoc signed and not notarised**,
because Gatekeeper only trusts a Developer ID certificate plus notarisation and
both require the paid Apple Developer Program. macOS will refuse to open it
until the quarantine attribute is cleared:

```sh
xattr -dr com.apple.quarantine /Applications/Keyward.app
```

If that trade is not one you want to make, build it yourself — the toolchain is
the same either way.

Requires macOS 14+ on Apple Silicon; the Secure Enclave key has nowhere to live
otherwise.

### First run

```sh
keywardd --generate-key --policy presence   # once; cannot be undone or backed up
keywardd --pubkey                           # authorise this on your servers
```

Then point ssh at it — `IdentityAgent ~/.ssh/keyward.sock` — and keep an
existing key authorised until you have confirmed the new one works.

The daemon ships **inside** `Keyward.app/Contents/MacOS/keywardd`, so the app is
the whole product: one thing to move, one path for launchd, and no dependency
on a checkout that could be cleaned or relocated out from under SSH.

On launch the app writes `dev.danielsol.keyward.agent` and
`.watchdog` into `~/Library/LaunchAgents`, pointing at the bundle it is
running from, and reloads them only when the contents actually change. Move the
app and the next launch repairs the paths by itself.

`keywardd` is also reachable directly for `--health`, `--pubkey` and
`--generate-key`; `dist/keywardd` is a symlink to the copy inside the bundle.

### What nix owns, and what it deliberately does not

The nix-darwin flake configures Keyward — `IdentityAgent`, `SSH_AUTH_SOCK`,
`~/.config/keyward/config.json` — and installs the built bundle into
`~/Applications` from an activation script. It does **not** declare the launchd
agent. A path baked into the flake pointed into a git checkout, so a clean or a
move would have left SSH with no agent at all; the app owning its own
registration keeps the running daemon and its path in the same place.

Building it in the nix sandbox is not possible: it links a Swift shim that needs
Xcode. The activation script copies whatever `./build.sh` produced and does
nothing when there is no build to copy.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
