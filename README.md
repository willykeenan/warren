# warren

Private links between your machines, through a relay you run yourself.

`warren` is one Rust binary. Enroll each of your machines with a relay you
host on any small server with a public IP, and every machine can reach the
ports you choose to share on the others, from anywhere, with no inbound ports
opened on the machines, no kernel driver and no third-party account. It can
also publish one local service on a public HTTPS name.

```
 laptop (a)                     relay (your VPS, :443)                  desktop (b)
 warren forward 2222 b:22  ──wss──►  forwards ciphertext  ◄──wss──  warren share 22
 ssh -p 2222 localhost          cannot read private streams          sshd on 127.0.0.1:22
```

* **Private links are end-to-end encrypted.** Inside every stream the two
  machines run `Noise_IK_25519_ChaChaPoly_BLAKE2s`; the relay only forwards
  ciphertext it cannot read.
* **The destination decides.** Nothing is reachable until that machine runs
  `warren share PORT`, optionally only for named machines. The check happens
  on the destination, so even a compromised relay cannot open an unshared port.
* **Keys are pinned.** Each machine remembers every peer's key the first time
  it sees it and refuses a changed key until you verify the new fingerprint
  and run `warren trust NAME --expect FINGERPRINT`.
* **Everything rides one outbound WebSocket on port 443**, so it works behind
  NAT and strict firewalls.
* **Publishing** (`warren publish 3230 --name web`) puts a local port at
  `https://web.<relay domain>/`, including long polling and WebSocket upgrades.
  Public traffic is, by necessity, TLS-terminated at the relay: the relay sees
  published traffic in plaintext. Private links never are.

## Windows (candidate)

Windows support is a source candidate. Windows compilation, runtime tests and
installer acceptance have **not** been run for this candidate. The checked-in
CI jobs describe the required validation; they are not a passing CI receipt.

Target: Windows 10/11 x64, Rust 1.88+ and Visual Studio C++ Build Tools for a
source build (`cargo build --release --locked`). Copy `target/release/warren.exe`
to a stable folder on PATH. The tag-only workflow can produce an x64 ZIP once
Windows CI passes; no Windows binary is published by this change. ARM64 is not
yet qualified. Unsigned binaries may trigger SmartScreen.

In PowerShell, enroll and run the node (replace the example relay/code):

```powershell
warren join CODE --relay https://relay.example.com --name desktop
warren up
# In a second terminal:
warren status
warren share 22 --to laptop
warren install
warren down
warren uninstall
```

The default home is `%LOCALAPPDATA%\warren` (fallback:
`%USERPROFILE%\AppData\Local\warren`). `--home DIR` overrides `WARREN_HOME`.
PowerShell, cmd and Git Bash use the same default; `HOME` is ignored on Windows.
Use a dedicated local NTFS/ReFS directory. Files and directories use a protected
DACL granting your account and SYSTEM access. Administrators can take ownership.
FAT/exFAT cannot enforce this privacy and are rejected.
The correction candidate also rejects UNC/device paths, reparse points or
junctions in the path, alternate data streams, and hard-linked state files.
Policy files with unsafe ACLs are preserved and rejected for explicit recovery.

The control endpoint is a local named pipe derived from your SID and canonical
home. It rejects remote clients, checks the owner and mandatory integrity label before sending requests,
and reserves the first instance. Framing preserves `nc` half-close semantics.
Windows allows at most 254 connected control clients plus the listening instance.

`install` registers a least-privilege, current-user logon task with no password or
administrator requirement, and checks that the daemon becomes reachable. The
console may appear briefly; background logs go to `logs\warren.log` without ANSI
colors. `down` exits cleanly and stays down until the next logon or explicit start.
`install --no-start` registers for the next logon; `--dir DIR` or `WARREN_TASK_DIR`
writes UTF-16 task XML and its name record, with no Task Scheduler effects. `uninstall` removes
the task, XML and name record, preserving enrollment and settings. A failed deletion is an
error; if someone manually removes a registered task, remove the stale XML only
after confirming that task is absent.
The registered task name is saved in `login-task-name.json` so alternate spellings
of the home remove the same registration. Older candidates with XML but no name
record require manual removal of the old `warren-*` task and its XML before
reinstalling; the installer refuses to guess an old task name.

Install the Windows OpenSSH Client optional feature for `warren ssh me@desktop`.
An equivalent SSH config uses:

```sshconfig
Host desktop
    ProxyCommand "C:/tools/warren.exe" nc %h 22
```

Paths with spaces are quoted. Paths containing quotes, `%`, `$`, backticks or
control characters are rejected for SSH. Real Windows OpenSSH is a CI test;
Git for Windows/MSYS OpenSSH still needs a separate compatibility run. Firewall,
reserved-port, user-logon, console-close and desktop acceptance remain Windows
validation requirements. The relay is not qualified for Windows production; use
Linux for relay hosting until its platform-specific checks pass.

## Quick start (about five minutes)

You need a small server with a public IP (the relay) and two machines. The
example uses `relay.example.com`; replace it with a name you control.

### 1. DNS

Point these records at the server's public address:

```
relay.example.com.     A     203.0.113.10
*.relay.example.com.   A     203.0.113.10     ; only needed for `warren publish`
```

### 2. Build

You need Rust 1.88 or newer. On the relay host, install the binary where
`sudo` finds it (`sudo` does not search `~/.cargo/bin` on most distributions):

```sh
git clone https://github.com/willykeenan/warren && cd warren
cargo build --release --locked
sudo install -m 755 target/release/warren /usr/local/bin/warren
```

On your machines either do the same or run `cargo install --locked --path .`
in the clone (without cloning: `cargo install --locked --git
https://github.com/willykeenan/warren`). `cargo install warren` installs an
unrelated crate of the same name.

To try warren on one machine first, see *Self-signed (testing)* in
[docs/relay.md](docs/relay.md).

### 3. Run the relay (on the server)

```sh
sudo warren relay --domain relay.example.com --acme you@example.com --state /var/lib/warren
```

The relay listens on 443 (nodes and published names) and, with `--acme`, on 80
for certificate challenges. Certificates are requested from Let's Encrypt
automatically (this has not yet been tested against the live CA; see *Status
and limitations*).
See [docs/relay.md](docs/relay.md) for running it as a service, bringing your
own certificate, and custom domains.

Create one enrollment code per machine (valid 10 minutes, single use):

```sh
sudo warren relay invite --state /var/lib/warren
# 7KQ4MWX9HD
```

### 4. Enroll the machines

On machine **b** (the one with the service, e.g. sshd):

```sh
warren join 7KQ4MWX9HD --relay https://relay.example.com --name b
warren install          # start `warren up` at login (launchd / systemd --user)
warren share 22         # let enrolled machines reach 127.0.0.1:22 here
```

On machine **a**:

```sh
warren join 3MPXT82KCE --relay https://relay.example.com --name a
warren install
warren forward 2222 b:22
ssh -p 2222 localhost   # reaches b's sshd
```

Or skip the forward and let ssh use warren directly:

```sh
warren ssh b                       # wraps: ssh -o ProxyCommand='warren nc %h 22' b
```

```
# ~/.ssh/config
Host b
    ProxyCommand warren nc %h 22
```

Check both machines see the same fingerprints (this is what makes the first
contact trustworthy, see *Security model*):

```sh
warren devices
```

### 5. Publish a service (optional)

```sh
warren publish 3230 --name web      # https://web.relay.example.com/ -> 127.0.0.1:3230
warren unpublish web
```

## Status and limitations

warren is new. Read this before relying on it.

* **Run on macOS only.** The relay, the node daemon and the login service
  have been used on macOS. Linux is supported by the code (a systemd user
  unit for nodes, the unit in [docs/relay.md](docs/relay.md) for the relay)
  and the test suite passes on Linux too (CI runs it there), but warren has
  not been run on real Linux machines yet; please report problems.
* **Automatic certificates have not been tested against a real CA.** The
  pieces around the ACME HTTP-01 exchange (challenge responder, renewal
  policy, storage) are unit-tested; the exchange with Let's Encrypt itself
  has not been run end to end. Start with `--acme-directory
  https://acme-staging-v02.api.letsencrypt.org/directory`, or bring your own
  certificate with `--cert/--key`.
* **`warren install` / `uninstall`** are tested by writing the service file
  to a temporary directory and with a stand-in for the service manager; the
  real `launchctl` and `systemctl` calls are not run by the tests.
* **Trust on first use.** The first key a machine sees for a peer comes from
  the relay; compare fingerprints after enrolling (see *Security model*).
* **One relay, no direct connections.** All traffic goes through your relay;
  if it is down, nothing connects.
* **TCP only**, and the relay's default listeners are IPv4 (see
  [docs/relay.md](docs/relay.md) for IPv6).
* The performance figures below were measured on loopback, not over the
  internet.

## Commands

| command | what it does |
|---|---|
| `warren relay [flags]` | run the relay (see `docs/relay.md`) |
| `warren relay invite [--name N]` | print a one-time enrollment code (on the relay host) |
| `warren relay nodes` / `revoke NAME` / `domain add HOST NAME` / `info` | relay administration |
| `warren join CODE --relay URL [--name N]` | enroll this machine (generates its keys) |
| `warren up` | run the node daemon in the foreground |
| `warren install` / `uninstall` | start `warren up` at login (launchd on macOS, systemd user unit on Linux, per-user Task Scheduler on Windows) |
| `warren down` | stop the running daemon (a daemon started by `warren install` then stays stopped until the next login or `warren install`) |
| `warren status` | relay, connection state, latency, shares, forwards, publishes, recent errors |
| `warren share PORT [--to a,b]` / `unshare PORT` | allow (some) enrolled machines to reach `127.0.0.1:PORT` |
| `warren forward LOCAL NODE:PORT` / `--remove LOCAL` | listen on `127.0.0.1:LOCAL` and forward to a peer |
| `warren nc NODE PORT` | stdin/stdout to a peer's port (ssh `ProxyCommand`) |
| `warren ssh [USER@]NODE [-p PORT] [-- ARGS]` | ssh through warren |
| `warren publish PORT --name N [--replace] [--allow CIDR,...]` | publish a local port at `https://N.<domain>/` |
| `warren unpublish N` | release a published name |
| `warren devices` | machines, fingerprints, online state, last seen, pin state |
| `warren trust NAME [--expect FINGERPRINT]` | accept a peer's new key after a legitimate change (replacing a pinned key requires `--expect`) |

Every command accepts `--json` for machine-readable output; failures,
including argument errors, are then a JSON object `{"ok": false, "code":
..., "error": ...}` on stdout. Shares, forwards and publishes persist across
restarts.

Nodes run on macOS and Linux; see the Windows candidate status above. On Linux, systemd user services run only while
you are logged in; on a headless machine run `loginctl enable-linger $USER`
once so `warren up` starts at boot.

### Exit codes

| code | meaning |
|---:|---|
| 0 | success |
| 1 | other error |
| 2 | usage error (bad arguments, e.g. an invalid `--name` or a non-`https` `--relay` for `join`) |
| 3 | this machine is not enrolled |
| 4 | the daemon is not running |
| 5 | not connected to the relay (or the relay is unreachable during `join`) |
| 6 | refused: port not shared, not shared with you, node offline or unknown, nothing listening, limits |
| 7 | a pinned key changed, `trust` needs `--expect` to replace a pinned key, or `--expect` did not match |
| 8 | authentication or enrollment refused (bad or used code, rate limited, revoked) |
| 9 | name conflict (`publish` of a name held by another node, or already published without `--replace`; `join --name` of a name in use) |

### Files and environment

A node keeps everything in `~/.warren` (override with `WARREN_HOME`); the
directory is `0700` and every file in it `0600`:

| file | contents |
|---|---|
| `identity.json` | node id, name, relay URL (and certificate pin), Ed25519 and X25519 private keys |
| `shares.json` | the share policy (default deny) |
| `known_peers.json` | pinned peer keys |
| `forwards.json`, `publishes.json` | persisted forwards and publishes |
| `warren.sock` | control socket used by the CLI |
| `logs/warren.log` | daemon log when started by `warren install` on macOS |

Use a dedicated directory for `WARREN_HOME` (and for the relay's `--state`):
warren sets it to `0700`, and warns when that takes access away from others.
On Unix, keep the path short: the control socket inside it must fit in a Unix socket
path (103 bytes on macOS, 107 on Linux), and warren says so when it does not.

On Linux the login service logs to the user journal: `journalctl --user -u
warren` (with a custom `WARREN_HOME` the unit name has a suffix;
`warren install --json` prints it as `label`).

`WARREN_LOG` sets how much warren itself logs: a level (`info`, `debug`,
`trace`) or directives for its modules (`warren::relay=debug`). Libraries log
at `warn` at most whatever it says, so no setting puts protocol messages
(enrollment codes, published traffic) in the log. `WARREN_LAUNCHD_DIR` and
`WARREN_SYSTEMD_DIR` (or `warren install --dir`) write the login service file
elsewhere without loading it.

## Security model

**What the relay can see:** which machines are enrolled and online, who opens
streams to whom and on which port, when, and how many bytes flow. For
published names it sees the full HTTP traffic, because it terminates TLS for
them.

**What the relay cannot do:**

* read or modify private stream contents: they are Noise transport messages
  between the two machines' static keys; any modification fails authentication
  and a truncated stream is detected (the end of a stream is itself an
  authenticated message);
* reach a port the destination has not shared, or reach it as a machine the
  share is not for: the destination checks its own `shares.json`, the Noise
  handshake proves which key the other end holds, and the destination
  connects to the local service only after the opener has completed a fresh
  handshake, so replaying a recorded one gets the relay nowhere;
* impersonate a machine whose key you have pinned.

**Shares open to every machine.** `warren share PORT` without `--to` admits
every machine enrolled on the relay, and the relay decides who is enrolled.
Whoever controls the relay host (or its state directory) can enroll a new
machine and reach such shares; the destination pins that machine's key on
first contact like any other. Use `--to NAME,...` for anything sensitive: a
listed name whose key this machine has already pinned cannot be taken over by
a different key.

Text that comes from other machines or from the relay (refusal messages,
names) is shown with control characters escaped, so it cannot rewrite your
terminal.

**Trust on first use.** The first time a machine talks to a peer, it takes the
peer's static key from the relay's registry and pins it. A relay that is
malicious at that very first contact could substitute a key. Compare
fingerprints with `warren devices` on both machines (or `warren trust NAME
--expect FINGERPRINT`) when you enroll a machine. After that, a changed key
is refused with an error showing the pinned and the new fingerprint. Check
the new one on that machine itself (`warren status` shows its own), then
accept it with `warren trust NAME --expect FINGERPRINT`; `trust` without
`--expect` never replaces a pinned key, so the relay cannot slip in another
key between showing you one and the moment you accept it. A pin store that
cannot be read is an error, never a reason to trust anew.

**Authentication.** Each node proves possession of its Ed25519 key on every
connection by signing a fresh random challenge bound to the relay's host name,
so signatures cannot be replayed or relayed to another relay. Unknown and
revoked keys are refused; revoking a machine disconnects it immediately,
including a connection it is making at that moment. Enrollment codes are 10
characters from an alphabet without look-alike characters, valid for 10
minutes, single use, limited to 5 failed attempts per IP address per 10
minutes, and stored only as SHA-256 hashes.

**Local files.** Keys never leave the machine; files are `0600` in a `0700`
directory; keys and codes never appear in logs or `--json` output.

**Network.** The binary connects only to the relay named in `identity.json`
and to `127.0.0.1` ports you shared or published (and, on the relay, to its
ACME directory). There is no telemetry and no update check.

**Availability** depends on the relay: a relay (or its host) that is down or
hostile can stop your links, but cannot read or redirect them.

## Limits

| limit | value |
|---|---|
| concurrent streams per machine | 1024 |
| stream opens per machine | 64 per second (burst 64); the daemon paces itself just below this, so a burst of local connections is delayed, not refused |
| frame payload | 65535 bytes (one frame per WebSocket message) |
| flow-control window | 256 KiB per stream, per direction |
| public request head | 32 KiB (larger: `431`) |
| public TLS handshake + request head | 10 s |
| public connection idle (no bytes either way) | 5 min |
| relay connections (any kind) | 16384 total, 256 per client IP |
| enrollment failures | 5 per IP per 10 minutes |
| relay-side stream data queued per machine | 32 MiB; when full, the relay stops reading from the machines sending to it until there is room, and a machine whose queue makes no progress for 20 s is disconnected |
| other frames queued per machine | 64 MiB (a machine that stops reading while provoking replies is disconnected) |

Violations are handled locally: an overrunning stream is reset, a malformed or
oversized frame closes that machine's connection, excess opens are refused with
an error code.

## How public TLS works

A published name `web` is served at `https://web.<publish domain>/` (by default
the publish domain is the relay's own domain). The relay terminates TLS using
a certificate for that exact name, obtained on first claim via ACME HTTP-01
(or from `--cert/--key`, e.g. a wildcard certificate). For every client
connection the relay opens one stream to the publishing machine, which
connects it to `127.0.0.1:PORT`. The relay parses each request head so it can
replace `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` with its
own values (client-supplied `Forwarded`, `X-Real-IP` and `X-Forwarded-*` are
removed) and so it can find the next request on keep-alive connections; bodies
(fixed length or chunked) are streamed, never buffered. After a successful
`Upgrade` (WebSocket) the connection becomes an opaque byte pipe.

Only one machine can hold a name; another machine's claim is always refused
and the owner changes its own publish only with `--replace`. Names stay owned
while the machine is offline (clients get `502`). The relay operator can map
custom domains to published names with `warren relay domain add`.

This traffic is visible to the relay by design. Anything that must stay
private belongs on a private link.

## Performance

Measured on loopback (Apple M-series, release build, relay and both machines
on one host, TLS + Noise, `cargo test --release --test bench -- --ignored
--nocapture`):

| measurement | result |
|---|---|
| private link throughput | 1.6 to 1.9 Gbit/s |
| added median round-trip latency | 0.07 to 0.08 ms |

## Development

```sh
cargo test                          # unit + end-to-end tests (real relay, 2-4 nodes)
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --release --test bench -- --ignored --nocapture
```

The end-to-end tests start a relay with a self-signed certificate on
`127.0.0.1` and nodes with temporary homes, and cover each security
requirement, including a capture of everything the relay receives and sends
that must never contain the plaintext sent over a private link. The
requirements the tests check are listed in [docs/security.md](docs/security.md).

Some tests hold about a thousand connections at once. The tests (like the
relay and the daemon) raise their soft open-file limit themselves; where the
hard limit is lower than that (some containers), raise it first, for example
with `ulimit -n 4096`. On Linux the binary-level test also needs `lsof` for
its socket check; with `WARREN_REQUIRE_LSOF=1` a missing `lsof` is a failure
rather than a skipped check.

CI (`.github/workflows/ci.yml`) runs formatting, clippy, the tests and the
docs on Linux and macOS, and checks the minimum Rust version. Release
binaries are built there with `--remap-path-prefix`, so they carry no paths
from the build machine; build any binary you publish the same way.

Protocol details: [docs/protocol.md](docs/protocol.md). Relay operations:
[docs/relay.md](docs/relay.md).

All traffic goes through the relay; machines never connect to each other
directly.

## License

MIT, see [LICENSE](LICENSE).
