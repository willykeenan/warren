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

With Rust 1.85 or newer, on the relay host install the binary where `sudo`
finds it (`sudo` does not search `~/.cargo/bin` on most distributions):

```sh
cargo build --release && sudo install -m 755 target/release/warren /usr/local/bin/warren
```

On your machines either do the same or run `cargo install --path .`.

### 3. Run the relay (on the server)

```sh
sudo warren relay --domain relay.example.com --acme you@example.com --state /var/lib/warren
```

The relay listens on 443 (nodes and published names) and, with `--acme`, on 80
for certificate challenges. Certificates come from Let's Encrypt automatically.
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

## Commands

| command | what it does |
|---|---|
| `warren relay [flags]` | run the relay (see `docs/relay.md`) |
| `warren relay invite [--name N]` | print a one-time enrollment code (on the relay host) |
| `warren relay nodes` / `revoke NAME` / `domain add HOST NAME` / `info` | relay administration |
| `warren join CODE --relay URL [--name N]` | enroll this machine (generates its keys) |
| `warren up` | run the node daemon in the foreground |
| `warren install` / `uninstall` | start `warren up` at login (launchd on macOS, systemd user unit on Linux) |
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

Nodes run on macOS and Linux. On Linux, systemd user services run only while
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
cargo clippy --all-targets -- -D warnings
cargo test --release --test bench -- --ignored --nocapture
```

The end-to-end tests start a relay with a self-signed certificate on
`127.0.0.1` and nodes with temporary homes, and cover each security
requirement, including a capture of everything the relay receives and sends
that must never contain the plaintext sent over a private link.

Protocol details: [docs/protocol.md](docs/protocol.md). Relay operations:
[docs/relay.md](docs/relay.md).

All traffic goes through the relay; machines never connect to each other
directly.

## License

MIT, see [LICENSE](LICENSE).
