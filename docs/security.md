# Security requirements

The tests refer to these requirements by number. The security model behind
them is described in the README.

| id | requirement | tests |
|---|---|---|
| SR1 | The relay never sees the plaintext of private streams. | `tests/e2e.rs` |
| SR2 | Unenrolled, forged, replayed, wrong-host and revoked credentials are refused. | `tests/e2e.rs`, `tests/security_revocation_race.rs`, `tests/security_reload_race.rs` |
| SR3 | Enrollment codes are single use, expire after 10 minutes, are rate-limited per IP address and are stored only as hashes. | `tests/e2e.rs` |
| SR4 | Default deny at the destination: only shared ports are reachable, only by the machines a share names, even through a compromised relay. | `tests/e2e.rs`, `tests/security_noise_replay.rs` |
| SR5 | A changed key for a pinned peer is refused until accepted with `warren trust NAME --expect FINGERPRINT`; an unreadable pin store is an error. | `tests/e2e.rs`, `tests/security_pin_store.rs` |
| SR6 | Resource limits: streams, open rate, frame size, flow-control windows, public request heads and timeouts, connections per client address. | `tests/e2e.rs`, `tests/robustness_*.rs` |
| SR7 | Published names cannot be taken by another machine, and clients cannot spoof `X-Forwarded-*` headers. | `tests/e2e.rs`, `tests/cli.rs` |
| SR8 | Node files are `0600` in a `0700` directory; keys and enrollment codes never appear in logs or `--json` output. | `tests/cli.rs`, `tests/e2e.rs`, `tests/security_trace_log.rs` |
| SR9 | The binary connects only to its relay, loopback ports, explicitly granted and validated LAN gateway targets, and on the relay to its ACME directory. | `tests/network_audit.rs`, `tests/cli.rs` |

To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Windows candidate boundary

Windows uses a protected user + SYSTEM DACL and a local named pipe in place of
Unix file modes and sockets. The client verifies pipe ownership; the server
rejects remote clients and requires the first instance. The only source module
permitted to contain unsafe code is `src/sys/windows.rs`, containing documented
Win32 calls and owned allocation/handle guards. All security policy and framing
logic is safe Rust and tested on the native host. This is a deliberate exception
to the earlier crate-wide unsafe ban and needs independent security review.
Windows kernel behavior and cross-account rejection still require Windows proof.

Named gateways bind grants to pinned static keys and have acknowledged active
revocation. See [gateway security](gateway-shares.md) for the narrower omitted
`--to` semantics, raw policy edit delay, unsupported overrides and release gates.

The correction candidate validates identity and policy bytes through the same
open handle used for reading. A policy file with unsafe ownership or outsider
access is rejected and preserved for explicit recovery; it is not automatically
made trustworthy by changing its ACL. A private file missing inheritance
protection is protected and rechecked on that handle. Ancestor handles deny
write/delete sharing during access. Local drive paths are the supported scope;
UNC/device paths, reparse points (including junction ancestors), alternate data
streams and hard-linked state files are rejected. Previously retained data-write
handles cause opening the private reader to fail rather than allowing an
unchecked concurrent writer. An account already able to run arbitrary code at
the daemon's integrity level, and administrators/SYSTEM, remain outside this
local isolation boundary.

New private files use unpredictable exclusive names, a private descriptor at
creation and replacement through the retained source handle. Background logs
retain their validated append handle and ancestor pins for their lifetime.
Pipe clients check an explicit mandatory no-write-up label before sending any
request, requiring medium integrity or higher and at least the caller's level,
in addition to exact owner SID and identification-only impersonation QoS. A
low-integrity same-account counterfeit pipe is therefore intended to be refused;
the cross-integrity Windows attack test remains mandatory before acceptance.

Required Windows checks include `cargo clippy --all-targets --locked`,
`cargo test --locked`, MSRV 1.88 all-target compilation, the ACL/alias/retained
handle regression tests, another-account and low-integrity counterfeit pipes,
real OpenSSH/binary half-close, and disposable Task Scheduler registration,
abnormal restart, clean down, alias-path uninstall and logon behavior. Portable
tests and a Windows Rust module compile do not establish any of those runtime
results.
