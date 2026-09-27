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
| SR9 | The binary connects only to its relay, to loopback ports and, on the relay, to its ACME directory. | `tests/network_audit.rs`, `tests/cli.rs` |

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
