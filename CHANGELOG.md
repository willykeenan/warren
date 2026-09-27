# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
semantic versioning.

## [1.0.0] - 2026-09-27

First release.

### Added

- One binary, `warren`, with the relay, the node daemon and the CLI.
- Relay: TLS on one port for nodes (`wss://…/v1/node`) and published names;
  certificates from `--cert/--key`, automatic ACME HTTP-01 (`--acme`, one
  certificate per name, renewed with 30 days left) or `--self-signed` for
  testing; state in one SQLite file.
- Enrollment with one-time codes (`warren relay invite`, `warren join`):
  10 characters, 10 minutes, single use, 5 failed attempts per IP per 10
  minutes, stored only as SHA-256.
- Node authentication by Ed25519 signature over a fresh challenge bound to the
  relay host; revocation (`warren relay revoke`) takes effect immediately.
- Multiplexed streams over one WebSocket with per-stream flow control (256 KiB
  window), 1024 streams and 64 opens per second per node, 64 KiB frames.
- Private links end-to-end encrypted with `Noise_IK_25519_ChaChaPoly_BLAKE2s`;
  the relay forwards ciphertext only. Destination-side, default-deny share
  policy (`warren share PORT [--to NODE,...]`).
- Peer key pinning (`known_peers.json`), `warren trust`, `warren devices`.
- `warren forward`, `warren nc` (ssh `ProxyCommand`), `warren ssh`.
- `warren publish` / `unpublish`: public HTTPS for a local port with
  keep-alive, chunked bodies, long polling and WebSocket upgrades;
  `X-Forwarded-For/Proto/Host` set by the relay; one owner per name; optional
  client CIDR allowlist; custom domains (`warren relay domain`).
- `warren status` (connection state, latency, shares, forwards, publishes,
  recent errors), `--json` on every command, documented exit codes.
- `warren install` / `uninstall`: launchd agent on macOS, systemd user unit on
  Linux.
- Reconnection with jittered backoff from 1 s to 60 s.
