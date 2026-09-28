# Named LAN gateway shares (source candidate)

A gateway runs Warren and connects an explicitly selected LAN TCP service to another Warren node. This candidate is not the Windows-inclusive v0.2.0 release, device discovery, a camera viewer, media conversion or a tested iPhone/device setup.

First check the peer's fingerprint on that peer, then pin it on the gateway:

```
warren trust laptop --expect FINGERPRINT
warren share --target camera.local:554 --name camera --to laptop
warren share
```

On the permitted laptop:

```
warren nc gateway --share camera
warren forward 8554 gateway --share camera
```

Only the gateway stores the LAN target. The client selects a name, never an arbitrary host or port. `share` lists local port grants and named gateways without printing raw targets. The daemon's local privileged `status` reports a gateway count and names, without targets or keys; any hub summary must export only the count. The private `shares.json` contains the exact target, random generation and snapshot of permitted peer names and static public keys.

Omitting `--to` grants all peers already pinned on the gateway at that moment. It does not authorize future peers. No pins means refusal with an instruction to verify and trust a peer. Changing a peer's trusted key does not update an existing gateway grant: grant the share again explicitly. Legacy `share PORT` retains its existing enrolled-node policy and loopback-only connection behavior.

## Revoke and replacement

```
warren unshare --name camera
```

While the daemon runs, gateway changes go through its private local control channel. Successful revoke waits for affected handlers and target TCP sockets to close, including unfinished handshakes and resolution/dial work. Replacing a share cancels its prior generation. Pending handshakes do not yet reveal a name, so any gateway policy change cancels those pending handshakes. Existing streams for unaffected named shares continue. Already delivered bytes cannot be recalled.

Offline changes are saved privately for the next daemon start. Direct edits to `shares.json` are checked on every gateway admission and before/after dial, and polled every 100 ms for existing streams. They do not provide acknowledged instant revocation; use the command. Unreadable or malformed policy cancels gateway access. A failed daemon save cancels access and requires a successful subsequent policy write or repair before restart.

## Address restrictions

Only exact RFC1918/link-local IPv4 or IPv6 ULA/link-local targets and ASCII `.local` names are admitted. Loopback, public, wildcard, unspecified, multicast, limited broadcast and the cloud metadata endpoint are rejected. IPv4 addresses ending in `.255` are conservatively denied. Identifying every directed broadcast on unusual subnet masks requires interface information that this candidate does not yet collect; that remains a delivery limitation. Scoped IPv6 is currently unsupported. There is no public or relay override. `.local` resolution uses the gateway's platform resolver; it is not discovery.

For every connect the gateway re-resolves the target and configured relay, bounds answers and total DNS/dial time to five seconds, rejects the entire answer if any target address is unsafe, and connects only validated numeric socket addresses. Fresh relay addresses and every observed connected relay address in the daemon lifetime are excluded. Failed or empty relay resolution denies the connection.

## Wire and privacy

Named streams require an upgraded relay and endpoints. The binary OPEN contains gateway flag `0x02` and reserved port `0`. The prior relay rejects port zero, preventing accidental downgrade to a loopback port. The name travels only in encrypted Noise Hello. Source, destination, mode, port and share are bound to the proven static key and the stored generation/grant. The target connection starts only after the initiator confirms the fresh Noise handshake, preserving replay protection. Unknown flags, gateway+public combinations and selector mismatches are rejected.

The relay still sees communicating nodes, gateway mode, timing and traffic volume. It does not receive share names, LAN targets or device credentials. A bounded private `gateway-audit.json` keeps up to 512 policy/connect/refusal records without targets, payloads, device passwords or raw keys. Device credentials belong in the device's own UI or separately approved local credential store, never Warren share arguments.

## Audit failures and recovery

New grants, both online and offline, require an audit write before saving policy. The `grant_intent` record means that a grant was requested; it does not claim that the later policy save succeeded. New connections require audit writes before accepting the gateway handshake, before resolving or dialing the target, and before accepting the encrypted stream. `connect_intent` and `connect_ready` describe those stages, not completed application traffic. Damaged, oversized or unwritable audit data denies those operations. Existing streams continue until revoked or otherwise closed.

Revocation always removes the saved grant and drains its active operations before attempting the audit write. If that final write fails, `unshare` returns an error explicitly saying that access was revoked and connections drained but audit is unavailable. Do not automatically replay a failed command. The local device API conservatively reports `revocation_not_confirmed` for this nonzero CLI result; the daemon's status can independently confirm that the share name is absent while audit remains degraded. Offline revocation likewise saves removal before reporting any audit error.

Local privileged `status` exposes `gateway_audit`: `degraded`, `last_write` (`unattempted`, `ok` or `failed`), a saturating failure count, the last failure time, and `admission: audit_write_required`. These fields contain no targets or raw errors. A readable file is not proof that its next write will succeed. Only a successful required write clears degraded state; every admission still requires its own write. Restarting clears in-memory health history but does not bypass checking the file.

The audit accepts at most 512 bounded records and rejects files larger than 1 MiB, malformed content and nonregular files. It never automatically discards damaged evidence. To recover, stop the daemon with `warren down` and confirm it is stopped. Preserve the exact `gateway-audit.json` from the selected Warren home (`WARREN_HOME` when set) under one new, private archive filename without overwriting an existing archive. Correct the specific directory, permission or storage problem, then restart with `warren up` and check status. The missing audit file is recreated on the next successful audit write. Existing saved grants remain in effect after repair, so revoke any unwanted grants while stopped before restarting. Keep the archive private for inspection; do not delete it or repeatedly reset the log to force admission.

Do not edit gateway policy with older Warren binaries: their old serializer may discard the new gateway collection, revoking it. No gateway field can turn into a legacy local-port share. Existing local-port revocation semantics are unchanged; the acknowledged active-stream revocation above applies to named gateways only.

Acceptance remains separate: Windows runtime/DACL/framing, production relay/ACME, real LAN device and simulated-iPhone viewer evidence must pass before release or public claims.
