# Opening a stream with an explicitly trusted key

`DaemonInner::open_private_pinned(dest, port, expected_key: &[u8; 32])` opens an
ordinary private port using the caller's full expected Noise static public key.
The destination name must be valid and the port must be nonzero.
`DaemonInner::open_gateway_pinned(dest, share, expected_key)` uses the same guarded
core for a valid exact named gateway share: OPEN has `FLAG_GATEWAY` and port zero,
and the authenticated encrypted Hello contains `share`. It never retries a
refused named request as an ordinary port.

Before OPEN, the local pin store must be readable and valid, belong to the
node's relay, and contain that exact key with an explicit `trusted_at` approval.
A missing pin, TOFU-only pin, different key, or corrupt store is an error. Neither
method writes pins or asks the relay for a key, including after a handshake
failure. Provision approval through the existing owner-controlled trust path
after independently verifying the peer's full key; a relay-reported key or
matching display name alone is not that verification.

The method snapshots the approval record before waiting for a relay session.
Every actual OPEN enqueue rechecks that snapshot **after** pacing, rate-limit
retry delays, and acquiring the daemon trust lock. The final synchronous check
and enqueue contain no await and hold the same lock used by daemon trust writes.
That lock is released before waiting for OPEN acknowledgment or Noise. Removal
while pacing therefore causes zero OPEN; removal after a RateLimited response
causes no additional OPEN. This boundary is local enqueue, not delivery time:
an OPEN already queued before a policy change cannot be recalled from the wire.

After a successful OPEN acknowledgment, approval is checked again before starting
Noise; drift resets the stream without sending the handshake. After the awaited
Noise handshake, a final check rejects/reset streams whose approval changed.
Noise always uses the caller's expected key; successful relay routing does not
authenticate a peer. Both pinned methods share these checks. The ordinary
`open_private` and `open_gateway` paths keep their existing TOFU/fallback behavior.

This is opening authentication, not enrollment, a native ABI, or continuous
revocation. The destination may already have accepted its backend connection
before the final check. Approval changes after return do not close an existing
channel. The lock serializes daemon trust writes, not arbitrary external pin-file
writers; an external writer can race a synchronous check/enqueue. File edits that
remove and restore the identical approval record between observations are not
detectable; this API has no approval generation counter. Callers needing session
lifetime revocation or atomic credential consumption must implement that separate
policy using immutable generations and cancellation/drain.

`cargo test --locked --lib --test pinned_client --test gateway` covers real
loopback relay connections, explicit trust and encrypted payload exchange,
unchanged ordinary TOFU, pre-OPEN rejection, no lookup fallback, deterministic
pacing-time revocation, a relay-injected RateLimited retry and OPEN acknowledgment
revocation, and handshake-time drift/reset. Private unit fixtures control the
existing token bucket without a public test API. The named client test uses an
actual relay plus a peer-owned Noise responder to check the encrypted selector,
expected identity and authenticated refusal; it does not dial a LAN target or
qualify device enrollment. The existing real-interface gateway test remains
explicitly opt-in and is not run by this leaf.
