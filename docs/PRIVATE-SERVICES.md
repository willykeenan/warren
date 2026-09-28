# Authenticated in-process private services (Rust primitive)

`DaemonInner::register_private_service(port, peer, expected_key, handler)` reserves a
nonzero ordinary private port for one exact, already explicitly trusted peer key.
It returns an opaque `ServiceRegistration` with a fresh random generation. The
local embedding application must authorize registration; no network or CLI
registration endpoint is provided. Registration is memory-only and is lost on
restart. It never creates or replaces a peer pin. A TOFU pin (`trusted_at: null`)
is insufficient. The caller supplies the full 32-byte key, not a fingerprint prefix.

`PrivateServiceHandler::handle` receives `&ServiceContext` and `&mut SecureChannel`
only after the existing Noise IK exchange and fresh encrypted confirmation. Both
the relay's source claim and the authenticated Hello must match the granted peer,
key, destination and port. Hello stays v1, `share` must be absent, OPEN stays
flags=0 with a nonzero port, and no new relay or cipher protocol is introduced.
The context cannot be constructed by HTTP headers or application request bytes.
The runtime does not bind a TCP listener or forward to loopback.

The handler is trusted Rust code. It must use bounded parsing, yield to Tokio,
and keep all operation work within the borrowed future. Do not spawn detached
mutations or stream tasks, block a runtime thread, recursively call the service
runtime inside an authorization closure, or put authorization metadata into
unauthenticated HTTP headers. There are at most 32 concurrent operations across
services, 64 reserved ports per daemon lifetime, and a 30-second total deadline
including handshake and handler. These are short-request services, not persistent
stream tunnels. Cancellation cannot preempt arbitrary blocking Rust code. A panic inside an
authorization commit permanently disables all service grants on that daemon
instance; recovery requires restarting and explicitly registering again.

The context exposes `peer_name()`, `peer_static_key()` and `registration()`.
`context.with_authorization(|| synchronous_commit())` checks the current exact
pin and registration generation and holds the revocation lock through a short
synchronous local commit. Use this immediately before consuming an enrollment
approval or changing protected state. Async backend commits need their own
atomic generation-aware transaction; checking and then awaiting a write is not
an atomic authorization boundary. The transport supplies no token persistence,
application transaction, audit ledger, expiry policy, or credential rollback.

`DaemonInner::revoke_private_service(&registration)` invalidates the generation,
cancels all its pending handshakes and active handler futures, and waits until
their streams are dropped. A stale handle cannot revoke a replacement generation.
Each reserved slot retains its last exact opaque registration after explicit
revocation, policy loss, shutdown, or a handler panic. A handle from another daemon
or a superseded generation fails even when that port is already revoked. Repeating
revoke with the same current registration is idempotent and still waits for any
remaining operations of that generation to drain; an already revoked replacement
does not make older handles valid again. Identity is the full random 256-bit
generation plus port, retained only for this daemon instance's lifetime.
Registration on the same port requires old operations to finish draining and gets
a new generation. Revocation errors must not be treated as a clean acknowledgment.
Do not await a service's own revoke from inside its handler: cancellation drops
that handler before it can deliver a response. The local owner must orchestrate
revocation separately and define any application acknowledgment semantics.
Dropping a registration handle does not revoke it: the owner must explicitly revoke
or stop the daemon. Daemon shutdown cancels and drains these operations too.

Ordinary TCP shares and public publishes conflict with reserved service ports.
Both registration and supported local share/publish mutations reject collisions.
Reserved-port tombstones remain for the daemon instance's lifetime, including
after shutdown, so revocation cannot turn
a service request into an ordinary TCP/TOFU connection. Disk policy is rechecked
at admission, after confirmation, and by a 100ms watcher. Removed/changed/untrusted
pins, unreadable policy or an external share/publish collision cancel the generation;
repair does not reactivate it. Direct external file writes are not atomic with a
handler commit: use the supported revoke API for an acknowledged authorization
boundary. Ordinary shares outside these reserved ports and named gateways retain
their existing behavior. This does not cancel older ordinary-share connections
that were already established before an ordinary share was removed.

This is a local source primitive, not implemented device enrollment. The embedding
owner still must provide explicit local approval, a secure broker with single-use
redemption and durable generation-aware state, per-credential expiry and revoke,
an explicitly pinned client open path, native ABI/lifecycle and Keychain handling,
and native acceptance tests. The existing `open_private` client can still use TOFU;
a future native enrollment bridge must enforce its expected full destination pin
before opening. No token-returning endpoint or native ABI is added here.
