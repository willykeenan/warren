# Local device enrollment broker

This Rust library leaf is not a working phone enrollment product. It adds no
listener, CLI, HTTP route, QR renderer, native ABI, Keychain code, or token endpoint.
It does not read or migrate the Python device service's `auth.json`. Only a trusted
local embedding may construct and call `EnrollmentBroker`.

## Identity and owner approval

`approve(&ServiceContext, &ServiceRegistration, Duration) -> Result<Approval>`
requires an actual confirmed bootstrap service context and an opaque management
registration. The broker captures the peer name, full static key, bootstrap port
and generation from the authenticated context, and the management port and
generation from its registration. Request JSON cannot supply identity. Each
operation uses `ServiceContext::with_authorization`, which guards its short
synchronous commit against transport revocation.

The frozen transport API exposes no local registration identity accessor. A
preliminary confirmed bootstrap connection is therefore required before local
owner approval. Its borrowed context lives only inside the handler, subject to
the transport's 30-second operation deadline. The future local owner bridge must
obtain a decision within that lifetime or explicitly start a fresh interaction.
This does not implement an owner-first, one-scan phone flow. The approval result
must go exclusively to the local owner UI; the preliminary remote connection
must never automatically receive the approval secret or QR material. A later
registration-authority API would require separate review.

Approval permits one pending or active phone generation. It generates a 128-bit
identifier and 256-bit secret. Only the secret hash is stored. TTL is an integral
1–120 seconds. An existing pending or active generation cannot be silently
replaced. The caller must explicitly revoke before approving another generation.
Management registration should target the same peer/key and original daemon;
redemption cannot grant a differently bound management context access.

`redeem(&ServiceContext, &id, &secret) -> Result<Credential>` only accepts the
exact bootstrap peer, key, port, generation and secret. It atomically stores the
consumed enrollment tombstone and a new credential hash before returning the
256-bit credential. The returned credential has a random 128-bit identifier and
an absolute expiry. Deliver it only over that confirmed secure channel. Neither
secret wrapper implements Debug, Display, Serialize or Clone. Callers can still
copy bytes through explicit accessors and must avoid logging them. This library
does not promise secret heap zeroization.

## Management and revocation

`with_management(&ServiceContext, &credential_id, &token, commit)` accepts only
the captured management registration, same confirmed peer/full key, valid token
and unexpired credential. `commit` is a short synchronous action inside the
transport authorization guard and broker mutex. It must not await, call back into
the broker, or treat authorization as a capability for later detached work. The
embedding owns atomicity and uncertain-result handling for its own backend
mutation; this broker does not supply a distributed transaction or audit log.

`revoke_management(&DaemonInner).await` first removes broker authorization
durably, then revokes and drains both saved service registrations on the original
daemon. Do not await it from either of those handlers, because revocation cancels
the handler itself. Concurrent revoke calls serialize. Cancellation retains the
bindings and denial state so an explicit retry can finish draining. A storage or
drain error is not a clean acknowledgement and poisons further broker access;
transport draining is still attempted after storage failure. An unexpected daemon
argument cannot confirm a drain. Named LAN-device shares remain independently
managed and are not removed by management revocation.

## Time, persistence and failures

Approvals expire after at most 120 seconds; credentials after at most 24 hours.
Both wall and monotonic deadlines apply. Observed wall-clock or monotonic rollback
poisons the live broker. Successful state operations durably advance the wall
high-water mark. Startup before that mark is denied. The injectable `Clock` is
trusted local infrastructure for tests/embedding, never remote request input.

Every broker restart invalidates **both pending approvals and active
credentials**, retaining consumed identifiers. This deliberately requires new
local approval after restart and avoids reconstructing monotonic lifetimes or
replaying a token response. A failed/ambiguous consume never returns a credential;
restart burns any surviving pending state. Lost responses do not authorize an
automatic redemption retry, automatic owner approval, or token replay. Recovery
requires an explicit owner action and fresh registrations/approval as applicable.

The caller provides an already private, owned directory. SQLite uses a retained
exclusive process lock, DELETE journal, synchronous EXTRA and fullfsync, followed
by directory sync before success. Database initialization and mutations are
checked for failure; ambiguous errors make the live broker unusable. Records are
strictly parsed and bounded to 128 KiB; the database is limited to 1 MiB. At most
128 consumed identifiers are retained; older unknown identifiers still cannot
redeem. A second process cannot open the same live store.

The current storage implementation supports macOS and Linux only. Other targets,
including Windows and iOS, return `platform_not_qualified`. The directory must
be owned by the current uid with mode 0700 and database/journal files mode 0600.
Symlinks, hardlinks, unexpected entries and inode replacement are refused.
macOS extended ACLs are refused using a fixed read-only `/bin/ls` invocation
on the gateway only; this process-spawn path is never available on the phone.
Unknown files are never chmod-repaired. Open directory/database handles pin inode
identity for subsequent checks. These protections assume the current uid and
its private parent hierarchy are trusted; this is not a sandbox against an
adversary already running as that uid.

## Verification and remaining integration

Tests use synthetic stores and confirmed contexts over a local two-node relay.
They cover concurrent single-use redemption, wrong secret/context/key binding,
expiry, clock rollback, restart, permission/ACL/symlink/hardlink rejection,
exclusive ownership, an actual SQLite write failure, abrupt post-commit process
exit, secret absence in persistence/relay bytes, and service revoke/drain. Local
macOS tests do not qualify Linux runtime behavior, Windows ACLs, full-volume
faults, or physical power loss during filesystem flush.

A future integration still needs a reviewed trusted owner bridge, protocol
framing and parsing, local confirmation/QR flow, authenticated token delivery,
credential custody in Keychain, the Swift/Rust ABI, native bootstrap and management
handlers, device-service backend transactions/reconciliation, and end-to-end
phone evidence. No existing API token is exposed by this leaf. The library alone
does not establish installed enrollment or phone connectivity.
