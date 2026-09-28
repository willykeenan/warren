# Warren native ABI v1 — source candidate

This standalone Rust static-library crate exposes the fixed versioned C header in
`include/warren_native_v1.h`. It is not a packaged or independently accepted native
product. Build from this directory, using the same locked dependency versions as
Warren. The root crate remains safe Rust; raw-pointer handling is confined here.

All blocking entry points must run on dedicated background dispatch lanes, never
Swift's main actor or a Tokio runtime thread. Pointers must be aligned, valid for
their stated full object/length, non-overlapping, and borrowed until return. There
are no callbacks and no caller pointers in detached tasks. Buffers are bounded at
64 KiB. Writes report bytes enqueued locally, not application delivery.

A context owns explicit caller-provided storage. Preparing iOS protected storage,
backup exclusion, device-only Keychain credentials, lifecycle presentation and
application packaging remain native-app responsibilities. No default home or
shared application-group directory is chosen here.

Cancellation before dispatch is effect-free. Cancellation of begun I/O terminates
both stream directions; close and stop retain ownership until outstanding calls
drain. A deadline leaves the closing stream or stopping context available only
for cleanup. Release terminal operation handles explicitly. Never replay join,
approval, forget or writes automatically after an uncertain result.

The source contract and tests require the parent's independently accepted embedded
public surface and allocation-aware SecureAbort composition. Pending candidates
must not be substituted. See the parent evidence result for the exact source and
executed validation state; declarations and test source are not proof of a build.

Operation completion chooses one numeric result; it does not release an active
call's ownership. Operation release remains BUSY through output and cleanup, and
stream close/stop wait for those output lifetimes too. Context destruction marks
the context dead while holding the child-admission lock, rejecting callers that
previously looked it up before destruction.

Start uses an owned initialization driver. Its elapsed deadline bounds the waiting
caller, followed by at most two seconds of cleanup waiting. If filesystem work is
still blocked, the context remains STOPPING and retains ownership until that work
returns and shutdown drains. A hung filesystem can therefore prevent restart or
destroy; it cannot silently free the live context. Unclassified join failures use
INTERNAL with MAY_HAVE_EFFECT because core's generic error can represent storage
or transport failure. These errors must never trigger automatic enrollment retry.

Run the adapter tests serially (`cargo test --locked -- --test-threads=1`) because
v1 intentionally permits one context per process. They use temporary storage and
a synthetic loopback relay, including exact-key denial, encrypted round trips,
authenticated half-close, read remainder, cancellation, and deterministic lifecycle
race barriers. Static-library consumer linking and Apple packaging are separate
checks; neither these tests nor an archive establish installed device behavior.

A failed begun I/O call closes both directions and schedules owned buffer/direction
cleanup after outstanding calls finish. Its error return acknowledges only that
call's borrowed memory lifetime. Invoke stream close or context stop to obtain the
complete drain acknowledgement; no new I/O is admitted on the closing stream.
