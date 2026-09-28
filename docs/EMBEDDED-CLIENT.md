# Embedded client Rust lifecycle

`warren::node::embedded` adds a client-only lifecycle with an explicit absolute
application storage directory. It does not choose HOME, bind or clean desktop
IPC, change resource limits, install anything, or register signal handlers.

- `join(&Path, code, relay, name, relay_certificate_pin)` returns `IdentityFile`.
  There is no force option. Any existing identity entry, including malformed
  data, refuses replacement. Enrollment has a 45-second total bound and retains
  ordinary relay invitation/signature/TLS checks. No control-path validation or
  IPC probe occurs. An uncertain result or cancellation is not retry authority.
- `EmbeddedClient::start(&Path)` loads the identity and starts the relay
  connection lifecycle. `wait_connected(Duration)` and `is_connected()` expose
  connection state. `shutdown(self).await` cancels and drains transport tasks;
  dropping the handle requests cancellation and aborts its tasks without an
  asynchronous acknowledgment. Prefer awaited shutdown before releasing a native
  context or replacing application storage.

Embedded mode does not load or restore shares, gateways, forwards or publishes,
including malformed persisted desktop policy. It creates no control/listening
socket, policy watcher or public publication. All unsolicited incoming OPENs
are refused before allocation/dispatch, regardless of seeded shares. The
existing desktop `DaemonConfig` fields and public function signatures stay
unchanged; desktop policy, IPC and forward behavior remain enabled.

Updated desktop and embedded join/start operations serialize ownership through
an OS-backed SQLite exclusive lock in `.warren-owner.sqlite3`, using the existing
SQLite dependency. The lock file stays private and is never unlinked; connection
close or process death releases ownership. Concurrent owners fail immediately.
On Unix, initialization creates the file only when absent; existing files are
checked without opening or closing their inode outside SQLite. This preserves a
live owner's POSIX lock when another attempt in the same process fails. Existing
lock files must be owned by the effective user, mode 0600, regular and singly
linked; insecure files and symlinks are rejected, not repaired. SQLite also opens
without following symlinks. These checks do not make mutable, hostile application
storage safe.
The already-created private root is canonicalized before appending the exact lock
filename. Ordinary parent-directory aliases (such as macOS `/tmp` or an app-owned
storage alias) therefore resolve to the same ownership lock as the canonical root.
The final lock-file component is never canonicalized: a symlink at that component
still fails, as do hardlinks, insecure permissions, or a different file owner.
Directory resolution does not open or close the ownership-file inode and does not
release another connection's POSIX lock. This does not protect against concurrent
replacement of caller-controlled storage directories by a hostile same-user writer.
Do not share an app storage root with an older binary that does not honor this
lock, or delete/replace the ownership file while any process may own it. The
application must control its private storage root; this is not protection against
another writer with the same OS identity modifying its files.

The handle exposes no public daemon, control, service-registration, forwarding
or unpinned-open methods. Its crate-private `handle` is the composition seam for
separately reviewed strict expected-key opening. That forwarding API is **not
implemented in this leaf**. One internal test uses ordinary opening with a
seeded explicit pin solely to prove transport and shutdown, not strict opening
approval. Public API tests cover long application paths, malformed irrelevant
policy, inbound refusal, no restored forwards/publications, same-root contention,
mixed same-process/cross-process contention, process-death lock release and IPC
sentinel preservation.
Alias-path tests enroll and start through a symlinked parent, exercise ownership
contention in both alias/canonical directions and separate processes, and repeat
final-file rejection checks through an aliased root. These are macOS host tests,
not iOS runtime or app-container acceptance.

Identity keys still live in private `identity.json` application-file storage.
Keychain/protected-data/backup exclusion, explicit verified peer approval,
strict pinned opening, C ABI, runtime ownership, iOS packaging and native device
acceptance are separate integration requirements. This is not native enrollment
or a mobile-delivered feature, and does not authorize background persistence.
