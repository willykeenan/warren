# Disposable Windows scheduler acceptance

This opt-in test changes the current user's Task Scheduler registrations. Run it
only in a disposable Windows VM with an existing interactive user session. It
creates no users, changes no service configuration, and never logs anyone off.
Do not run it on a personal workstation. No workflow automatically enables it.

From a clean checkout with Rust and Windows PowerShell available:

```powershell
$env:WARREN_DISPOSABLE_WINDOWS_ACCEPTANCE = 'I_ACKNOWLEDGE_DISPOSABLE_INTERACTIVE_WINDOWS'
$env:WARREN_ACCEPTANCE_RESULT = "$PWD\acceptance-results\scheduler.json"
git rev-parse HEAD | Set-Content "$PWD\acceptance-source.txt"
cargo test --locked --test windows_scheduler_acceptance disposable_scheduler_lifecycle -- --ignored --nocapture --test-threads=1
```

Keep the source commit, JSON result, and Cargo log together. Before any fixture is created, the result atomically replaces any prior success
with a unique current run ID and non-PASS state. Checkpoints record fixture paths,
binary hash and the exact expected task name before registration, then observed
PIDs/events before termination, clean down, uninstall and cleanup. Abrupt runner
loss therefore leaves a non-PASS recovery record at the printed path. The result binds the
copied executable by SHA-256 and records the current SID/session, Windows version,
exact task name, task XML, daemon PIDs, scheduler state/result, and cleanup result.
The binary is copied to a unique path containing spaces. A real local relay and
fresh enrolled node exercise the production CLI and authenticated local IPC.

Ordinary `cargo test` ignores this side-effecting test. **Ignored is not PASS.**
Explicit execution without Windows, opt-in, an interactive token outside session
zero, or Task Scheduler capability writes `BLOCKED` and exits unsuccessfully.
`WARREN_ACCEPTANCE_RESULT` chooses the output path; without it, the printed result
path is a PID-specific file in the temporary directory. Hosted service-session CI
may legitimately be blocked; do not count a missing execution context as success.

The test checks actual registration without startup, the task's user/command/home
and logon policy, ordinary install startup and connected IPC, a different daemon
PID after forced termination (120-second bound), clean down without restart for
90 seconds, exact task deletion using a dot spelling of the home, and repeated
uninstall. Each child command has a 20-second limit; the lifecycle has a nine-minute
limit. Cleanup disables/stops/deletes only the exact task after verifying its
executable and home, and checks for surviving processes by the unique copied
executable path. Timeouts and caught panics also attempt cleanup. Abruptly killing
the entire test runner still requires inspecting and cleaning the exact recorded
task in the disposable VM. If cleanup fails, the result retains and identifies the
fixture paths for recovery; inspect that result before discarding the VM.

`PARTIAL` with `schedulerStatus: PASS` means those scheduler lifecycle gates passed.
It does **not** prove the fresh-logon trigger. That gate always remains explicitly
`BLOCKED` until a separate VM controller performs a real logoff/logon while keeping
the evidence collector alive. Other-account and reduced-integrity counterfeit-pipe
fixtures are also separate outstanding acceptance work; this test does not claim
them. Neither a macOS build nor a Windows typecheck establishes runtime acceptance.
