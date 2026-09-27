//! Explicit opt-in acceptance for a disposable, interactive Windows runner.
//! Normal `cargo test` ignores this test; ignored is NOT runtime acceptance.
//! See docs/windows-acceptance.md. No production behavior is replaced or mocked.
mod common;

use anyhow::{bail, ensure, Context, Result};
use futures_util::FutureExt;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::process::Command;
use warren::node::control::{self, ControlError, ControlRequest};
use warren::node::NodePaths;

const PROBE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scripts/windows-scheduler-probe.ps1"
);
const BIN: &str = env!("CARGO_BIN_EXE_warren");

fn new_report() -> Value {
    json!({"schemaVersion":2, "runId":format!("{}-{:032x}", std::process::id(), rand::random::<u128>()),
        "runnerPid":std::process::id(), "status":"BLOCKED", "schedulerStatus":"BLOCKED",
        "freshLogon":{"status":"BLOCKED", "reason":"Requires a separately orchestrated real logoff/logon in a disposable interactive VM; this harness never logs off users"}, "events":[], "observedDaemonPids":[]})
}

fn checkpoint(report: &mut Value, path: &Path, phase: &str) -> Result<()> {
    report["phase"] = json!(phase);
    report["checkpointUnixMillis"] = json!(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    // Same-directory atomic replacement: interrupted writes leave the preceding
    // checkpoint intact, never a partially serialized current result.
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), report)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn lifecycle_checkpoint(
    f: &Fixture,
    events: &[Value],
    report: &mut Value,
    path: &Path,
    phase: &str,
) -> Result<()> {
    report["taskName"] = json!(f.label);
    report["events"] = json!(events);
    checkpoint(report, path, phase)
}

async fn output(mut command: Command) -> Result<Value> {
    command.kill_on_drop(true);
    let out = tokio::time::timeout(Duration::from_secs(20), command.output())
        .await
        .context("command exceeded 20 seconds")??;
    ensure!(
        out.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).context("command did not return JSON")
}

fn probe(mode: &str) -> Command {
    let mut c = Command::new("powershell.exe");
    c.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        PROBE,
        "-Mode",
        mode,
    ]);
    c
}

struct Fixture {
    // Keep this directory alive until the exact task and daemon are removed.
    root: tempfile::TempDir,
    exe: PathBuf,
    home: PathBuf,
    label: Option<String>,
}
impl Fixture {
    fn new(home: PathBuf) -> Result<Self> {
        let root = tempfile::Builder::new()
            .prefix("warren scheduler ")
            .tempdir()?;
        let tools = root.path().join("my tools");
        std::fs::create_dir(&tools)?;
        let exe = tools.join("warren.exe");
        std::fs::copy(BIN, &exe)?;
        Ok(Self {
            root,
            exe,
            home,
            label: None,
        })
    }
    fn expected_label(&self) -> Result<String> {
        #[cfg(windows)]
        {
            warren::install::label(&warren::install::InstallOptions {
                flavor: warren::install::Flavor::TaskScheduler,
                exe: self.exe.clone(),
                warren_home: self.home.clone(),
                custom_home: true,
                dir: None,
                start: false,
            })
        }
        #[cfg(not(windows))]
        {
            bail!("native Windows task identity is required")
        }
    }
    fn command(&self, home: &Path, args: &[&str]) -> Command {
        let mut c = Command::new(&self.exe);
        c.arg("--json")
            .arg("--home")
            .arg(home)
            .args(args)
            .env_remove("WARREN_TASK_DIR")
            .env_remove("WARREN_HOME")
            .env("HOME", self.root.path())
            .env("LOCALAPPDATA", self.root.path());
        c
    }
    fn probe(&self, mode: &str) -> Command {
        let mut c = probe(mode);
        c.arg("-FixtureExe")
            .arg(&self.exe)
            .arg("-FixtureHome")
            .arg(&self.home);
        if let Some(label) = &self.label {
            c.arg("-TaskName").arg(label);
        }
        c
    }
    fn recover_label(&mut self) -> Result<()> {
        let path = self.home.join("login-task-name.json");
        if path.exists() {
            self.label = Some(serde_json::from_slice(&std::fs::read(path)?)?);
        }
        Ok(())
    }
    async fn task(&self) -> Result<Value> {
        output(self.probe("Task")).await
    }
    async fn cleanup(&mut self) -> Result<Value> {
        let recovered = self.recover_label();
        let paths = NodePaths::new(&self.home);
        // Attempt all cleanup steps even if one fails. Delete the task first to
        // prevent a pending restart, then terminate only our unique copied exe.
        let task = if self.label.is_some() {
            output(self.probe("Cleanup")).await
        } else {
            Ok(json!({"created":false}))
        };
        let processes = output(self.probe("CleanupProcesses")).await;
        let absent = wait_absent(&paths, Duration::from_secs(10)).await;
        recovered?;
        let task = task?;
        let processes = processes?;
        absent?;
        Ok(json!({"task":task, "processes":processes}))
    }
}

async fn status(paths: &NodePaths) -> Result<Option<Value>> {
    match tokio::time::timeout(
        Duration::from_secs(3),
        control::request(paths, &ControlRequest::Status),
    )
    .await?
    {
        Ok(r) => {
            ensure!(r.ok, "status refused: {r:?}");
            Ok(Some(r.result))
        }
        Err(ControlError::NotRunning) => Ok(None),
        Err(e) => Err(e.into()),
    }
}
async fn wait_connected(paths: &NodePaths, old_pid: Option<u64>, seconds: u64) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        if let Some(s) = status(paths).await? {
            let pid = s["daemon"]["pid"]
                .as_u64()
                .context("status has no daemon PID")?;
            if Some(pid) != old_pid && s["connection"]["state"] == "connected" {
                return Ok(s);
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bail!("no new connected daemon within {seconds} seconds")
}
async fn wait_absent(paths: &NodePaths, duration: Duration) -> Result<()> {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        if status(paths).await?.is_none() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bail!("daemon did not stop")
}
async fn lifecycle(
    f: &mut Fixture,
    preflight: &Value,
    events: &mut Vec<Value>,
    report: &mut Value,
    result_path: &Path,
) -> Result<()> {
    let paths = NodePaths::new(&f.home);
    let install = output(f.command(&f.home, &["install", "--no-start"])).await;
    f.recover_label()?; // Also recover on a command failure after registration.
    lifecycle_checkpoint(f, events, report, result_path, "registration_returned")?;
    let install = install?;
    ensure!(install["started"] == false, "--no-start reported a start");
    ensure!(
        install["label"].as_str() == f.label.as_deref(),
        "saved label mismatch"
    );
    let task = f.task().await?;
    ensure!(task["exists"] == true, "task was not registered");
    ensure!(
        task["sid"] == preflight["sid"] && task["triggerSid"] == preflight["sid"],
        "task user mismatch"
    );
    ensure!(task["logonType"] == "InteractiveToken", "wrong logon type");
    ensure!(task["restartInterval"] == "PT1M", "wrong restart policy");
    let arguments = task["arguments"].as_str().context("no task arguments")?;
    ensure!(
        arguments.starts_with("up --background --home ")
            && arguments.contains(f.home.to_str().context("non Unicode fixture home")?),
        "task home arguments mismatch"
    );
    // Query the real scheduler repeatedly; neither IPC nor a task instance may start.
    for _ in 0..12 {
        ensure!(
            status(&paths).await?.is_none(),
            "--no-start launched a daemon"
        );
        ensure!(
            f.task().await?["instances"] == 0,
            "--no-start launched a task instance"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    events.push(json!({"gate":"registration_no_start", "status":"PASS", "task":task}));
    lifecycle_checkpoint(f, events, report, result_path, "before_start")?;
    let start = output(f.command(&f.home, &["install"])).await?;
    ensure!(
        start["started"] == true && start["label"].as_str() == f.label.as_deref(),
        "ordinary install did not start same task"
    );
    let first = wait_connected(&paths, None, 20).await?;
    let first_pid = first["daemon"]["pid"].as_u64().unwrap();
    report["observedDaemonPids"]
        .as_array_mut()
        .unwrap()
        .push(json!(first_pid));
    lifecycle_checkpoint(f, events, report, result_path, "observed_first_daemon")?;
    ensure!(
        f.task().await?["instances"] == 1,
        "expected exactly one scheduled instance"
    );
    events.push(json!({"gate":"explicit_start", "status":"PASS", "pid":first_pid}));
    lifecycle_checkpoint(f, events, report, result_path, "before_abnormal_exit")?;
    let mut kill = f.probe("Kill");
    kill.arg("-ProcessId").arg(first_pid.to_string());
    let terminated = output(kill).await?;
    events.push(json!({"gate":"forced_exit", "status":"OBSERVED", "termination":terminated}));
    lifecycle_checkpoint(f, events, report, result_path, "waiting_for_restart")?;
    let second = wait_connected(&paths, Some(first_pid), 120).await?;
    let second_pid = second["daemon"]["pid"].as_u64().unwrap();
    report["observedDaemonPids"]
        .as_array_mut()
        .unwrap()
        .push(json!(second_pid));
    lifecycle_checkpoint(f, events, report, result_path, "observed_restarted_daemon")?;
    events.push(json!({"gate":"abnormal_restart", "status":"PASS", "termination":terminated, "newPid":second_pid, "task":f.task().await?}));
    lifecycle_checkpoint(f, events, report, result_path, "before_clean_down")?;
    output(f.command(&f.home, &["down"])).await?;
    wait_absent(&paths, Duration::from_secs(10)).await?;
    let stopped = Instant::now();
    while f.task().await?["instances"] != 0 {
        ensure!(
            stopped.elapsed() < Duration::from_secs(10),
            "scheduled instance did not exit after clean down"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let quiet = Instant::now();
    while quiet.elapsed() < Duration::from_secs(90) {
        ensure!(
            status(&paths).await?.is_none(),
            "clean down restarted daemon"
        );
        ensure!(
            f.task().await?["instances"] == 0,
            "clean down left or restarted task instance"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    events.push(json!({"gate":"clean_down_no_restart", "status":"PASS", "observedSeconds":quiet.elapsed().as_secs(), "task":f.task().await?}));
    lifecycle_checkpoint(f, events, report, result_path, "before_alias_uninstall")?;
    let alias = f.home.join(".");
    let uninstall = output(f.command(&alias, &["uninstall"])).await?;
    ensure!(
        uninstall["label"].as_str() == f.label.as_deref(),
        "alias uninstalled wrong label"
    );
    ensure!(
        f.task().await?["exists"] == false,
        "task still exists after uninstall"
    );
    ensure!(
        !f.home.join("login-task.xml").exists() && !f.home.join("login-task-name.json").exists(),
        "registration files remain"
    );
    lifecycle_checkpoint(f, events, report, result_path, "before_repeated_uninstall")?;
    let again = output(f.command(&alias, &["uninstall"])).await?;
    ensure!(
        again["commands"].as_array().is_some_and(Vec::is_empty),
        "repeated uninstall was not a no-op"
    );
    events.push(json!({"gate":"alias_uninstall", "status":"PASS", "repeatedUninstall":again}));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit disposable Windows opt-in; see docs/windows-acceptance.md"]
async fn disposable_scheduler_lifecycle() {
    let result_path = std::env::var_os("WARREN_ACCEPTANCE_RESULT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!(
                "warren-scheduler-acceptance-{}.json",
                std::process::id()
            ))
        });
    let mut report = new_report();
    checkpoint(&mut report, &result_path, "initializing")
        .expect("must replace any stale result before starting");
    eprintln!(
        "Windows acceptance run {}: {}",
        report["runId"],
        result_path.display()
    );
    let outcome = match std::panic::AssertUnwindSafe(run(&mut report, &result_path))
        .catch_unwind()
        .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!(
            "acceptance harness panicked; inspect the Cargo log"
        )),
    };
    if let Err(error) = &outcome {
        report["error"] = json!(format!("{error:#}"));
    }
    checkpoint(&mut report, &result_path, "finished").unwrap();
    eprintln!(
        "Windows acceptance result: {}\n{}",
        result_path.display(),
        report
    );
    outcome.unwrap();
}
async fn run(report: &mut Value, result_path: &Path) -> Result<()> {
    ensure!(cfg!(windows), "BLOCKED: native Windows is required");
    ensure!(
        std::env::var("WARREN_DISPOSABLE_WINDOWS_ACCEPTANCE").as_deref()
            == Ok("I_ACKNOWLEDGE_DISPOSABLE_INTERACTIVE_WINDOWS"),
        "BLOCKED: explicit disposable Windows opt-in is required"
    );
    let preflight = output(probe("Preflight"))
        .await
        .context("BLOCKED: Windows scheduler preflight unavailable")?;
    report["preflight"] = preflight.clone();
    ensure!(
        preflight["interactive"] == true,
        "BLOCKED: this token is not an interactive user token outside session zero"
    );
    ensure!(
        preflight["scheduleRunning"] == true && preflight["schtasksAvailable"] == true,
        "BLOCKED: Task Scheduler service or schtasks unavailable"
    );
    report["status"] = json!("FAIL");
    report["schedulerStatus"] = json!("FAIL");
    checkpoint(report, result_path, "before_fixture_creation")?;
    let mut relay = common::start_relay().await;
    let node = common::enroll(&relay, "scheduler-fixture").await;
    let mut fixture = Fixture::new(node.paths.home.clone())?;
    report["binarySha256"] = json!(warren::crypto::sha256_hex(&std::fs::read(&fixture.exe)?));
    report["fixtureHome"] = json!(fixture.home);
    report["fixtureExe"] = json!(fixture.exe);
    fixture.label = Some(fixture.expected_label()?);
    report["taskName"] = json!(fixture.label);
    report["expectedTaskName"] = json!(fixture.label);
    report["registrationNameFile"] = json!(fixture.home.join("login-task-name.json"));
    report["cleanup"] = json!({"status":"PENDING"});
    checkpoint(report, result_path, "before_registration")?;
    let mut events = Vec::new();
    let result = tokio::time::timeout(
        Duration::from_secs(540),
        std::panic::AssertUnwindSafe(lifecycle(
            &mut fixture,
            &preflight,
            &mut events,
            report,
            result_path,
        ))
        .catch_unwind(),
    )
    .await;
    report["events"] = json!(events);
    report["taskName"] = json!(fixture.label);
    // A checkpoint error must not prevent cleanup of already-created resources.
    let recovery_checkpoint = checkpoint(report, result_path, "before_cleanup");
    let cleanup = fixture.cleanup().await;
    report["cleanup"] = match &cleanup {
        Ok(v) => json!({"status":"PASS", "task":v}),
        Err(e) => json!({"status":"FAIL", "error":format!("{e:#}")}),
    };
    // Retain paths when cleanup fails, so an orphaned task never points at a deleted binary.
    if cleanup.is_err() {
        report["retainedBinaryDirectory"] = json!(fixture.root.keep());
        report["retainedNodeDirectory"] = json!(node.dir.keep());
    }
    relay.stop().await;
    checkpoint(report, result_path, "cleanup_finished")?;
    cleanup?;
    recovery_checkpoint?;
    result
        .context("scheduler lifecycle exceeded nine minutes")?
        .map_err(|_| anyhow::anyhow!("scheduler lifecycle panicked; cleanup was attempted"))??;
    report["schedulerStatus"] = json!("PASS");
    report["status"] = json!("PARTIAL"); // Fresh logon remains BLOCKED even when all lifecycle gates pass.
    Ok(())
}

// Bounded source guard, not a replacement for native PowerShell parsing. It
// catches the simple/scoped automatic-variable assignments used by this helper.
fn automatic_assignments(source: &str) -> Vec<String> {
    const RESERVED: &[&str] = &[
        "home",
        "pid",
        "pshome",
        "host",
        "psversiontable",
        "psedition",
        "shellid",
        "executioncontext",
        "true",
        "false",
        "null",
    ];
    source
        .lines()
        .filter_map(|line| {
            let (left, _) = line.split_once('=')?;
            let token = left.rsplit_once('$')?.1.trim_start_matches('{');
            let name: String = token
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
                .collect();
            let name = name.rsplit(':').next()?.to_ascii_lowercase();
            RESERVED.contains(&name.as_str()).then_some(name)
        })
        .collect()
}

#[test]
fn powershell_reserved_assignment_guard() {
    let source = include_str!("../scripts/windows-scheduler-probe.ps1");
    assert!(automatic_assignments(source).is_empty());
    let regression = source.replace("$taskHome", "$hOmE");
    assert!(automatic_assignments(&regression).contains(&"home".to_string()));
    assert_eq!(
        automatic_assignments("$global:HOME = 'x'\n[int]$PiD = 4"),
        ["home", "pid"]
    );
}

#[test]
#[ignore = "receipt-only child process used by receipt_survives_abrupt_exit"]
fn receipt_crash_child() {
    let path = PathBuf::from(std::env::var_os("WARREN_RECEIPT_TEST_PATH").expect("test-only path"));
    let phase = std::env::var("WARREN_RECEIPT_TEST_PHASE").unwrap();
    let mut report = new_report();
    checkpoint(&mut report, &path, "initializing").unwrap();
    if phase == "before_abnormal_exit" {
        report["fixtureHome"] = json!("synthetic-receipt-control/home");
        report["fixtureExe"] = json!("synthetic-receipt-control/warren.exe");
        report["binarySha256"] = json!("synthetic-hash");
        report["taskName"] = json!("warren-0123456789abcdef");
        report["events"] = json!([{"gate":"explicit_start", "pid":12345}]);
        checkpoint(&mut report, &path, &phase).unwrap();
    }
    // Exit without destructors or any final receipt write. No Windows APIs run.
    std::process::exit(75);
}

#[test]
fn receipt_survives_abrupt_exit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scheduler.json");
    let mut run_ids = Vec::new();
    for phase in ["initializing", "before_abnormal_exit"] {
        std::fs::write(
            &path,
            br#"{"runId":"stale","status":"PARTIAL","schedulerStatus":"PASS"}"#,
        )
        .unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "receipt_crash_child", "--ignored", "--nocapture"])
            .env("WARREN_RECEIPT_TEST_PATH", &path)
            .env("WARREN_RECEIPT_TEST_PHASE", phase)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(75));
        let report: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(report["status"], "BLOCKED");
        assert_eq!(report["schedulerStatus"], "BLOCKED");
        assert_eq!(report["freshLogon"]["status"], "BLOCKED");
        assert_eq!(report["phase"], phase);
        assert_ne!(report["runId"], "stale");
        if phase == "before_abnormal_exit" {
            assert_eq!(report["taskName"], "warren-0123456789abcdef");
            assert_eq!(report["events"][0]["pid"], 12345);
            assert_eq!(report["fixtureExe"], "synthetic-receipt-control/warren.exe");
        }
        run_ids.push(report["runId"].clone());
    }
    assert_ne!(run_ids[0], run_ids[1]);
}
