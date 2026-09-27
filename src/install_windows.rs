//! Per-user Task Scheduler integration. Directory overrides never run schtasks.
use anyhow::{bail, Context, Result};
use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    TaskScheduler,
}
impl Flavor {
    pub fn current() -> Result<Self> {
        Ok(Self::TaskScheduler)
    }
}
#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub flavor: Flavor,
    pub exe: PathBuf,
    pub warren_home: PathBuf,
    pub custom_home: bool,
    pub dir: Option<PathBuf>,
    pub start: bool,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct InstallReport {
    pub path: PathBuf,
    pub label: String,
    pub started: bool,
    pub commands: Vec<String>,
}
pub fn label(opts: &InstallOptions) -> Result<String> {
    let home = std::fs::canonicalize(&opts.warren_home)
        .context("resolving Task Scheduler home identity")?;
    let mut key = current_sid()?.into_bytes();
    key.push(0);
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        for unit in home.as_os_str().encode_wide() {
            key.extend_from_slice(&unit.to_le_bytes());
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        key.extend_from_slice(home.as_os_str().as_bytes());
    }
    Ok(format!("warren-{}", &crate::crypto::sha256_hex(&key)[..16]))
}

fn registration_label(opts: &InstallOptions, dir: &Path) -> Result<String> {
    if let Some(label) = crate::fsutil::read_json::<String>(&dir.join("login-task-name.json"))? {
        anyhow::ensure!(
            label.starts_with("warren-")
                && label.len() == 23
                && label[7..].bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid saved task name"
        );
        return Ok(label);
    }
    // Old candidates did not save their actual task name. Do not guess an
    // alias and create duplicates or delete an unrelated registration.
    anyhow::ensure!(!dir.join("login-task.xml").exists(),
        "legacy task registration has no saved task name; remove the old warren task in Task Scheduler and its login-task.xml before reinstalling");
    label(opts)
}

pub fn default_dir(_: Flavor) -> Result<PathBuf> {
    crate::node::default_home()
}
pub fn env_dir(_: Flavor) -> Option<PathBuf> {
    std::env::var_os("WARREN_TASK_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}
fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
/// MSVCRT command-line quoting, including trailing backslashes.
pub fn quote_arg(s: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for c in s.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        if c == '"' {
            out.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
        } else {
            out.extend(std::iter::repeat_n('\\', slashes));
        }
        slashes = 0;
        out.push(c);
    }
    out.extend(std::iter::repeat_n('\\', slashes * 2));
    out.push('"');
    out
}
pub fn task_xml(opts: &InstallOptions, sid: &str) -> Vec<u8> {
    let args = xml(&format!(
        "up --background --home {}",
        quote_arg(&opts.warren_home.to_string_lossy())
    ));
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{sid}</UserId></LogonTrigger></Triggers>
<Principals><Principal id="Author"><UserId>{sid}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure></Settings>
<Actions Context="Author"><Exec><Command>{exe}</Command><Arguments>{args}</Arguments><WorkingDirectory>{home}</WorkingDirectory></Exec></Actions>
</Task>"#,
        sid = xml(sid),
        exe = xml(&opts.exe.to_string_lossy()),
        home = xml(&opts.warren_home.to_string_lossy())
    );
    [
        vec![0xff, 0xfe],
        body.encode_utf16().flat_map(u16::to_le_bytes).collect(),
    ]
    .concat()
}
#[derive(Debug, Clone, Copy)]
pub enum Tool {
    Schtasks,
}
pub type Runner<'a> = dyn FnMut(Tool, &[OsString]) -> io::Result<ExitStatus> + 'a;
fn run_system(_: Tool, args: &[OsString]) -> io::Result<ExitStatus> {
    Command::new("schtasks")
        .args(args)
        .output()
        .map(|o| o.status)
}
fn run(runner: &mut Runner, a: &[&std::ffi::OsStr], log: &mut Vec<String>) -> Result<()> {
    let args: Vec<_> = a.iter().map(|s| s.to_os_string()).collect();
    log.push(format!(
        "schtasks {}",
        args.iter()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    ));
    let st = runner(Tool::Schtasks, &args).context("running schtasks")?;
    if !st.success() {
        bail!("Task Scheduler command failed ({st}); check this user's Task Scheduler policy");
    }
    Ok(())
}
#[cfg(windows)]
fn current_sid() -> Result<String> {
    Ok(crate::sys::windows::current_user_sid()?)
}
#[cfg(all(test, unix))]
fn current_sid() -> Result<String> {
    Ok("S-1-5-21-123-456-789-1001".into())
}

fn target(opts: &InstallOptions) -> &Path {
    opts.dir.as_deref().unwrap_or(&opts.warren_home)
}
pub fn install(opts: &InstallOptions) -> Result<InstallReport> {
    install_with(opts, target(opts), opts.dir.is_none(), &mut run_system)
}
pub fn start_registered(opts: &InstallOptions) -> Result<InstallReport> {
    let dir = target(opts);
    let label = registration_label(opts, dir)?;
    let mut commands = Vec::new();
    run(
        &mut run_system,
        &["/Run".as_ref(), "/TN".as_ref(), label.as_ref()],
        &mut commands,
    )?;
    Ok(InstallReport {
        path: dir.join("login-task.xml"),
        label,
        started: true,
        commands,
    })
}
pub fn install_with(
    opts: &InstallOptions,
    dir: &Path,
    manage: bool,
    runner: &mut Runner,
) -> Result<InstallReport> {
    crate::fsutil::ensure_private_dir(&opts.warren_home)?;
    crate::fsutil::ensure_private_dir(dir)?;
    let label = registration_label(opts, dir)?;
    let path = dir.join("login-task.xml");
    let existed = path.exists();
    crate::fsutil::write_private(&path, &task_xml(opts, &current_sid()?))?;
    crate::fsutil::write_json(&dir.join("login-task-name.json"), &label)?;
    let mut commands = Vec::new();
    if manage {
        if let Err(e) = run(
            runner,
            &[
                "/Create".as_ref(),
                "/TN".as_ref(),
                label.as_ref(),
                "/XML".as_ref(),
                path.as_os_str(),
                "/F".as_ref(),
            ],
            &mut commands,
        ) {
            if !existed {
                let _ = std::fs::remove_file(&path);
            }
            return Err(e);
        }
        if opts.start {
            let _ = run(
                runner,
                &["/End".as_ref(), "/TN".as_ref(), label.as_ref()],
                &mut commands,
            );
            run(
                runner,
                &["/Run".as_ref(), "/TN".as_ref(), label.as_ref()],
                &mut commands,
            )?;
        }
    }
    Ok(InstallReport {
        path,
        label,
        started: manage && opts.start,
        commands,
    })
}
pub fn uninstall(opts: &InstallOptions) -> Result<InstallReport> {
    uninstall_with(opts, target(opts), opts.dir.is_none(), &mut run_system)
}
pub fn uninstall_with(
    opts: &InstallOptions,
    dir: &Path,
    manage: bool,
    runner: &mut Runner,
) -> Result<InstallReport> {
    let path = dir.join("login-task.xml");
    if !path.exists() && !dir.join("login-task-name.json").exists() {
        return Ok(InstallReport {
            path,
            label: String::new(),
            started: false,
            commands: Vec::new(),
        });
    }
    let label = registration_label(opts, dir)?;
    let mut commands = Vec::new();
    if manage {
        let _ = run(
            runner,
            &["/End".as_ref(), "/TN".as_ref(), label.as_ref()],
            &mut commands,
        );
        // Without our local registration record, an already removed installation is
        // a no-op. Otherwise deletion must succeed; localized error text is not parsed.
        if path.exists() {
            run(
                runner,
                &[
                    "/Delete".as_ref(),
                    "/TN".as_ref(),
                    label.as_ref(),
                    "/F".as_ref(),
                ],
                &mut commands,
            )?;
        }
    }
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    match std::fs::remove_file(dir.join("login-task-name.json")) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(InstallReport {
        path,
        label,
        started: false,
        commands,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn status(code: i32) -> ExitStatus {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            ExitStatus::from_raw(code << 8)
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::ExitStatusExt;
            ExitStatus::from_raw(code as u32)
        }
    }
    #[test]
    fn stable_labels_and_saved_registration_cleanup() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        crate::fsutil::ensure_private_dir(&home).unwrap();
        let opts = InstallOptions {
            flavor: Flavor::TaskScheduler,
            exe: "warren.exe".into(),
            warren_home: home.clone(),
            custom_home: true,
            dir: None,
            start: false,
        };
        let mut alias = opts.clone();
        alias.warren_home = home.join(".");
        assert_eq!(label(&opts).unwrap(), label(&alias).unwrap());
        #[cfg(windows)]
        {
            alias.warren_home = PathBuf::from(home.to_str().unwrap().replace('\\', "/"));
            assert_eq!(label(&opts).unwrap(), label(&alias).unwrap());
        }
        let report = install_with(&opts, &home, true, &mut |_, _| Ok(status(0))).unwrap();
        let removed = uninstall_with(&alias, &home, true, &mut |_, args| {
            assert!(args.iter().any(|a| a == report.label.as_str()));
            Ok(status(0))
        })
        .unwrap();
        assert_eq!(report.label, removed.label);
        assert!(!home.join("login-task-name.json").exists());
        crate::fsutil::write_private(&home.join("login-task.xml"), b"legacy").unwrap();
        let mut called = false;
        assert!(install_with(&opts, &home, true, &mut |_, _| {
            called = true;
            Ok(status(0))
        })
        .is_err());
        assert!(
            !called,
            "legacy migration must not guess the old registration"
        );
    }

    #[test]
    fn task_restarts_only_on_failure_with_a_schema_valid_count() {
        let opts = InstallOptions {
            flavor: Flavor::TaskScheduler,
            exe: "C:/warren.exe".into(),
            warren_home: "C:/home".into(),
            custom_home: true,
            dir: None,
            start: false,
        };
        let raw = task_xml(&opts, "S-1-5-21-1-2-3-1001");
        let body = String::from_utf16(
            &raw[2..]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let restart = body
            .split("<RestartOnFailure>")
            .nth(1)
            .unwrap()
            .split("</RestartOnFailure>")
            .next()
            .unwrap();
        let count: u8 = restart
            .split("<Count>")
            .nth(1)
            .unwrap()
            .split("</Count>")
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(count > 0);
        assert_eq!(body.matches("<LogonTrigger>").count(), 1);
        assert!(!body.contains("<TimeTrigger>") && !body.contains("<Repetition>"));
        assert!(body.contains("<MultipleInstancesPolicy>IgnoreNew"));
    }

    #[test]
    fn registration_no_start_restart_and_failure() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("task");
        let mut opts = InstallOptions {
            flavor: Flavor::TaskScheduler,
            exe: PathBuf::from("C:/tools/warren.exe"),
            warren_home: t.path().join("home"),
            custom_home: true,
            dir: None,
            start: false,
        };
        let mut calls = Vec::new();
        let report = install_with(&opts, &dir, true, &mut |_, args| {
            calls.push(args[0].to_string_lossy().into_owned());
            Ok(status(0))
        })
        .unwrap();
        assert!(!report.started);
        assert_eq!(calls, ["/Create"]);
        opts.start = true;
        calls.clear();
        let report = install_with(&opts, &dir, true, &mut |_, args| {
            calls.push(args[0].to_string_lossy().into_owned());
            Ok(status(0))
        })
        .unwrap();
        assert!(report.started);
        assert_eq!(calls, ["/Create", "/End", "/Run"]);
        assert!(uninstall_with(&opts, &dir, true, &mut |_, _| Ok(status(1))).is_err());
        assert!(
            report.path.exists(),
            "failed delete must preserve registration record"
        );
        uninstall_with(&opts, &dir, true, &mut |_, _| Ok(status(0))).unwrap();
        assert!(!report.path.exists());
        assert!(install_with(&opts, &dir, true, &mut |_, _| Ok(status(1))).is_err());
        assert!(
            !report.path.exists(),
            "failed first registration removes new XML"
        );
    }
    #[test]
    fn quoted_arguments_preserve_trailing_slashes() {
        assert_eq!(quote_arg(r"C:\my tools\"), "\"C:\\my tools\\\\\"");
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
    }
    #[test]
    fn directory_override_has_no_service_effects() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("task");
        let opts = InstallOptions {
            flavor: Flavor::TaskScheduler,
            exe: PathBuf::from(r"C:\my tools\warren.exe"),
            warren_home: t.path().join("home & x"),
            custom_home: true,
            dir: Some(dir.clone()),
            start: true,
        };
        let report = install(&opts).unwrap();
        assert!(!report.started);
        assert!(report.commands.is_empty());
        let b = std::fs::read(&report.path).unwrap();
        assert_eq!(&b[..2], &[255, 254]);
        let body = String::from_utf16(
            &b[2..]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(body.contains("home &amp; x"));
        assert!(body.contains("<ExecutionTimeLimit>PT0S"));
        assert!(body.contains("LeastPrivilege"));
        uninstall(&opts).unwrap();
        uninstall(&opts).unwrap();
        assert!(!report.path.exists());
    }
}
