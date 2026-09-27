//! `warren install`: start the node daemon at login, as a launchd agent on
//! macOS or a systemd user service on Linux.
//!
//! The target directory can be overridden (`--dir`, or `WARREN_LAUNCHD_DIR` /
//! `WARREN_SYSTEMD_DIR`). When it is overridden the service manager is never
//! invoked, which is how the tests exercise this code without touching the
//! real `~/Library/LaunchAgents` or `~/.config/systemd`; unit tests replace the
//! service manager with a recorder.

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

/// Service manager flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Launchd,
    Systemd,
}

impl Flavor {
    pub fn current() -> Result<Flavor> {
        match std::env::consts::OS {
            "macos" => Ok(Flavor::Launchd),
            "linux" => Ok(Flavor::Systemd),
            other => bail!("`warren install` supports macOS and Linux, not {other}"),
        }
    }
}

/// Inputs for generating and installing the service definition.
#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub flavor: Flavor,
    /// Absolute path of the `warren` binary.
    pub exe: PathBuf,
    /// The node home the service should use.
    pub warren_home: PathBuf,
    /// True if `warren_home` is not the default `~/.warren` (then it is passed
    /// explicitly and the service name gets a suffix).
    pub custom_home: bool,
    /// Directory override; if set, the service manager is not invoked.
    pub dir: Option<PathBuf>,
    /// Load/start the service after writing it (ignored when `dir` is set).
    pub start: bool,
}

/// What `install` did.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InstallReport {
    pub path: PathBuf,
    pub label: String,
    pub started: bool,
    pub commands: Vec<String>,
}

fn suffix(opts: &InstallOptions) -> String {
    if opts.custom_home {
        let h = crate::crypto::sha256_hex(opts.warren_home.to_string_lossy().as_bytes());
        format!(".{}", &h[..8])
    } else {
        String::new()
    }
}

/// launchd label / systemd unit base name.
pub fn label(opts: &InstallOptions) -> String {
    match opts.flavor {
        Flavor::Launchd => format!("io.github.willykeenan.warren.node{}", suffix(opts)),
        Flavor::Systemd => format!("warren{}", suffix(opts).replace('.', "-")),
    }
}

/// Default directory for the service definition.
pub fn default_dir(flavor: Flavor) -> Result<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?);
    Ok(match flavor {
        Flavor::Launchd => home.join("Library/LaunchAgents"),
        Flavor::Systemd => match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            Some(x) => PathBuf::from(x).join("systemd/user"),
            None => home.join(".config/systemd/user"),
        },
    })
}

/// Directory override from the environment.
pub fn env_dir(flavor: Flavor) -> Option<PathBuf> {
    let var = match flavor {
        Flavor::Launchd => "WARREN_LAUNCHD_DIR",
        Flavor::Systemd => "WARREN_SYSTEMD_DIR",
    };
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// launchd property list.
pub fn launchd_plist(opts: &InstallOptions) -> String {
    let exe = xml_escape(&opts.exe.to_string_lossy());
    let log = xml_escape(&opts.warren_home.join("logs/warren.log").to_string_lossy());
    let env = if opts.custom_home {
        format!(
            "    <key>EnvironmentVariables</key>\n    <dict>\n        <key>WARREN_HOME</key>\n        <string>{}</string>\n    </dict>\n",
            xml_escape(&opts.warren_home.to_string_lossy())
        )
    } else {
        String::new()
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>up</string>
    </array>
{env}    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#,
        label = xml_escape(&label(opts)),
    )
}

fn systemd_quote(s: &str) -> String {
    format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    )
}

/// systemd user unit.
pub fn systemd_unit(opts: &InstallOptions) -> String {
    let env = if opts.custom_home {
        format!(
            "Environment={}\n",
            systemd_quote(&format!(
                "WARREN_HOME={}",
                opts.warren_home.to_string_lossy()
            ))
        )
    } else {
        String::new()
    };
    format!(
        "[Unit]\nDescription=warren node (private links between your machines)\n\n[Service]\nType=simple\nExecStart={} up\n{env}Restart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n",
        systemd_quote(&opts.exe.to_string_lossy())
    )
}

fn file_path(opts: &InstallOptions, dir: &Path) -> PathBuf {
    match opts.flavor {
        Flavor::Launchd => dir.join(format!("{}.plist", label(opts))),
        Flavor::Systemd => dir.join(format!("{}.service", label(opts))),
    }
}

/// A service manager `install` and `uninstall` may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Launchctl,
    Systemctl,
}

impl Tool {
    fn name(self) -> &'static str {
        match self {
            Tool::Launchctl => "launchctl",
            Tool::Systemctl => "systemctl",
        }
    }

    fn command(self) -> Command {
        match self {
            Tool::Launchctl => Command::new("launchctl"),
            Tool::Systemctl => Command::new("systemctl"),
        }
    }
}

/// Runs one service-manager command and reports how it exited.
pub type Runner<'a> = dyn FnMut(Tool, &[OsString]) -> io::Result<ExitStatus> + 'a;

fn run_system(tool: Tool, args: &[OsString]) -> io::Result<ExitStatus> {
    tool.command().args(args).status()
}

fn args(v: &[&dyn AsRef<std::ffi::OsStr>]) -> Vec<OsString> {
    v.iter().map(|a| a.as_ref().to_os_string()).collect()
}

/// Run a command, record it, and fail unless it succeeded.
fn run(runner: &mut Runner, tool: Tool, a: Vec<OsString>, log: &mut Vec<String>) -> Result<()> {
    let shown = std::iter::once(tool.name().to_string())
        .chain(a.iter().map(|x| x.to_string_lossy().into_owned()))
        .collect::<Vec<_>>()
        .join(" ");
    log.push(shown.clone());
    let st = runner(tool, &a).map_err(|e| anyhow!("running `{shown}`: {e}"))?;
    if !st.success() {
        bail!("`{shown}` failed ({st})");
    }
    Ok(())
}

fn uid() -> Result<String> {
    use std::os::unix::fs::MetadataExt;
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(std::fs::metadata(home)?.uid().to_string())
}

fn target_dir(opts: &InstallOptions) -> Result<PathBuf> {
    match &opts.dir {
        Some(d) => Ok(d.clone()),
        None => default_dir(opts.flavor),
    }
}

/// Write the service definition and (unless overridden) load it.
pub fn install(opts: &InstallOptions) -> Result<InstallReport> {
    let manage = opts.start && opts.dir.is_none();
    install_with(opts, &target_dir(opts)?, manage, &mut run_system)
}

/// [`install`] into `dir`, loading the service with `runner` if `manage`.
pub fn install_with(
    opts: &InstallOptions,
    dir: &Path,
    manage: bool,
    runner: &mut Runner,
) -> Result<InstallReport> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    crate::fsutil::ensure_private_dir(&opts.warren_home.join("logs"))?;
    let path = file_path(opts, dir);
    let existed = path.exists();
    let body = match opts.flavor {
        Flavor::Launchd => launchd_plist(opts),
        Flavor::Systemd => systemd_unit(opts),
    };
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    }
    let mut commands = Vec::new();
    if manage {
        let loaded = match opts.flavor {
            Flavor::Launchd => uid().and_then(|uid| {
                let domain = format!("gui/{uid}");
                // Unload a previous version first; "not loaded" is fine.
                let _ = run(
                    runner,
                    Tool::Launchctl,
                    args(&[&"bootout", &domain, &path]),
                    &mut commands,
                );
                run(
                    runner,
                    Tool::Launchctl,
                    args(&[&"bootstrap", &domain, &path]),
                    &mut commands,
                )
            }),
            Flavor::Systemd => {
                let unit = format!("{}.service", label(opts));
                let mut systemctl = |a: &[&str]| {
                    let mut v = args(&[&"--user"]);
                    v.extend(a.iter().map(OsString::from));
                    run(runner, Tool::Systemctl, v, &mut commands)
                };
                // `restart` also starts a stopped service, and replaces a
                // running one that still uses an older binary or unit.
                systemctl(&["daemon-reload"])
                    .and_then(|_| systemctl(&["enable", &unit]))
                    .and_then(|_| systemctl(&["restart", &unit]))
            }
        };
        if let Err(e) = loaded {
            let file = if existed {
                format!("{} was updated and kept", path.display())
            } else {
                let _ = std::fs::remove_file(&path);
                format!("{} was removed again", path.display())
            };
            let hint = match opts.flavor {
                Flavor::Launchd => {
                    "launchctl loads the agent into your GUI login session (gui/UID), which needs \
                     you to be logged in on the Mac. `warren install --no-start` writes the file \
                     without loading it; it then starts at your next login"
                }
                Flavor::Systemd => {
                    "systemctl --user needs your user's service manager: on a headless machine run \
                     `loginctl enable-linger $USER` and log in again, and check that \
                     XDG_RUNTIME_DIR is set (log in directly, not with su). Or run \
                     `warren install --no-start` and start `warren up` another way"
                }
            };
            bail!("{e:#}\n{file}.\n{hint}.");
        }
    }
    Ok(InstallReport {
        path,
        label: label(opts),
        started: manage,
        commands,
    })
}

/// Remove the service definition (stopping it unless overridden).
pub fn uninstall(opts: &InstallOptions) -> Result<InstallReport> {
    let manage = opts.dir.is_none();
    uninstall_with(opts, &target_dir(opts)?, manage, &mut run_system)
}

/// [`uninstall`] from `dir`, stopping the service with `runner` if `manage`.
pub fn uninstall_with(
    opts: &InstallOptions,
    dir: &Path,
    manage: bool,
    runner: &mut Runner,
) -> Result<InstallReport> {
    let path = file_path(opts, dir);
    let mut commands = Vec::new();
    let unit = format!("{}.service", label(opts));
    // Stopping fails harmlessly when the service is not loaded.
    if manage {
        match opts.flavor {
            Flavor::Launchd => {
                let domain = format!("gui/{}", uid()?);
                let _ = run(
                    runner,
                    Tool::Launchctl,
                    args(&[&"bootout", &domain, &path]),
                    &mut commands,
                );
            }
            Flavor::Systemd => {
                let _ = run(
                    runner,
                    Tool::Systemctl,
                    args(&[&"--user", &"disable", &"--now", &unit]),
                    &mut commands,
                );
            }
        }
    }
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    if manage && opts.flavor == Flavor::Systemd {
        // Forget the removed unit.
        let _ = run(
            runner,
            Tool::Systemctl,
            args(&[&"--user", &"daemon-reload"]),
            &mut commands,
        );
    }
    Ok(InstallReport {
        path,
        label: label(opts),
        started: false,
        commands,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(flavor: Flavor, dir: &Path, home: &Path, custom: bool) -> InstallOptions {
        InstallOptions {
            flavor,
            exe: PathBuf::from("/opt/my tools/warren"),
            warren_home: home.to_path_buf(),
            custom_home: custom,
            dir: Some(dir.to_path_buf()),
            start: true,
        }
    }

    #[test]
    fn launchd_written_to_override_dir_only() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("agents");
        let home = t.path().join("home & <x>");
        let o = opts(Flavor::Launchd, &dir, &home, true);
        let r = install(&o).unwrap();
        assert!(r.path.starts_with(&dir));
        assert!(
            !r.started,
            "service manager must not run for an overridden dir"
        );
        assert!(r.commands.is_empty());
        let s = std::fs::read_to_string(&r.path).unwrap();
        assert!(s.contains("<string>/opt/my tools/warren</string>"));
        assert!(s.contains("<string>up</string>"));
        assert!(s.contains("<key>WARREN_HOME</key>"));
        assert!(s.contains("home &amp; &lt;x&gt;"));
        // Crashes are restarted, a clean exit (`warren down`) is not.
        assert!(s.contains(
            "<key>KeepAlive</key>\n    <dict>\n        <key>SuccessfulExit</key>\n        <false/>"
        ));
        assert!(r.label.starts_with("io.github.willykeenan.warren.node."));
        uninstall(&o).unwrap();
        assert!(!r.path.exists());
    }

    #[test]
    fn systemd_unit_contents() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("units");
        let o = opts(Flavor::Systemd, &dir, t.path(), false);
        let r = install(&o).unwrap();
        assert_eq!(r.path, dir.join("warren.service"));
        let s = std::fs::read_to_string(&r.path).unwrap();
        assert!(s.contains("ExecStart=\"/opt/my tools/warren\" up"));
        assert!(s.contains("Restart=on-failure"));
        assert!(!s.contains("Restart=always"));
        assert!(s.contains("WantedBy=default.target"));
        assert!(!s.contains("WARREN_HOME"));
        let o2 = opts(Flavor::Systemd, &dir, &t.path().join("h%1"), true);
        let s2 = systemd_unit(&o2);
        assert!(s2.contains("Environment=\"WARREN_HOME="));
        assert!(s2.contains("h%%1"));
        assert!(label(&o2).starts_with("warren-"));
    }

    /// A service manager that records every command and fails the ones
    /// `fail` picks: `Some(None)` = the program is missing, `Some(Some(code))`
    /// = it exits with `code`.
    fn recorder<'a>(
        log: &'a mut Vec<String>,
        fail: impl Fn(&str) -> Option<Option<i32>> + 'a,
    ) -> impl FnMut(Tool, &[OsString]) -> io::Result<ExitStatus> + 'a {
        use std::os::unix::process::ExitStatusExt;
        move |tool, a| {
            let line = std::iter::once(tool.name().to_string())
                .chain(a.iter().map(|x| x.to_string_lossy().into_owned()))
                .collect::<Vec<_>>()
                .join(" ");
            log.push(line.clone());
            match fail(&line) {
                None => Ok(ExitStatus::from_raw(0)),
                Some(None) => Err(io::Error::from(io::ErrorKind::NotFound)),
                Some(Some(code)) => Ok(ExitStatus::from_raw(code << 8)),
            }
        }
    }

    #[test]
    fn systemd_install_enables_and_restarts() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("units");
        let o = opts(Flavor::Systemd, &dir, t.path(), false);
        let mut log = Vec::new();
        let r = install_with(&o, &dir, true, &mut recorder(&mut log, |_| None)).unwrap();
        assert!(r.started);
        let expected = [
            "systemctl --user daemon-reload",
            "systemctl --user enable warren.service",
            "systemctl --user restart warren.service",
        ];
        assert_eq!(log, expected);
        assert_eq!(r.commands, expected);
        let mut log = Vec::new();
        let u = uninstall_with(&o, &dir, true, &mut recorder(&mut log, |_| None)).unwrap();
        assert_eq!(
            log,
            [
                "systemctl --user disable --now warren.service",
                "systemctl --user daemon-reload"
            ]
        );
        assert!(!u.path.exists());
    }

    #[test]
    fn failed_systemctl_removes_a_new_unit_and_explains() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("units");
        let o = opts(Flavor::Systemd, &dir, t.path(), false);
        // No systemctl at all.
        let mut log = Vec::new();
        let e = install_with(&o, &dir, true, &mut recorder(&mut log, |_| Some(None)))
            .unwrap_err()
            .to_string();
        assert_eq!(log, ["systemctl --user daemon-reload"]);
        assert!(
            e.contains("running `systemctl --user daemon-reload`"),
            "{e}"
        );
        assert!(e.contains("was removed again"), "{e}");
        assert!(
            e.contains("loginctl enable-linger") && e.contains("--no-start"),
            "{e}"
        );
        assert!(!dir.join("warren.service").exists());
        // No user bus: `enable` fails. An existing unit is kept (updated).
        std::fs::write(dir.join("warren.service"), "old").unwrap();
        let mut log = Vec::new();
        let e = install_with(
            &o,
            &dir,
            true,
            &mut recorder(&mut log, |l| l.contains(" enable ").then_some(Some(1))),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("`systemctl --user enable warren.service` failed"),
            "{e}"
        );
        assert!(e.contains("was updated and kept"), "{e}");
        let unit = std::fs::read_to_string(dir.join("warren.service")).unwrap();
        assert!(unit.contains("ExecStart="));
    }

    #[test]
    fn launchd_install_reloads_and_cleans_up_on_failure() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("agents");
        let o = opts(Flavor::Launchd, &dir, t.path(), false);
        let plist = dir.join("io.github.willykeenan.warren.node.plist");
        let mut log = Vec::new();
        // `bootout` of a service that is not loaded fails; that is fine.
        let r = install_with(
            &o,
            &dir,
            true,
            &mut recorder(&mut log, |l| l.contains("bootout").then_some(Some(3))),
        )
        .unwrap();
        assert!(r.started);
        assert_eq!(log.len(), 2);
        assert!(log[0].starts_with("launchctl bootout gui/") && log[0].ends_with(".plist"));
        assert!(log[1].starts_with("launchctl bootstrap gui/"));
        std::fs::remove_file(&plist).unwrap();
        let mut log = Vec::new();
        let e = install_with(
            &o,
            &dir,
            true,
            &mut recorder(&mut log, |l| l.contains("bootstrap").then_some(Some(5))),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("was removed again") && e.contains("--no-start"),
            "{e}"
        );
        assert!(!plist.exists());
    }

    #[test]
    fn user_unit_has_no_system_only_dependencies() {
        let t = tempfile::tempdir().unwrap();
        let s = systemd_unit(&opts(Flavor::Systemd, t.path(), t.path(), false));
        // network-online.target exists only in the system manager.
        assert!(!s.contains("network-online"), "{s}");
    }

    #[test]
    fn default_dirs() {
        let d = default_dir(Flavor::Launchd).unwrap();
        assert!(d.ends_with("Library/LaunchAgents"));
        let s = default_dir(Flavor::Systemd).unwrap();
        assert!(s.ends_with("systemd/user"));
    }
}
