//! `warren install`: start the node daemon at login, as a launchd agent on
//! macOS or a systemd user service on Linux.
//!
//! The target directory can be overridden (`--dir`, or `WARREN_LAUNCHD_DIR` /
//! `WARREN_SYSTEMD_DIR`). When it is overridden the service manager is never
//! invoked, which is how the tests exercise this code without touching the
//! real `~/Library/LaunchAgents` or `~/.config/systemd`.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

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
        Flavor::Launchd => format!("dev.warren.node{}", suffix(opts)),
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
        "[Unit]\nDescription=warren node (private links between your machines)\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={} up\n{env}Restart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n",
        systemd_quote(&opts.exe.to_string_lossy())
    )
}

fn file_path(opts: &InstallOptions, dir: &Path) -> PathBuf {
    match opts.flavor {
        Flavor::Launchd => dir.join(format!("{}.plist", label(opts))),
        Flavor::Systemd => dir.join(format!("{}.service", label(opts))),
    }
}

fn run(cmd: &mut Command, log: &mut Vec<String>) -> Result<()> {
    log.push(format!("{cmd:?}"));
    let st = cmd.status().with_context(|| format!("running {cmd:?}"))?;
    if !st.success() {
        bail!("{cmd:?} failed with {st}");
    }
    Ok(())
}

fn uid() -> Result<String> {
    use std::os::unix::fs::MetadataExt;
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(std::fs::metadata(home)?.uid().to_string())
}

/// Write the service definition and (unless overridden) load it.
pub fn install(opts: &InstallOptions) -> Result<InstallReport> {
    let overridden = opts.dir.is_some();
    let dir = match &opts.dir {
        Some(d) => d.clone(),
        None => default_dir(opts.flavor)?,
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    crate::fsutil::ensure_private_dir(&opts.warren_home.join("logs"))?;
    let path = file_path(opts, &dir);
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
    let mut started = false;
    if opts.start && !overridden {
        match opts.flavor {
            Flavor::Launchd => {
                let domain = format!("gui/{}", uid()?);
                // Reload if already present; ignore "not loaded" errors.
                let _ = Command::new("launchctl")
                    .args(["bootout", &domain])
                    .arg(&path)
                    .status();
                run(
                    Command::new("launchctl")
                        .args(["bootstrap", &domain])
                        .arg(&path),
                    &mut commands,
                )?;
            }
            Flavor::Systemd => {
                run(
                    Command::new("systemctl").args(["--user", "daemon-reload"]),
                    &mut commands,
                )?;
                run(
                    Command::new("systemctl")
                        .args(["--user", "enable", "--now"])
                        .arg(format!("{}.service", label(opts))),
                    &mut commands,
                )?;
            }
        }
        started = true;
    }
    Ok(InstallReport {
        path,
        label: label(opts),
        started,
        commands,
    })
}

/// Remove the service definition (stopping it unless overridden).
pub fn uninstall(opts: &InstallOptions) -> Result<InstallReport> {
    let overridden = opts.dir.is_some();
    let dir = match &opts.dir {
        Some(d) => d.clone(),
        None => default_dir(opts.flavor)?,
    };
    let path = file_path(opts, &dir);
    let mut commands = Vec::new();
    if !overridden {
        match opts.flavor {
            Flavor::Launchd => {
                let domain = format!("gui/{}", uid()?);
                commands.push(format!("launchctl bootout {domain} {}", path.display()));
                let _ = Command::new("launchctl")
                    .args(["bootout", &domain])
                    .arg(&path)
                    .status();
            }
            Flavor::Systemd => {
                let unit = format!("{}.service", label(opts));
                commands.push(format!("systemctl --user disable --now {unit}"));
                let _ = Command::new("systemctl")
                    .args(["--user", "disable", "--now", &unit])
                    .status();
            }
        }
    }
    if path.exists() {
        std::fs::remove_file(&path)?;
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
        assert!(r.label.starts_with("dev.warren.node."));
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

    #[test]
    fn default_dirs() {
        let d = default_dir(Flavor::Launchd).unwrap();
        assert!(d.ends_with("Library/LaunchAgents"));
        let s = default_dir(Flavor::Systemd).unwrap();
        assert!(s.ends_with("systemd/user"));
    }
}
