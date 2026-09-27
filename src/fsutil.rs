//! Private file handling: directories are 0700, files 0600 (on Windows: owned
//! by the user, with a protected DACL that grants only the user and
//! LocalSystem), and writes are atomic.

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;

/// Create `dir` (and parents) and make it private: mode 0700, or on Windows
/// a protected DACL for the user and LocalSystem only. Tightening an existing
/// directory that others could read is logged as a warning: `WARREN_HOME`
/// and the relay's state directory should be dedicated directories, not,
/// say, the home directory itself.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    if let Some(old) = make_private_dir(dir)? {
        #[cfg(unix)]
        tracing::warn!(
            "{} was open to other users ({old}); warren keeps private keys in it and \
             set it to 0700. Use a dedicated directory for warren",
            dir.display()
        );
        #[cfg(windows)]
        tracing::warn!(
            "{} was open to other accounts ({old}); warren keeps private keys in it and \
             made it private to your account. Use a dedicated directory for warren",
            dir.display()
        );
    }
    Ok(())
}

/// Make an existing file that holds a private key private again, with a
/// warning if others could read it (for example a file copied or moved in
/// from elsewhere, which on Windows keeps its old permissions). A missing
/// file is not an error.
pub fn ensure_private_file(path: &Path) -> Result<()> {
    if let Some(old) = make_private_file(path)? {
        tracing::warn!(
            "{} was readable by other users ({old}); it holds a private key and warren \
             made it private. If others could have copied it, replace the key",
            path.display()
        );
    }
    Ok(())
}

fn temp_path(path: &Path) -> Result<PathBuf> {
    let dir = path.parent().context("path has no parent")?;
    let name = path
        .file_name()
        .context("path has no file name")?
        .to_string_lossy();
    Ok(dir.join(format!(".{name}.tmp{}", std::process::id())))
}

/// Serialize `value` as pretty JSON into a private file.
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut v = serde_json::to_vec_pretty(value)?;
    v.push(b'\n');
    write_private(path, &v)
}

/// Read JSON from `path`; `Ok(None)` if it does not exist.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match fs::read(path) {
        Ok(b) => Ok(Some(
            serde_json::from_slice(&b).with_context(|| format!("parsing {}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    /// Mode for private files.
    pub const FILE_MODE: u32 = 0o600;
    /// Mode for private directories.
    pub const DIR_MODE: u32 = 0o700;

    /// [`ensure_private_dir`] without the warning: describes (`mode 0755`)
    /// how an existing directory that was open to group or others was set.
    pub fn make_private_dir(dir: &Path) -> Result<Option<String>> {
        let existed = dir.is_dir();
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let mode = fs::metadata(dir)?.permissions().mode() & 0o777;
        if mode == DIR_MODE {
            return Ok(None);
        }
        fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))
            .with_context(|| format!("setting permissions on {}", dir.display()))?;
        Ok((existed && mode & 0o077 != 0).then(|| format!("mode {mode:04o}")))
    }

    /// [`ensure_private_file`] without the warning.
    pub fn make_private_file(path: &Path) -> Result<Option<String>> {
        let mode = match fs::metadata(path) {
            Ok(m) => m.permissions().mode() & 0o777,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        if mode & 0o077 == 0 {
            return Ok(None);
        }
        fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE))
            .with_context(|| format!("setting permissions on {}", path.display()))?;
        Ok(Some(format!("mode {mode:04o}")))
    }

    /// Atomically replace `path` with `data`, mode 0600.
    pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
        let tmp = temp_path(path)?;
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(FILE_MODE)
                .open(&tmp)
                .with_context(|| format!("writing {}", tmp.display()))?;
            // The mode passed to open() is subject to umask and ignored for
            // existing files; set it explicitly.
            f.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }

    /// Create an empty private file if missing and force mode 0600.
    pub fn touch_private(path: &Path) -> Result<()> {
        let f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(FILE_MODE)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        f.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;
        Ok(())
    }

    /// Mode bits of a path (for tests and diagnostics).
    pub fn mode_of(path: &Path) -> Result<u32> {
        Ok(fs::metadata(path)?.permissions().mode() & 0o777)
    }

    /// True if neither group nor others have any access to `path`.
    pub fn is_private(path: &Path) -> Result<bool> {
        Ok(mode_of(path)? & 0o077 == 0)
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::sys::sddl;
    use crate::sys::windows as win;
    use std::io::{self, Write};
    use std::os::windows::fs::OpenOptionsExt;

    fn user() -> Result<String> {
        win::current_user_sid().context("reading this account's SID")
    }

    fn default_owner() -> Result<String> {
        win::default_owner_sid().context("reading this account's default owner")
    }

    /// Explain errors from volumes without access control lists (FAT, exFAT,
    /// some network shares), where warren cannot keep keys private.
    fn acl_error(e: io::Error, path: &Path) -> anyhow::Error {
        let unsupported = matches!(
            e.raw_os_error().map(|c| c as u32),
            Some(win::ERROR_NOT_SUPPORTED) | Some(win::ERROR_INVALID_FUNCTION)
        );
        if unsupported {
            anyhow::anyhow!(
                "{}: this volume does not support permissions, so warren cannot keep its keys \
                 private there; put WARREN_HOME (and the relay's --state) on an NTFS or ReFS \
                 volume",
                path.display()
            )
        } else {
            anyhow::Error::new(e).context(format!("permissions of {}", path.display()))
        }
    }

    /// Open a file or directory to read (and with `extra`, change) its
    /// security descriptor. Handles avoid path length limits and races.
    fn open_meta(path: &Path, extra: u32) -> io::Result<fs::File> {
        fs::OpenOptions::new()
            .access_mode(win::READ_CONTROL | extra)
            .custom_flags(win::FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
    }

    fn assess(f: &fs::File, path: &Path) -> Result<sddl::Assessment> {
        let text = win::security_sddl(f, win::Object::File).map_err(|e| acl_error(e, path))?;
        sddl::assess(&text, &user()?, &default_owner()?)
            .with_context(|| format!("permissions of {}", path.display()))
    }

    /// Apply `sddl` to `path` through a handle opened for it, then check the
    /// result (a volume that silently ignores permissions is an error).
    fn apply(path: &Path, sddl_text: &str, want_protected: bool) -> Result<()> {
        let f = open_meta(path, win::WRITE_DAC | win::WRITE_OWNER)
            .with_context(|| format!("setting permissions on {}", path.display()))?;
        win::apply_sddl(&f, sddl_text).map_err(|e| acl_error(e, path))?;
        let a = assess(&f, path)?;
        if !a.is_private() || (want_protected && !a.protected) {
            return Err(acl_error(
                io::Error::from_raw_os_error(win::ERROR_NOT_SUPPORTED as i32),
                path,
            ));
        }
        Ok(())
    }

    /// [`ensure_private_dir`] without the warning: describes (`access for BU`)
    /// who else had access to an existing directory. Removing only the
    /// Administrators group (which every folder in a profile grants) is not
    /// reported.
    pub fn make_private_dir(dir: &Path) -> Result<Option<String>> {
        let existed = dir.is_dir();
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let a = {
            let f = open_meta(dir, 0).with_context(|| format!("opening {}", dir.display()))?;
            assess(&f, dir)?
        };
        if a.is_private() && a.protected {
            return Ok(None);
        }
        apply(dir, &sddl::private_dir(&user()?), true)?;
        Ok((existed && a.exposed()).then(|| a.describe()))
    }

    /// [`ensure_private_file`] without the warning.
    pub fn make_private_file(path: &Path) -> Result<Option<String>> {
        let a = match open_meta(path, 0) {
            Ok(f) => assess(&f, path)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
        };
        if a.is_private() {
            return Ok(None);
        }
        apply(path, &sddl::private_file(&user()?), false)?;
        Ok(a.exposed().then(|| a.describe()))
    }

    /// Access for writing a private file: the data, plus changing its
    /// owner and DACL before anything is written.
    const WRITE_ACCESS: u32 =
        win::FILE_GENERIC_WRITE | win::READ_CONTROL | win::WRITE_DAC | win::WRITE_OWNER;

    /// Atomically replace `path` with `data`, readable only by this account
    /// (and LocalSystem).
    pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
        let tmp = temp_path(path)?;
        let written = (|| -> Result<()> {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .access_mode(WRITE_ACCESS)
                .open(&tmp)
                .with_context(|| format!("writing {}", tmp.display()))?;
            // Before any data: the file already inherits the private
            // directory's entries, and now gets its own protected DACL.
            win::apply_sddl(&f, &sddl::private_file(&user()?)).map_err(|e| acl_error(e, &tmp))?;
            f.write_all(data)?;
            f.sync_all()?;
            Ok(())
        })();
        if let Err(e) = written.and_then(|()| rename_retrying(&tmp, path)) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        Ok(())
    }

    /// Replace `to` with `from`. Antivirus scanners and the search indexer
    /// open files briefly without sharing, which makes the rename fail with a
    /// sharing violation or "access denied": retry for up to about half a
    /// second.
    fn rename_retrying(from: &Path, to: &Path) -> Result<()> {
        let mut delay = std::time::Duration::from_millis(10);
        let mut attempt = 0;
        loop {
            match fs::rename(from, to) {
                Ok(()) => return Ok(()),
                Err(e)
                    if attempt < 9
                        && matches!(
                            e.raw_os_error().map(|c| c as u32),
                            Some(win::ERROR_SHARING_VIOLATION) | Some(win::ERROR_ACCESS_DENIED)
                        ) =>
                {
                    attempt += 1;
                    std::thread::sleep(delay);
                    delay = (delay * 2).min(std::time::Duration::from_millis(100));
                }
                Err(e) => {
                    return Err(e).with_context(|| format!("replacing {}", to.display()));
                }
            }
        }
    }

    /// Create an empty private file if missing and make it private.
    pub fn touch_private(path: &Path) -> Result<()> {
        let f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .access_mode(WRITE_ACCESS)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        win::apply_sddl(&f, &sddl::private_file(&user()?)).map_err(|e| acl_error(e, path))
    }

    /// True if only this account and LocalSystem have access to `path`, and
    /// it is owned by one of them (or by the account new files are created
    /// as, which is BUILTIN\Administrators in an elevated process).
    pub fn is_private(path: &Path) -> Result<bool> {
        let f = open_meta(path, 0).with_context(|| format!("opening {}", path.display()))?;
        Ok(assess(&f, path)?.is_private())
    }

    /// The owner and DACL of `path` as SDDL (for tests and diagnostics).
    pub fn security_of(path: &Path) -> Result<String> {
        let f = open_meta(path, 0).with_context(|| format!("opening {}", path.display()))?;
        win::security_sddl(&f, win::Object::File).map_err(|e| acl_error(e, path))
    }

    /// Replace the security descriptor of `path` (for tests that need a
    /// loosened directory or file).
    #[doc(hidden)]
    pub fn set_security_for_test(path: &Path, sddl_text: &str) -> Result<()> {
        let f = open_meta(path, win::WRITE_DAC | win::WRITE_OWNER)
            .with_context(|| format!("opening {}", path.display()))?;
        win::apply_sddl(&f, sddl_text).map_err(|e| acl_error(e, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_files_and_dirs() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("home");
        ensure_private_dir(&d).unwrap();
        assert!(is_private(&d).unwrap());
        let f = d.join("x.json");
        write_json(&f, &serde_json::json!({"a": 1})).unwrap();
        assert!(is_private(&f).unwrap());
        let v: serde_json::Value = read_json(&f).unwrap().unwrap();
        assert_eq!(v["a"], 1);
        write_json(&f, &serde_json::json!({"a": 2})).unwrap();
        assert!(is_private(&f).unwrap());
        let v: serde_json::Value = read_json(&f).unwrap().unwrap();
        assert_eq!(v["a"], 2);
        assert!(read_json::<serde_json::Value>(&d.join("missing"))
            .unwrap()
            .is_none());
        let g = d.join("db");
        touch_private(&g).unwrap();
        assert!(is_private(&g).unwrap());
        // No temporary files are left behind.
        let names: Vec<String> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().all(|n| !n.contains(".tmp")), "{names:?}");
        assert_eq!(make_private_file(&d.join("missing")).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn private_modes() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("home");
        ensure_private_dir(&d).unwrap();
        assert_eq!(mode_of(&d).unwrap(), 0o700);
        // loosen and re-ensure
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&d).unwrap();
        assert_eq!(mode_of(&d).unwrap(), 0o700);
        let f = d.join("x.json");
        write_json(&f, &serde_json::json!({"a": 1})).unwrap();
        assert_eq!(mode_of(&f).unwrap(), 0o600);
        let v: serde_json::Value = read_json(&f).unwrap().unwrap();
        assert_eq!(v["a"], 1);
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
        write_json(&f, &serde_json::json!({"a": 2})).unwrap();
        assert_eq!(mode_of(&f).unwrap(), 0o600);
        assert!(read_json::<serde_json::Value>(&d.join("missing"))
            .unwrap()
            .is_none());
        let g = d.join("db");
        touch_private(&g).unwrap();
        assert_eq!(mode_of(&g).unwrap(), 0o600);
        // A key file loosened by hand is made private again, and reported.
        fs::set_permissions(&g, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_private(&g).unwrap());
        assert_eq!(make_private_file(&g).unwrap(), Some("mode 0644".into()));
        assert_eq!(mode_of(&g).unwrap(), 0o600);
        assert_eq!(make_private_file(&g).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn tightening_a_shared_directory_is_reported() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let new = t.path().join("new");
        assert_eq!(make_private_dir(&new).unwrap(), None);
        assert_eq!(mode_of(&new).unwrap(), 0o700);
        let shared = t.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(make_private_dir(&shared).unwrap(), Some("mode 0755".into()));
        assert_eq!(mode_of(&shared).unwrap(), 0o700);
        assert_eq!(make_private_dir(&shared).unwrap(), None);
        // Only ever more restrictive: 0500 becomes 0700 without a report.
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o500)).unwrap();
        assert_eq!(make_private_dir(&shared).unwrap(), None);
        assert_eq!(mode_of(&shared).unwrap(), 0o700);
    }

    #[cfg(windows)]
    #[test]
    fn windows_descriptors() {
        use crate::sys::sddl;
        let me = crate::sys::windows::current_user_sid().unwrap();
        let t = tempfile::tempdir().unwrap();
        // A new directory: owned by the user, protected, user + SYSTEM,
        // inherited by what is created inside.
        let new = t.path().join("new");
        assert_eq!(make_private_dir(&new).unwrap(), None);
        let d = sddl::parse(&security_of(&new).unwrap()).unwrap();
        assert!(
            d.owner.as_deref().is_some_and(|o| sddl::is_account(o, &me)),
            "{d:?}"
        );
        let Some(sddl::Dacl::List { protected, aces }) = d.dacl else {
            panic!("{d:?}")
        };
        assert!(protected);
        assert_eq!(aces.len(), 2, "{aces:?}");
        assert!(aces
            .iter()
            .all(|a| a.flags.contains("OI") && a.flags.contains("CI")));
        // A directory everyone may use is reported and tightened.
        let shared = t.path().join("shared");
        fs::create_dir(&shared).unwrap();
        set_security_for_test(&shared, "D:(A;OICI;FA;;;WD)").unwrap();
        assert!(!is_private(&shared).unwrap());
        let r = make_private_dir(&shared).unwrap();
        assert!(r.as_deref().is_some_and(|r| r.contains("WD")), "{r:?}");
        assert!(is_private(&shared).unwrap());
        assert_eq!(make_private_dir(&shared).unwrap(), None);
        // A folder that only also grants Administrators (like any folder in
        // a profile) is tightened without a report.
        let admins = t.path().join("admins");
        fs::create_dir(&admins).unwrap();
        set_security_for_test(
            &admins,
            &format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"),
        )
        .unwrap();
        assert_eq!(make_private_dir(&admins).unwrap(), None);
        assert!(is_private(&admins).unwrap());
        // Files: explicit protected DACL, owner the user.
        let f = new.join("x.json");
        write_json(&f, &serde_json::json!({"a": 1})).unwrap();
        let d = sddl::parse(&security_of(&f).unwrap()).unwrap();
        assert!(matches!(
            d.dacl,
            Some(sddl::Dacl::List {
                protected: true,
                ..
            })
        ));
        // A key file moved in with a permissive DACL is tightened, with a report.
        let moved = new.join("moved.key");
        fs::write(&moved, b"k").unwrap();
        set_security_for_test(&moved, "D:(A;;FA;;;WD)").unwrap();
        assert!(!is_private(&moved).unwrap());
        assert!(make_private_file(&moved).unwrap().is_some());
        assert!(is_private(&moved).unwrap());
        assert_eq!(make_private_file(&moved).unwrap(), None);
    }

    #[cfg(windows)]
    #[test]
    fn replace_waits_for_a_briefly_locked_file() {
        use std::os::windows::fs::OpenOptionsExt;
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("home");
        ensure_private_dir(&d).unwrap();
        let f = d.join("x.json");
        write_json(&f, &1).unwrap();
        // Another program holds the file open without allowing deletion
        // (as a virus scanner might) for a moment.
        let held = fs::OpenOptions::new()
            .read(true)
            .share_mode(crate::sys::windows::FILE_SHARE_READ)
            .open(&f)
            .unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(held);
        });
        write_json(&f, &2).unwrap();
        release.join().unwrap();
        assert_eq!(read_json::<i32>(&f).unwrap(), Some(2));
    }
}
