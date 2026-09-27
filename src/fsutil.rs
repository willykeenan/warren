//! Private file handling: directories are 0700, files 0600, writes are atomic.

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Mode for private files.
pub const FILE_MODE: u32 = 0o600;
/// Mode for private directories.
pub const DIR_MODE: u32 = 0o700;

/// Create `dir` (and parents) and force its mode to 0700. Tightening an
/// existing directory that others could read is logged as a warning:
/// `WARREN_HOME` and the relay's state directory should be dedicated
/// directories, not, say, the home directory itself.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    if let Some(old) = make_private_dir(dir)? {
        tracing::warn!(
            "{} was open to other users (mode {old:03o}); warren keeps private keys in it and \
             set it to 0700. Use a dedicated directory for warren",
            dir.display()
        );
    }
    Ok(())
}

/// [`ensure_private_dir`] without the warning: returns the previous mode of an
/// existing directory that was open to group or others.
pub fn make_private_dir(dir: &Path) -> Result<Option<u32>> {
    let existed = dir.is_dir();
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let mode = fs::metadata(dir)?.permissions().mode() & 0o777;
    if mode == DIR_MODE {
        return Ok(None);
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))
        .with_context(|| format!("setting permissions on {}", dir.display()))?;
    Ok((existed && mode & 0o077 != 0).then_some(mode))
}

/// Atomically replace `path` with `data`, mode 0600.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().context("path has no parent")?;
    let name = path
        .file_name()
        .context("path has no file name")?
        .to_string_lossy();
    let tmp = dir.join(format!(".{name}.tmp{}", std::process::id()));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_modes() {
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
    }

    #[test]
    fn tightening_a_shared_directory_is_reported() {
        let t = tempfile::tempdir().unwrap();
        let new = t.path().join("new");
        assert_eq!(make_private_dir(&new).unwrap(), None);
        assert_eq!(mode_of(&new).unwrap(), 0o700);
        let shared = t.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(make_private_dir(&shared).unwrap(), Some(0o755));
        assert_eq!(mode_of(&shared).unwrap(), 0o700);
        assert_eq!(make_private_dir(&shared).unwrap(), None);
        // Only ever more restrictive: 0500 becomes 0700 without a report.
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o500)).unwrap();
        assert_eq!(make_private_dir(&shared).unwrap(), None);
        assert_eq!(mode_of(&shared).unwrap(), 0o700);
    }
}
