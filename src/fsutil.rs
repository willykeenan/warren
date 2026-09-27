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

/// Create `dir` (and parents) and force its mode to 0700.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let meta = fs::metadata(dir)?;
    if meta.permissions().mode() & 0o777 != DIR_MODE {
        fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))
            .with_context(|| format!("setting permissions on {}", dir.display()))?;
    }
    Ok(())
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
}
