//! Private, local-only daemon control transport.
use super::{control::ControlError, NodePaths};
use std::io;
#[cfg(unix)]
pub type Client = tokio::net::UnixStream;
#[cfg(unix)]
pub type Server = tokio::net::UnixStream;
#[cfg(unix)]
pub struct Listener(tokio::net::UnixListener);
#[cfg(unix)]
pub async fn connect(paths: &NodePaths) -> Result<Client, ControlError> {
    match tokio::net::UnixStream::connect(paths.checked_socket()?).await {
        Ok(s) => Ok(s),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Err(ControlError::NotRunning)
        }
        Err(e) => Err(e.into()),
    }
}
#[cfg(unix)]
pub async fn bind(paths: &NodePaths) -> anyhow::Result<Listener> {
    use std::os::unix::fs::PermissionsExt;
    let sock = paths.checked_socket()?;
    if sock.exists() {
        if tokio::net::UnixStream::connect(&sock).await.is_ok() {
            anyhow::bail!("warren is already running for {}", paths.home.display());
        }
        std::fs::remove_file(&sock)?;
    }
    let l = tokio::net::UnixListener::bind(&sock)?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    Ok(Listener(l))
}
#[cfg(unix)]
impl Listener {
    pub async fn accept(&mut self) -> io::Result<Server> {
        self.0.accept().await.map(|(s, _)| s)
    }
}
pub fn cleanup(paths: &NodePaths) {
    #[cfg(unix)]
    let _ = std::fs::remove_file(paths.socket());
    #[cfg(windows)]
    let _ = paths;
}
#[cfg(windows)]
pub use windows::*;
#[cfg(windows)]
mod windows {
    use super::*;
    use crate::sys::{sddl, windows as win};
    use std::os::windows::ffi::OsStrExt;
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
    };
    pub type Client = NamedPipeClient;
    pub type Server = NamedPipeServer;
    pub struct Listener {
        next: NamedPipeServer,
        name: String,
        sd: win::SecurityDescriptor,
    }
    pub fn pipe_name(paths: &NodePaths) -> io::Result<String> {
        let home = std::fs::canonicalize(&paths.home)?;
        let mut key = win::current_user_sid()?.into_bytes();
        key.push(0);
        for unit in home.as_os_str().encode_wide() {
            key.extend_from_slice(&unit.to_le_bytes());
        }
        Ok(format!(
            r"\\.\pipe\warren-{}",
            &crate::crypto::sha256_hex(&key)[..24]
        ))
    }
    pub async fn connect(paths: &NodePaths) -> Result<Client, ControlError> {
        let name = pipe_name(paths).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                ControlError::NotRunning
            } else {
                e.into()
            }
        })?;
        let until = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            // Identification prevents a squatting server impersonating the CLI.
            match ClientOptions::new()
                .security_qos_flags(win::SECURITY_IDENTIFICATION)
                .open(&name)
            {
                Ok(s) => {
                    if win::owner_sid(&s, win::Object::Kernel)? != win::current_user_sid()? {
                        return Err(ControlError::Untrusted);
                    }
                    if !sddl::trusted_pipe_integrity(
                        &win::integrity_sddl(&s, win::Object::Kernel)?,
                        &win::current_integrity_sid()?,
                    ) {
                        return Err(ControlError::Untrusted);
                    }
                    return Ok(s);
                }
                Err(e)
                    if e.raw_os_error() == Some(win::ERROR_PIPE_BUSY as i32)
                        && tokio::time::Instant::now() < until =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Err(ControlError::NotRunning)
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
    pub async fn bind(paths: &NodePaths) -> anyhow::Result<Listener> {
        let name = pipe_name(paths)?;
        let integrity = win::current_integrity_sid()?;
        anyhow::ensure!(
            sddl::integrity_level(&integrity).is_some_and(|l| l >= 8192),
            "warren requires medium or higher integrity"
        );
        let sd = win::SecurityDescriptor::from_sddl(&sddl::control_pipe_at_integrity(
            &win::current_user_sid()?,
            &integrity,
        ))?;
        let next = win::create_pipe(
            ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(true)
                .pipe_mode(PipeMode::Byte),
            &name,
            &sd,
        )?;
        Ok(Listener { next, name, sd })
    }
    impl Listener {
        pub async fn accept(&mut self) -> io::Result<Server> {
            self.next.connect().await?;
            // Keep a listening instance alive before transferring the connected one.
            let next = win::create_pipe(
                ServerOptions::new()
                    .reject_remote_clients(true)
                    .pipe_mode(PipeMode::Byte),
                &self.name,
                &self.sd,
            )?;
            Ok(std::mem::replace(&mut self.next, next))
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::sys::{sddl, windows as win};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn private_pipe_long_home_and_first_instance() {
        let tmp = tempfile::tempdir().unwrap();
        let mut home = tmp.path().to_path_buf();
        for _ in 0..6 {
            home.push("long-component-abcdefghijklmnopqrstuvwxyz0123456789");
        }
        let paths = NodePaths::new(home);
        paths.ensure().unwrap();
        let mut listener = bind(&paths).await.unwrap();
        assert!(
            bind(&paths).await.is_err(),
            "a second daemon must not share the first pipe"
        );
        let task = tokio::spawn(async move {
            let mut s = listener.accept().await.unwrap();
            s.write_all(b"ok").await.unwrap();
            // Keep the listening handle alive until the connected instance is consumed.
            let mut b = [0];
            s.read_exact(&mut b).await.unwrap();
        });
        let mut client = connect(&paths).await.unwrap();
        let me = win::current_user_sid().unwrap();
        assert_eq!(win::owner_sid(&client, win::Object::Kernel).unwrap(), me);
        let sd = win::security_sddl(&client, win::Object::Kernel).unwrap();
        let a = sddl::assess(&sd, &me, &win::default_owner_sid().unwrap()).unwrap();
        assert!(a.is_private() && a.protected, "{sd}");
        let mut bytes = [0; 2];
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ok");
        client.write_all(&[1]).await.unwrap();
        drop(client);
        task.await.unwrap();
        let _listener = bind(&paths).await.unwrap();
    }
}
