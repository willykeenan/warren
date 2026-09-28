//! Operating-system specific pieces that do not belong to one feature.
//!
//! * [`sddl`]: Windows security descriptors as text, portable and tested
//!   everywhere.
//! * `windows` (Windows only): the one module allowed to use `unsafe`, for
//!   the Win32 security and console calls that have no safe API.

pub mod sddl;
#[cfg(windows)]
pub mod windows;

use std::future::Future;
use std::io;

/// Register for the requests to stop that a foreground process receives, and
/// return a future that completes on the first one.
///
/// Unix: SIGINT and SIGTERM. Windows: Ctrl+C, Ctrl+Break, and the console
/// window closing (which allows about five seconds before the process is
/// ended).
#[cfg(unix)]
pub fn shutdown_signal() -> io::Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    })
}

/// Register for the requests to stop that a foreground process receives, and
/// return a future that completes on the first one.
///
/// Unix: SIGINT and SIGTERM. Windows: Ctrl+C, Ctrl+Break, and the console
/// window closing (which allows about five seconds before the process is
/// ended).
#[cfg(windows)]
pub fn shutdown_signal() -> io::Result<impl Future<Output = ()>> {
    use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close};
    let mut c = ctrl_c()?;
    let mut b = ctrl_break()?;
    let mut close = ctrl_close()?;
    Ok(async move {
        tokio::select! {
            _ = c.recv() => {}
            _ = b.recv() => {}
            _ = close.recv() => {}
        }
    })
}
