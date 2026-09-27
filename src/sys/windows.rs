//! The Win32 calls warren needs that have no safe std or tokio API: the
//! current account's SID, reading and applying security descriptors on open
//! handles, creating the control pipe with a security descriptor, and
//! detaching from the console.
//!
//! This is the only module in the crate that may use `unsafe` (a test in
//! `tests/network_audit.rs` enforces that). Each call is wrapped in a small
//! safe function, memory the system allocates is freed by a guard, and every
//! decision about *what* to apply or accept is made by the safe, portable
//! [`super::sddl`] module on the text form.

#![allow(unsafe_code)]

use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use std::sync::OnceLock;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    GetTokenInformation, TokenIntegrityLevel, TokenOwner, TokenUser, ACL,
    DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SE_DACL_PROTECTED, TOKEN_INFORMATION_CLASS, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::System::Console::{
    FreeConsole, GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED,
    ERROR_PIPE_BUSY, ERROR_SHARING_VIOLATION,
};
pub use windows_sys::Win32::Storage::FileSystem::{
    FILE_APPEND_DATA, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, READ_CONTROL, SECURITY_IDENTIFICATION, WRITE_DAC, WRITE_OWNER,
};
pub use windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP;

/// Memory the system allocated with `LocalAlloc`, freed on drop.
struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a Win32 call documented to
            // allocate it with LocalAlloc, and it is freed exactly once.
            unsafe { LocalFree(self.0) };
        }
    }
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

fn check(ok: windows_sys::core::BOOL) -> io::Result<()> {
    if ok == 0 {
        Err(last_error())
    } else {
        Ok(())
    }
}

fn win32(code: u32) -> io::Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Copy a NUL-terminated wide string the system returned.
///
/// # Safety
///
/// `p` must point to a readable, NUL-terminated UTF-16 string.
unsafe fn from_wide(p: *const u16) -> String {
    let mut len = 0;
    // SAFETY: the caller guarantees a terminating NUL within the allocation.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the `len` units before the NUL are initialized and readable.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

/// The text form (`S-1-5-...`) of a SID.
///
/// # Safety
///
/// `sid` must point to a valid SID for the duration of the call.
unsafe fn sid_string(sid: PSID) -> io::Result<String> {
    let mut s: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` is valid (caller); on success `s` receives a string
    // allocated with LocalAlloc, which the guard frees.
    check(unsafe { ConvertSidToStringSidW(sid, &mut s) })?;
    let _free = Local(s.cast());
    // SAFETY: the call returned a NUL-terminated string.
    Ok(unsafe { from_wide(s) })
}

/// The user or default-owner SID of this process's token.
fn token_sid(class: TOKEN_INFORMATION_CLASS) -> io::Result<String> {
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no
    // closing; on success `raw` receives a new token handle.
    check(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) })?;
    // SAFETY: `raw` is an open handle that nothing else owns.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut len = 0u32;
    // SAFETY: a size query: with a null buffer and length 0 the call only
    // writes the needed size to `len` (and fails with a "buffer too small"
    // error, which is expected).
    unsafe { GetTokenInformation(token.as_raw_handle(), class, ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(last_error());
    }
    // u64 elements: 8-byte alignment for TOKEN_USER / TOKEN_OWNER /
    // TOKEN_MANDATORY_LABEL (the latter begins with the same SID_AND_ATTRIBUTES
    // member as TOKEN_USER).
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` is writable for at least `len` bytes.
    check(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            buf.as_mut_ptr().cast(),
            len,
            &mut len,
        )
    })?;
    // SAFETY: on success the buffer starts with the requested structure,
    // suitably aligned; its SID pointer points into the same buffer, which
    // lives until the end of this function.
    let sid = unsafe {
        if class != TokenOwner {
            (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid
        } else {
            (*buf.as_ptr().cast::<TOKEN_OWNER>()).Owner
        }
    };
    // SAFETY: `sid` points into `buf`, still alive.
    unsafe { sid_string(sid) }
}

/// The SID of the account this process runs as.
pub fn current_user_sid() -> io::Result<String> {
    static SID: OnceLock<String> = OnceLock::new();
    if let Some(s) = SID.get() {
        return Ok(s.clone());
    }
    let s = token_sid(TokenUser)?;
    Ok(SID.get_or_init(|| s).clone())
}

/// The SID new objects of this process are owned by: the user, or
/// BUILTIN\Administrators in an elevated process.
pub fn default_owner_sid() -> io::Result<String> {
    static SID: OnceLock<String> = OnceLock::new();
    if let Some(s) = SID.get() {
        return Ok(s.clone());
    }
    let s = token_sid(TokenOwner)?;
    Ok(SID.get_or_init(|| s).clone())
}

pub fn current_integrity_sid() -> io::Result<String> {
    token_sid(TokenIntegrityLevel)
}

/// What kind of object a handle refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    /// A file or directory.
    File,
    /// A kernel object such as a named pipe.
    Kernel,
}

impl Object {
    fn se_type(self) -> SE_OBJECT_TYPE {
        match self {
            Object::File => SE_FILE_OBJECT,
            Object::Kernel => SE_KERNEL_OBJECT,
        }
    }
}

/// The owner and DACL of an open object, as SDDL. The handle needs
/// READ_CONTROL access.
pub fn security_sddl(h: &impl AsRawHandle, kind: Object) -> io::Result<String> {
    let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    security_sddl_with(h, kind, info)
}

/// Mandatory labels can be queried with READ_CONTROL, without requesting the
/// audit SACL privilege. Keep this separate from the DACL classifier.
pub fn integrity_sddl(h: &impl AsRawHandle, kind: Object) -> io::Result<String> {
    security_sddl_with(h, kind, LABEL_SECURITY_INFORMATION)
}

fn security_sddl_with(h: &impl AsRawHandle, kind: Object, info: u32) -> io::Result<String> {
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the handle is open while `h` is borrowed; only the whole
    // descriptor is requested (the optional part pointers are null); on
    // success it is allocated with LocalAlloc and freed by the guard.
    win32(unsafe {
        GetSecurityInfo(
            h.as_raw_handle(),
            kind.se_type(),
            info,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sd,
        )
    })?;
    let _sd = Local(sd);
    let mut s: *mut u16 = ptr::null_mut();
    // SAFETY: `sd` is the valid descriptor returned above; on success `s`
    // receives a LocalAlloc'ed string, freed by the guard.
    check(unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            info,
            &mut s,
            ptr::null_mut(),
        )
    })?;
    let _s = Local(s.cast());
    // SAFETY: the call returned a NUL-terminated string.
    Ok(unsafe { from_wide(s) })
}

/// The owner SID of an open object. The handle needs READ_CONTROL access.
pub fn owner_sid(h: &impl AsRawHandle, kind: Object) -> io::Result<String> {
    let mut owner: PSID = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: as in `security_sddl`; `owner` points into `sd`.
    win32(unsafe {
        GetSecurityInfo(
            h.as_raw_handle(),
            kind.se_type(),
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sd,
        )
    })?;
    let _sd = Local(sd);
    if owner.is_null() {
        return Err(io::Error::other("the object has no owner"));
    }
    // SAFETY: `owner` points into `sd`, alive until the guard drops.
    unsafe { sid_string(owner) }
}

/// A security descriptor built from SDDL (self-relative, LocalAlloc'ed).
pub struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is immutable memory owned by this value; the system
// only ever reads it.
unsafe impl Send for SecurityDescriptor {}
// SAFETY: as above; shared references only read it.
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> io::Result<SecurityDescriptor> {
        let w = wide(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `w` is NUL-terminated; on success `sd` receives a
        // LocalAlloc'ed descriptor that this value owns and frees.
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        })?;
        Ok(SecurityDescriptor(sd))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        drop(Local(self.0));
    }
}

/// Set the owner (if the SDDL names one) and the DACL of an open file or
/// directory, protected from inheritance if the SDDL says `P`. The handle
/// needs WRITE_DAC access, and WRITE_OWNER to set the owner. For a
/// directory, Windows also updates the inherited entries of what is inside.
pub fn apply_sddl(h: &impl AsRawHandle, sddl: &str) -> io::Result<()> {
    let sd = SecurityDescriptor::from_sddl(sddl)?;
    let mut owner: PSID = ptr::null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `sd.0` is a valid descriptor; the out pointers point into it
    // and are used only while `sd` is alive.
    unsafe {
        check(GetSecurityDescriptorOwner(sd.0, &mut owner, &mut defaulted))?;
        check(GetSecurityDescriptorDacl(
            sd.0,
            &mut present,
            &mut dacl,
            &mut defaulted,
        ))?;
        check(GetSecurityDescriptorControl(
            sd.0,
            &mut control,
            &mut revision,
        ))?;
    }
    let mut info = 0;
    if !owner.is_null() {
        info |= OWNER_SECURITY_INFORMATION;
    }
    if present != 0 {
        info |= DACL_SECURITY_INFORMATION;
        info |= if control & SE_DACL_PROTECTED != 0 {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
    }
    // SAFETY: the handle is open while `h` is borrowed; `owner` and `dacl`
    // point into `sd`, which outlives the call.
    win32(unsafe {
        SetSecurityInfo(
            h.as_raw_handle(),
            SE_FILE_OBJECT,
            info,
            owner,
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    })
}

/// Create a named pipe instance whose object gets the security descriptor
/// `sd` (it applies when the first instance creates the pipe).
pub fn create_pipe(
    opts: &ServerOptions,
    name: &str,
    sd: &SecurityDescriptor,
) -> io::Result<NamedPipeServer> {
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    // SAFETY: `sa` is a valid SECURITY_ATTRIBUTES whose descriptor outlives
    // the call (the system copies it into the new object).
    unsafe {
        opts.create_with_security_attributes_raw(
            name,
            (&mut sa as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    }
}

/// Detach from the console (for the login task): a console window that only
/// this process uses closes. Later writes to stdout and stderr are discarded.
pub fn free_console() {
    // SAFETY: no arguments; failure (no console attached) is harmless.
    unsafe { FreeConsole() };
}

/// Send Ctrl+Break to a process group created with CREATE_NEW_PROCESS_GROUP
/// that shares this process's console (used by tests to stop a child
/// gracefully).
#[doc(hidden)]
pub fn send_ctrl_break(process_group: u32) -> io::Result<()> {
    // SAFETY: plain values; the call has no memory arguments.
    check(unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, process_group) })
}

/// Create an exclusive file with its private descriptor already attached.
pub fn create_private_file(
    path: &std::path::Path,
    sd: &SecurityDescriptor,
    append: bool,
) -> io::Result<std::fs::File> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_NEW, DELETE, FILE_ATTRIBUTE_NORMAL,
    };
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let access = READ_CONTROL
        | WRITE_DAC
        | WRITE_OWNER
        | DELETE
        | if append {
            FILE_APPEND_DATA
        } else {
            FILE_GENERIC_WRITE
        };
    // SAFETY: terminated name and valid descriptor outlive CreateFileW; the
    // returned handle is transferred exactly once into File.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ,
            &sa,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    Ok(unsafe { std::fs::File::from_raw_handle(raw) })
}

pub fn file_links(file: &std::fs::File) -> io::Result<u32> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file remains open and info is a valid writable output.
    check(unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) })?;
    Ok(info.nNumberOfLinks)
}

/// Atomic replacement through the source handle; the caller retains pins for
/// the entire destination ancestry. No attacker-controlled source path lookup.
pub fn replace_file(file: &std::fs::File, destination: &std::path::Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfo, SetFileInformationByHandle, FILE_RENAME_INFO,
    };
    // FileNameLength excludes the terminator, but the Win32 path conversion
    // still requires a NUL-terminated FileName. Do not rely on allocation
    // padding: for some name lengths there is none.
    let name: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let bytes = offset + name.len() * 2;
    let mut buffer = vec![
        0u64;
        bytes
            .max(std::mem::size_of::<FILE_RENAME_INFO>())
            .div_ceil(8)
    ];
    // SAFETY: the allocation has structure alignment and space for the full
    // variable-length UTF-16 name. The system reads it only during this call.
    unsafe {
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        (*info).Anonymous.ReplaceIfExists = true;
        (*info).RootDirectory = ptr::null_mut();
        (*info).FileNameLength = ((name.len() - 1) * 2) as u32;
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name.len(),
        );
        check(SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            info.cast(),
            bytes as u32,
        ))
    }
}

pub fn delete_file(file: &std::fs::File) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: a valid initialized structure and live DELETE-capable handle.
    check(unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of_val(&info) as u32,
        )
    })
}

pub fn create_private_dir(path: &std::path::Path, sd: &SecurityDescriptor) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    // SAFETY: the name and descriptor remain valid until creation finishes.
    check(unsafe { CreateDirectoryW(name.as_ptr(), &sa) })
}
