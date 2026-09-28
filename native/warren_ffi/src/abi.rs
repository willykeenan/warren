use std::{
    mem::{align_of, size_of},
    ptr,
};
pub type Status = i32;
pub const OK: Status = 0;
pub const EOF: Status = 1;
pub const INVALID_ARGUMENT: Status = -1;
pub const INVALID_HANDLE: Status = -2;
pub const BAD_STATE: Status = -3;
pub const BUSY: Status = -4;
pub const LIMIT: Status = -5;
pub const CANCELLED: Status = -6;
pub const DEADLINE: Status = -7;
pub const NOT_CONNECTED: Status = -8;
pub const PIN_REJECTED: Status = -9;
pub const PEER_REFUSED: Status = -10;
pub const AUTH_FAILED: Status = -11;
pub const STORAGE_UNAVAILABLE: Status = -12;
pub const ALREADY_ENROLLED: Status = -13;
pub const TRANSPORT: Status = -14;
pub const INTERNAL: Status = -15;
pub const STOPPED: u32 = 0;
pub const STARTING: u32 = 1;
pub const RUNNING: u32 = 2;
pub const STOPPING: u32 = 3;
pub const FAULTED: u32 = 4;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Bytes {
    pub ptr: *const u8,
    pub len: u32,
}
#[repr(C)]
pub struct Config {
    pub struct_size: u32,
    pub abi_version: u32,
    pub storage_root: Bytes,
    pub reserved: [u32; 4],
}
#[repr(C)]
pub struct Join {
    pub struct_size: u32,
    pub has_relay_certificate_pin: u32,
    pub relay_https: Bytes,
    pub invite: Bytes,
    pub node_name: Bytes,
    pub relay_certificate_sha256: [u8; 32],
}
#[repr(C)]
pub struct PublicIdentity {
    pub struct_size: u32,
    pub name_len: u32,
    pub name: [u8; 32],
    pub noise_static_public_key: [u8; 32],
    pub signing_public_key: [u8; 32],
    pub relay_len: u32,
    pub relay_https: [u8; 2048],
}
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct ResultV1 {
    pub struct_size: u32,
    pub flags: u32,
    pub count: u32,
    pub reserved: u32,
    pub value: u64,
}
pub fn valid_ptr<T>(p: *const T) -> bool {
    !p.is_null() && (p as usize) % align_of::<T>() == 0
}
pub unsafe fn result<'a>(p: *mut ResultV1) -> Result<&'a mut ResultV1, Status> {
    if !valid_ptr(p) {
        return Err(INVALID_ARGUMENT);
    }
    let size = (*p).struct_size;
    ptr::write(
        p,
        ResultV1 {
            struct_size: size,
            ..Default::default()
        },
    );
    if size as usize != size_of::<ResultV1>() {
        return Err(INVALID_ARGUMENT);
    }
    Ok(&mut *p)
}
pub unsafe fn text(bytes: Bytes, max: usize) -> Result<String, Status> {
    if bytes.len == 0
        || bytes.len as usize > max
        || bytes.ptr.is_null()
        || (bytes.ptr as usize)
            .checked_add(bytes.len as usize)
            .is_none()
    {
        return Err(INVALID_ARGUMENT);
    }
    let b = std::slice::from_raw_parts(bytes.ptr, bytes.len as usize);
    if b.contains(&0) {
        return Err(INVALID_ARGUMENT);
    }
    std::str::from_utf8(b)
        .map(str::to_owned)
        .map_err(|_| INVALID_ARGUMENT)
}
pub unsafe fn key(p: *const u8) -> Result<[u8; 32], Status> {
    if p.is_null() || (p as usize).checked_add(32).is_none() {
        return Err(INVALID_ARGUMENT);
    }
    let mut k = [0; 32];
    ptr::copy_nonoverlapping(p, k.as_mut_ptr(), 32);
    Ok(k)
}
pub fn name(s: &str) -> Result<(), Status> {
    if warren::valid_name(s) {
        Ok(())
    } else {
        Err(INVALID_ARGUMENT)
    }
}
pub fn relay(s: &str) -> Result<(), Status> {
    if !s.starts_with("https://")
        || s.contains(['@', '?', '#', '\\'])
        || s.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(INVALID_ARGUMENT);
    }
    warren::net::RelayUrl::parse(s)
        .map(|_| ())
        .map_err(|_| INVALID_ARGUMENT)
}
pub struct Secret(pub Vec<u8>);
impl Drop for Secret {
    fn drop(&mut self) {
        clear(&mut self.0)
    }
}
pub fn clear(b: &mut [u8]) {
    for v in b {
        unsafe { ptr::write_volatile(v, 0) }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
