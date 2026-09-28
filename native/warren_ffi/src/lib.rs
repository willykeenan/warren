//! Versioned, blocking C boundary. Call only from native background dispatch lanes.
//! Raw pointer validity/non-overlap remains the C caller's responsibility.
mod abi;
mod handles;
mod stream;
use abi::*;
pub use abi::{Bytes, Config, Join, PublicIdentity, ResultV1};
use handles::*;
use std::{
    future::Future,
    mem::size_of,
    path::PathBuf,
    ptr,
    sync::{Arc, Mutex},
    time::Duration,
};
use stream::Stream;
use tokio_util::sync::CancellationToken;
use warren::node::{
    daemon::OpenError,
    embedded::{self, EmbeddedClient, PublicIdentity as CoreIdentity},
    JoinError,
};
fn boundary(f: impl FnOnce() -> Result<Status, Status>) -> Status {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(v)) => v,
        Ok(Err(v)) => v,
        Err(_) => INTERNAL,
    }
}
// Every result-bearing call reports uncertainty after a contained internal panic.
unsafe fn result_boundary(
    out: *mut ResultV1,
    f: impl FnOnce(&mut Epilogue) -> Result<Status, Status>,
) -> Status {
    let mut epilogue = Epilogue::default();
    let status = boundary(|| f(&mut epilogue));
    if status == INTERNAL && valid_ptr(out) {
        (*out).flags |= 1;
    }
    status
}
fn millis(ms: u32, max: u32) -> Result<Duration, Status> {
    if ms == 0 || ms > max {
        Err(INVALID_ARGUMENT)
    } else {
        Ok(Duration::from_millis(ms as u64))
    }
}
fn rt() -> Result<&'static tokio::runtime::Runtime, Status> {
    if tokio::runtime::Handle::try_current().is_ok() {
        Err(BAD_STATE)
    } else {
        runtime()
    }
}
async fn bounded<T>(
    op: &Operation,
    time: Duration,
    f: impl Future<Output = Result<T, Status>>,
) -> Result<T, Status> {
    tokio::select! {biased;_=op.cancel.cancelled()=>Err(CANCELLED),r=tokio::time::timeout(time,f)=>r.map_err(|_|DEADLINE)?}
}
fn finish(call: &mut Call, out: &mut ResultV1, status: Status, effect: bool) -> Status {
    let status = call.finish(status);
    if status < 0 && effect {
        out.flags = 1
    }
    status
}
fn open_error(e: OpenError) -> Status {
    match e {
        OpenError::NotConnected => NOT_CONNECTED,
        OpenError::InvalidArgument => INVALID_ARGUMENT,
        OpenError::PinRejected => PIN_REJECTED,
        OpenError::StorageUnavailable => STORAGE_UNAVAILABLE,
        OpenError::KeyChanged { .. } => PIN_REJECTED,
        OpenError::Refused { .. } => PEER_REFUSED,
        OpenError::Handshake(..) => AUTH_FAILED,
        _ => TRANSPORT,
    }
}
fn clone_identity(i: &CoreIdentity) -> CoreIdentity {
    CoreIdentity {
        name: i.name.clone(),
        noise_static_public_key: i.noise_static_public_key,
        signing_public_key: i.signing_public_key,
        relay_https: i.relay_https.clone(),
    }
}
fn begin_cleanup(handle: u64, c: &Arc<Context>) -> Result<(), Status> {
    let mut s = lock(&c.inner);
    if !s.alive {
        return Err(INVALID_HANDLE);
    }
    if s.cleanup {
        return Ok(());
    }
    s.phase = STOPPING;
    s.cleanup = true;
    drop(s);
    for op in operations(handle) {
        op.cancel()
    }
    for (_, stream) in streams(handle, None) {
        stream.close()
    }
    let c = c.clone();
    runtime()?.spawn(async move {
        loop {
            let n = c.notify.notified();
            if {
                let state = lock(&c.inner);
                state.active == 0 && !state.starting
            } {
                break;
            }
            n.await;
        }
        for (id, stream) in streams(handle, None) {
            stream.close();
            stream.drain().await;
            let _ = lock(registry()).streams.remove(id);
        }
        let owned = lock(&c.inner).client.take();
        if let Some(client) = owned {
            match Arc::try_unwrap(client) {
                Ok(client) => client.shutdown().await,
                Err(client) => {
                    let mut s = lock(&c.inner);
                    s.client = Some(client);
                    s.cleanup = false;
                    s.faulted = true;
                    s.phase = FAULTED;
                    drop(s);
                    c.notify.notify_waiters();
                    return;
                }
            }
        }
        let mut s = lock(&c.inner);
        s.phase = if s.faulted { FAULTED } else { STOPPED };
        s.cleanup = false;
        drop(s);
        c.notify.notify_waiters();
    });
    Ok(())
}
#[no_mangle]
pub extern "C" fn wr_v1_abi_version() -> u32 {
    1
}
/// # Safety
/// All pointers must name valid, aligned full ABI objects or stated-length
/// buffers, remain borrowed until return, and not overlap another argument.
#[no_mangle]
pub unsafe extern "C" fn wr_v1_context_create(config: *const Config, out: *mut u64) -> Status {
    boundary(|| {
        if !valid_ptr(out) {
            return Err(INVALID_ARGUMENT);
        }
        *out = 0;
        if !valid_ptr(config) {
            return Err(INVALID_ARGUMENT);
        }
        let cfg = &*config;
        if cfg.struct_size as usize != size_of::<Config>()
            || cfg.abi_version != 1
            || cfg.reserved != [0; 4]
        {
            return Err(INVALID_ARGUMENT);
        }
        let path = PathBuf::from(text(cfg.storage_root, 1024)?);
        if !path.is_absolute() {
            return Err(INVALID_ARGUMENT);
        }
        let h = lock(registry())
            .contexts
            .insert(Arc::new(Context::new(path)))?;
        *out = h;
        Ok(OK)
    })
}
/// # Safety
/// All pointers must name valid, aligned full ABI objects or stated-length
/// buffers, remain borrowed until return, and not overlap another argument.
#[no_mangle]
pub unsafe extern "C" fn wr_v1_context_state(
    h: u64,
    state: *mut u32,
    connected: *mut u32,
) -> Status {
    boundary(|| {
        if !valid_ptr(state) || !valid_ptr(connected) {
            return Err(INVALID_ARGUMENT);
        }
        *state = FAULTED;
        *connected = 0;
        let c = context(h)?;
        let s = lock(&c.inner);
        if !s.alive {
            return Err(INVALID_HANDLE);
        }
        *state = s.phase;
        *connected = u32::from(s.client.as_ref().is_some_and(|c| c.is_connected()));
        Ok(OK)
    })
}
#[no_mangle]
pub extern "C" fn wr_v1_context_destroy(h: u64) -> Status {
    boundary(|| {
        let c = context(h)?;
        let mut s = lock(&c.inner);
        if !s.alive {
            return Err(INVALID_HANDLE);
        }
        if ![STOPPED, FAULTED].contains(&s.phase)
            || s.active != 0
            || s.calls != 0
            || s.client.is_some()
            || s.cleanup
        {
            return Err(BUSY);
        }
        let mut r = lock(registry());
        if r.operations.entries().iter().any(|(_, o)| o.context == h)
            || r.streams.entries().iter().any(|(_, v)| v.context == h)
        {
            return Err(BUSY);
        }
        s.alive = false;
        r.contexts.remove(h)?;
        Ok(OK)
    })
}
/// # Safety
/// All pointers must name valid, aligned full ABI objects or stated-length
/// buffers, remain borrowed until return, and not overlap another argument.
#[no_mangle]
pub unsafe extern "C" fn wr_v1_operation_create(h: u64, out: *mut u64) -> Status {
    boundary(|| {
        if !valid_ptr(out) {
            return Err(INVALID_ARGUMENT);
        }
        *out = 0;
        let c = context(h)?;
        #[cfg(test)]
        tests_hooks::operation_lookup(h);
        let s = lock(&c.inner);
        if !s.alive {
            return Err(INVALID_HANDLE);
        }
        if [STOPPING, FAULTED].contains(&s.phase) {
            return Err(BAD_STATE);
        }
        *out = lock(registry()).operations.insert(Arc::new(Operation {
            context: h,
            inner: Mutex::new(OpState {
                active_call: false,
                phase: 0,
                cancelled: false,
            }),
            cancel: CancellationToken::new(),
            peer: Mutex::new(None),
        }))?;
        Ok(OK)
    })
}
#[no_mangle]
pub extern "C" fn wr_v1_operation_cancel(h: u64) -> Status {
    boundary(|| {
        operation(h)?.cancel();
        Ok(OK)
    })
}
#[no_mangle]
pub extern "C" fn wr_v1_operation_release(h: u64) -> Status {
    boundary(|| {
        let op = operation(h)?;
        let state = lock(&op.inner);
        if state.phase != 2 || state.active_call {
            return Err(BUSY);
        }
        lock(registry()).operations.remove(h)?;
        drop(state);
        Ok(OK)
    })
}
/// # Safety
/// All pointers must name valid, aligned full ABI objects or stated-length
/// buffers, remain borrowed until return, and not overlap another argument.
#[no_mangle]
pub unsafe extern "C" fn wr_v1_identity_public(h: u64, out: *mut PublicIdentity) -> Status {
    boundary(|| {
        if !valid_ptr(out) {
            return Err(INVALID_ARGUMENT);
        }
        let size = (*out).struct_size;
        ptr::write_bytes(out, 0, 1);
        (*out).struct_size = size;
        if size as usize != size_of::<PublicIdentity>() {
            return Err(INVALID_ARGUMENT);
        }
        let c = context(h)?;
        let s = lock(&c.inner);
        if !s.alive {
            return Err(INVALID_HANDLE);
        }
        let i = s.identity.as_ref().ok_or(BAD_STATE)?;
        if i.name.len() > 32 || i.relay_https.len() > 2048 {
            return Err(INTERNAL);
        }
        (*out).name_len = i.name.len() as u32;
        (&mut (*out).name)[..i.name.len()].copy_from_slice(i.name.as_bytes());
        (*out).noise_static_public_key = i.noise_static_public_key;
        (*out).signing_public_key = i.signing_public_key;
        (*out).relay_len = i.relay_https.len() as u32;
        (&mut (*out).relay_https)[..i.relay_https.len()].copy_from_slice(i.relay_https.as_bytes());
        Ok(OK)
    })
}
/// # Safety
/// All pointers must name valid, aligned full ABI objects or stated-length
/// buffers, remain borrowed until return, and not overlap another argument.
#[no_mangle]
pub unsafe extern "C" fn wr_v1_join(
    h: u64,
    o: u64,
    input: *const Join,
    ms: u32,
    out: *mut ResultV1,
) -> Status {
    result_boundary(out, |epilogue| {
        let out = result(out)?;
        let time = millis(ms, 45000)?;
        let runtime = rt()?;
        if !valid_ptr(input) {
            return Err(INVALID_ARGUMENT);
        }
        let j = &*input;
        if j.struct_size as usize != size_of::<Join>() || j.has_relay_certificate_pin > 1 {
            return Err(INVALID_ARGUMENT);
        }
        let url = text(j.relay_https, 2048)?;
        relay(&url)?;
        let node = text(j.node_name, 32)?;
        name(&node)?;
        let invite = Secret(text(j.invite, 128)?.into_bytes());
        let pin = (j.has_relay_certificate_pin == 1).then_some(j.relay_certificate_sha256);
        let mut call = Call::begin(h, o, epilogue)?;
        let control = match Control::acquire(&call.context, STOPPED, true) {
            Ok(c) => c,
            Err(e) => return Ok(finish(&mut call, out, e, false)),
        };
        let res = runtime.block_on(bounded(&call.operation, time, async {
            let code = std::str::from_utf8(&invite.0).map_err(|_| INVALID_ARGUMENT)?;
            let i = embedded::join(&call.context.home, code, &url, Some(&node), pin)
                .await
                .map_err(|e| match e {
                    JoinError::AlreadyEnrolled(_) => ALREADY_ENROLLED,
                    JoinError::DaemonRunning(_) => BUSY,
                    JoinError::Usage(_) => INVALID_ARGUMENT,
                    JoinError::Refused { .. } => PEER_REFUSED,
                    JoinError::Other(_) => INTERNAL,
                })?;
            CoreIdentity::from_identity(&i).map_err(|_| STORAGE_UNAVAILABLE)
        }));
        let status = match res {
            Ok(i) => {
                lock(&call.context.inner).identity = Some(i);
                OK
            }
            Err(e) => e,
        };
        drop(control);
        Ok(finish(&mut call, out, status, true))
    })
}
/// # Safety
/// All pointers must name valid, aligned full ABI objects or stated-length
/// buffers, remain borrowed until return, and not overlap another argument.
#[no_mangle]
pub unsafe extern "C" fn wr_v1_start(h: u64, o: u64, ms: u32, out: *mut ResultV1) -> Status {
    result_boundary(out, |epilogue| {
        let out = result(out)?;
        let time = millis(ms, 30000)?;
        let runtime = rt()?;
        let mut call = Call::begin(h, o, epilogue)?;
        let control = match Control::acquire(&call.context, STOPPED, true) {
            Ok(c) => c,
            Err(e) => return Ok(finish(&mut call, out, e, false)),
        };
        {
            let mut state = lock(&call.context.inner);
            state.phase = STARTING;
            state.starting = true;
        }
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let owned_context = call.context.clone();
        let home = owned_context.home.clone();
        let handle = runtime.handle().clone();
        // A blocked filesystem cannot strand the C call or lose tentative ownership.
        // The owned driver survives deadline/cancel and cleanup waits for `starting`.
        runtime.spawn(async move {
            let started = tokio::task::spawn_blocking(move || {
                #[cfg(test)]
                tests_hooks::start_blocking(h);
                handle.block_on(EmbeddedClient::start(&home))
            })
            .await;
            let result = {
                let mut state = lock(&owned_context.inner);
                let result = match started {
                    Ok(Ok(client)) => {
                        state.client = Some(Arc::new(client));
                        Ok(())
                    }
                    Ok(Err(_)) => Err(STORAGE_UNAVAILABLE),
                    Err(_) => {
                        state.faulted = true;
                        Err(INTERNAL)
                    }
                };
                state.starting = false;
                result
            };
            owned_context.notify.notify_waiters();
            let _ = ready_tx.send(result);
        });
        let status = runtime
            .block_on(bounded(&call.operation, time, async {
                let deadline = tokio::time::Instant::now() + time;
                ready_rx.await.map_err(|_| INTERNAL)??;
                let client = lock(&call.context.inner).client.clone().ok_or(INTERNAL)?;
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err(DEADLINE);
                }
                if client.wait_connected(remaining).await {
                    Ok(())
                } else {
                    Err(DEADLINE)
                }
            }))
            .map_or_else(|e| e, |_| OK);
        let status = {
            let mut state = lock(&call.context.inner);
            let proposed = if state.phase != STARTING {
                CANCELLED
            } else {
                status
            };
            let decided = call.operation.finish(proposed);
            if decided == OK {
                state.identity = state
                    .client
                    .as_ref()
                    .map(|c| clone_identity(c.public_identity()));
                state.phase = RUNNING;
            }
            decided
        };
        call.done_mark();
        let ctx = call.context.clone();
        drop(control);
        call.quiesce();
        if status != OK {
            out.flags = 1;
            begin_cleanup(h, &ctx)?;
            #[cfg(test)]
            tests_hooks::start_cleanup(h);
            let _ = runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let n = ctx.notify.notified();
                        if !lock(&ctx.inner).cleanup {
                            break;
                        }
                        n.await;
                    }
                })
                .await
            });
        }
        Ok(status)
    })
}

unsafe fn pin_action(
    h: u64,
    o: u64,
    peer: Bytes,
    k: *const u8,
    ms: u32,
    out: *mut ResultV1,
    forget: bool,
) -> Status {
    result_boundary(out, |epilogue| {
        let out = result(out)?;
        let time = millis(ms, 30000)?;
        let runtime = rt()?;
        let peer = text(peer, 32)?;
        name(&peer)?;
        let key = key(k)?;
        let mut call = Call::begin(h, o, epilogue)?;
        let control = match Control::acquire(&call.context, RUNNING, false) {
            Ok(c) => c,
            Err(e) => return Ok(finish(&mut call, out, e, false)),
        };
        let client = match client(&call.context, false) {
            Ok(c) => c,
            Err(e) => return Ok(finish(&mut call, out, e, false)),
        };
        let res = runtime.block_on(bounded(&call.operation, time, async {
            if forget {
                for op in operations(h) {
                    if lock(&op.peer).as_deref() == Some(&peer) {
                        op.cancel()
                    }
                }
                for (id, s) in streams(h, Some(&peer)) {
                    s.close();
                    s.drain().await;
                    let _ = lock(registry()).streams.remove(id);
                }
                client
                    .forget_verified_peer(&peer, &key)
                    .await
                    .map_err(open_error)
            } else {
                client
                    .approve_verified_peer(&peer, &key)
                    .await
                    .map_err(open_error)
            }
        }));
        drop(client);
        drop(control);
        Ok(finish(&mut call, out, res.map_or_else(|e| e, |_| OK), true))
    })
}
/// # Safety
/// All pointers must name valid, aligned full ABI objects or stated-length
/// buffers, remain borrowed until return, and not overlap another argument.
#[no_mangle]
pub unsafe extern "C" fn wr_v1_pin_approve(
    h: u64,
    o: u64,
    p: Bytes,
    k: *const u8,
    ms: u32,
    out: *mut ResultV1,
) -> Status {
    pin_action(h, o, p, k, ms, out, false)
}
/// # Safety
/// All pointers must name valid, aligned full ABI objects or stated-length
/// buffers, remain borrowed until return, and not overlap another argument.
#[no_mangle]
pub unsafe extern "C" fn wr_v1_pin_forget(
    h: u64,
    o: u64,
    p: Bytes,
    k: *const u8,
    ms: u32,
    out: *mut ResultV1,
) -> Status {
    pin_action(h, o, p, k, ms, out, true)
}
unsafe fn open(
    h: u64,
    o: u64,
    peer: Bytes,
    port: u16,
    share: Option<Bytes>,
    k: *const u8,
    ms: u32,
    out: *mut ResultV1,
) -> Status {
    result_boundary(out, |epilogue| {
        let out = result(out)?;
        let time = millis(ms, 30000)?;
        let runtime = rt()?;
        let peer = text(peer, 32)?;
        name(&peer)?;
        let key = key(k)?;
        let share = match share {
            Some(s) => {
                let s = text(s, 32)?;
                name(&s)?;
                Some(s)
            }
            None => {
                if port == 0 {
                    return Err(INVALID_ARGUMENT);
                }
                None
            }
        };
        let mut call = Call::begin(h, o, epilogue)?;
        *lock(&call.operation.peer) = Some(peer.clone());
        let client = match client(&call.context, true) {
            Ok(c) => c,
            Err(e) => return Ok(finish(&mut call, out, e, false)),
        };
        let res = runtime.block_on(bounded(&call.operation, time, async {
            match share {
                Some(s) => client
                    .open_gateway_pinned(&peer, &s, &key)
                    .await
                    .map_err(open_error),
                None => client
                    .open_private_pinned(&peer, port, &key)
                    .await
                    .map_err(open_error),
            }
        }));
        drop(client);
        match res {
            Err(e) => Ok(finish(&mut call, out, e, true)),
            Ok(channel) => {
                let stream = Stream::new(h, peer, key, channel);
                let context = call.context.clone();
                let state = lock(&context.inner);
                if state.phase != RUNNING || state.control {
                    stream.close();
                    drop(state);
                    return Ok(finish(&mut call, out, BAD_STATE, true));
                }
                let status = call.operation.finish(OK);
                if status != OK {
                    stream.close();
                    drop(state);
                    call.done_mark();
                    out.flags = 1;
                    return Ok(status);
                }
                call.done_mark();
                match lock(registry()).streams.insert(stream) {
                    Ok(id) => {
                        out.value = id;
                        Ok(OK)
                    }
                    Err(e) => {
                        out.flags = 1;
                        Ok(e)
                    }
                }
            }
        }
    })
}
/// # Safety
/// All pointers must name valid, aligned full ABI objects or stated-length
/// buffers, remain borrowed until return, and not overlap another argument.
#[no_mangle]
pub unsafe extern "C" fn wr_v1_open_private_pinned(
    h: u64,
    o: u64,
    p: Bytes,
    port: u16,
    k: *const u8,
    ms: u32,
    out: *mut ResultV1,
) -> Status {
    open(h, o, p, port, None, k, ms, out)
}
/// # Safety
/// All pointers must name valid, aligned full ABI objects or stated-length
/// buffers, remain borrowed until return, and not overlap another argument.
#[no_mangle]
pub unsafe extern "C" fn wr_v1_open_gateway_pinned(
    h: u64,
    o: u64,
    p: Bytes,
    s: Bytes,
    k: *const u8,
    ms: u32,
    out: *mut ResultV1,
) -> Status {
    open(h, o, p, 0, Some(s), k, ms, out)
}
fn io_error(e: std::io::Error) -> Status {
    if e.kind() == std::io::ErrorKind::InvalidData {
        AUTH_FAILED
    } else {
        TRANSPORT
    }
}
unsafe fn buffer(p: *const u8, len: u32) -> Result<(), Status> {
    if p.is_null() || len == 0 || len > 65536 || (p as usize).checked_add(len as usize).is_none() {
        Err(INVALID_ARGUMENT)
    } else {
        Ok(())
    }
}
async fn io_bounded<T>(
    op: &Operation,
    s: &Stream,
    time: Duration,
    f: impl Future<Output = Result<T, Status>>,
) -> Result<T, Status> {
    tokio::select! {biased;_=op.cancel.cancelled()=>Err(CANCELLED),_=s.cancel.cancelled()=>Err(CANCELLED),r=tokio::time::timeout(time,f)=>r.map_err(|_|DEADLINE)?}
}
fn io_done(call: &mut Call, s: &Arc<Stream>, status: Status, out: &mut ResultV1) -> Status {
    let status = call.finish(status);
    if status < 0 {
        s.close();
        // The call epilogue still owns an active stream lease. Cleanup must not
        // await that lease on this same stack, nor release it before output ends.
        // This owned task clears directions/remainders after both calls return;
        // only explicit close/stop acknowledges drain and invalidates the handle.
        let closing = s.clone();
        if let Ok(runtime) = runtime() {
            runtime.spawn(async move { closing.drain().await });
        }
        out.flags = 1;
    }
    status
}
/// # Safety
/// All pointers must name valid, aligned full ABI objects or stated-length
/// buffers, remain borrowed until return, and not overlap another argument.
#[no_mangle]
pub unsafe extern "C" fn wr_v1_write(
    h: u64,
    o: u64,
    p: *const u8,
    len: u32,
    ms: u32,
    out: *mut ResultV1,
) -> Status {
    result_boundary(out, |epilogue| {
        let out = result(out)?;
        let time = millis(ms, 30000)?;
        buffer(p, len)?;
        let runtime = rt()?;
        let s = stream(h)?;
        let mut call = Call::begin(s.context, o, epilogue)?;
        let user = match s.begin(&call.context) {
            Ok(u) => u,
            Err(e) => return Ok(finish(&mut call, out, e, false)),
        };
        epilogue.stream = Some(user);
        let mut tx = match s.tx.try_lock() {
            Ok(t) => t,
            Err(_) => {
                return Ok(finish(&mut call, out, BUSY, false));
            }
        };
        if lock(&s.meta).finished || tx.is_none() {
            drop(tx);
            return Ok(finish(&mut call, out, BAD_STATE, false));
        }
        let data = Secret(std::slice::from_raw_parts(p, len as usize).to_vec());
        let mut count = 0;
        let res = runtime.block_on(io_bounded(&call.operation, &s, time, async {
            for chunk in data.0.chunks(warren::noise::MAX_PLAINTEXT) {
                tx.as_mut()
                    .ok_or(BAD_STATE)?
                    .send(chunk)
                    .await
                    .map_err(io_error)?;
                count += chunk.len();
            }
            Ok(())
        }));
        drop(tx);
        out.count = count as u32;
        Ok(io_done(&mut call, &s, res.map_or_else(|e| e, |_| OK), out))
    })
}
/// # Safety
/// All pointers must name valid, aligned full ABI objects or stated-length
/// buffers, remain borrowed until return, and not overlap another argument.
#[no_mangle]
pub unsafe extern "C" fn wr_v1_finish_write(h: u64, o: u64, ms: u32, out: *mut ResultV1) -> Status {
    result_boundary(out, |epilogue| {
        let out = result(out)?;
        let time = millis(ms, 30000)?;
        let runtime = rt()?;
        let s = stream(h)?;
        let mut call = Call::begin(s.context, o, epilogue)?;
        let user = match s.begin(&call.context) {
            Ok(u) => u,
            Err(e) => return Ok(finish(&mut call, out, e, false)),
        };
        epilogue.stream = Some(user);
        let mut tx = match s.tx.try_lock() {
            Ok(t) => t,
            Err(_) => {
                return Ok(finish(&mut call, out, BUSY, false));
            }
        };
        if lock(&s.meta).finished || tx.is_none() {
            drop(tx);
            return Ok(finish(&mut call, out, BAD_STATE, false));
        }
        let res = runtime.block_on(io_bounded(&call.operation, &s, time, async {
            tx.as_mut()
                .ok_or(BAD_STATE)?
                .finish()
                .await
                .map_err(io_error)
        }));
        if res.is_ok() {
            lock(&s.meta).finished = true
        }
        drop(tx);
        Ok(io_done(&mut call, &s, res.map_or_else(|e| e, |_| OK), out))
    })
}
/// # Safety
/// All pointers must name valid, aligned full ABI objects or stated-length
/// buffers, remain borrowed until return, and not overlap another argument.
#[no_mangle]
pub unsafe extern "C" fn wr_v1_read(
    h: u64,
    o: u64,
    p: *mut u8,
    len: u32,
    ms: u32,
    out: *mut ResultV1,
) -> Status {
    result_boundary(out, |epilogue| {
        let out = result(out)?;
        let time = millis(ms, 30000)?;
        buffer(p, len)?;
        let runtime = rt()?;
        let s = stream(h)?;
        let mut call = Call::begin(s.context, o, epilogue)?;
        let user = match s.begin(&call.context) {
            Ok(u) => u,
            Err(e) => return Ok(finish(&mut call, out, e, false)),
        };
        epilogue.stream = Some(user);
        let mut rx = match s.rx.try_lock() {
            Ok(t) => t,
            Err(_) => {
                return Ok(finish(&mut call, out, BUSY, false));
            }
        };
        #[cfg(test)]
        tests_hooks::read_admitted(h);
        let res = runtime.block_on(io_bounded(&call.operation, &s, time, async {
            if rx.offset == rx.remainder.len() && !rx.eof {
                let next = rx
                    .rx
                    .as_mut()
                    .ok_or(BAD_STATE)?
                    .recv()
                    .await
                    .map_err(io_error)?;
                match next {
                    Some(v) => {
                        if v.len() > warren::noise::MAX_PLAINTEXT {
                            return Err(INTERNAL);
                        }
                        rx.remainder = v;
                        rx.offset = 0;
                    }
                    None => rx.eof = true,
                }
            }
            if rx.eof {
                return Ok((EOF, Secret(vec![])));
            }
            let end = (rx.offset + len as usize).min(rx.remainder.len());
            let data = Secret(rx.remainder[rx.offset..end].to_vec());
            let offset = rx.offset;
            clear(&mut rx.remainder[offset..end]);
            rx.offset = end;
            if end == rx.remainder.len() {
                rx.remainder.clear();
                rx.offset = 0;
            }
            Ok((OK, data))
        }));
        drop(rx);
        let (status, data) = match res {
            Ok(v) => v,
            Err(e) => (e, Secret(vec![])),
        };
        let status = io_done(&mut call, &s, status, out);
        #[cfg(test)]
        tests_hooks::read_terminal(h);
        if status == OK {
            ptr::copy_nonoverlapping(data.0.as_ptr(), p, data.0.len());
            out.count = data.0.len() as u32;
        }
        Ok(status)
    })
}
#[no_mangle]
pub extern "C" fn wr_v1_stream_close(h: u64, ms: u32) -> Status {
    boundary(|| {
        let time = millis(ms, 30000)?;
        let runtime = rt()?;
        let s = stream(h)?;
        s.close();
        runtime
            .block_on(async { tokio::time::timeout(time, s.drain()).await })
            .map_err(|_| DEADLINE)?;
        match lock(registry()).streams.remove(h) {
            Ok(()) | Err(INVALID_HANDLE) => Ok(OK),
            Err(e) => Err(e),
        }
    })
}
#[no_mangle]
pub extern "C" fn wr_v1_stop(h: u64, ms: u32) -> Status {
    boundary(|| {
        let time = millis(ms, 30000)?;
        let runtime = rt()?;
        let c = context(h)?;
        begin_cleanup(h, &c)?;
        runtime
            .block_on(async {
                tokio::time::timeout(time, async {
                    loop {
                        let n = c.notify.notified();
                        let done = {
                            let s = lock(&c.inner);
                            !s.cleanup
                                && s.active == 0
                                && s.calls == 0
                                && s.client.is_none()
                                && [STOPPED, FAULTED].contains(&s.phase)
                        };
                        if done {
                            break;
                        }
                        n.await;
                    }
                })
                .await
            })
            .map_err(|_| DEADLINE)?;
        Ok(OK)
    })
}

#[cfg(test)]
mod transport_tests;

#[cfg(test)]
mod panic_controls {
    use super::*;
    #[test]
    fn contained_panic_faults_and_drains_context() {
        unsafe {
            let path = "/ffi-panic-control-no-storage";
            let cfg = Config {
                struct_size: size_of::<Config>() as u32,
                abi_version: 1,
                storage_root: Bytes {
                    ptr: path.as_ptr(),
                    len: path.len() as u32,
                },
                reserved: [0; 4],
            };
            let mut h = 0;
            assert_eq!(wr_v1_context_create(&cfg, &mut h), OK);
            let mut o = 0;
            assert_eq!(wr_v1_operation_create(h, &mut o), OK);
            let mut out = ResultV1 {
                struct_size: size_of::<ResultV1>() as u32,
                ..Default::default()
            };
            let status = result_boundary(&mut out, |epilogue| {
                let _call = Call::begin(h, o, epilogue)?;
                panic!("fixed non-secret panic control");
            });
            assert_eq!(status, INTERNAL);
            assert_eq!(out.flags, 1);
            assert_eq!(wr_v1_stop(h, 5000), OK);
            let mut state = 99;
            let mut connected = 99;
            assert_eq!(wr_v1_context_state(h, &mut state, &mut connected), OK);
            assert_eq!((state, connected), (FAULTED, 0));
            assert_eq!(wr_v1_operation_release(o), OK);
            assert_eq!(wr_v1_context_destroy(h), OK);
        }
    }
}

#[cfg(test)]
mod tests_hooks {
    use super::*;
    use std::sync::Barrier;
    pub struct Pause {
        pub reached: Barrier,
        pub resume: Barrier,
    }
    impl Pause {
        pub fn new() -> Arc<Self> {
            Arc::new(Self {
                reached: Barrier::new(2),
                resume: Barrier::new(2),
            })
        }
    }
    pub static OP_LOOKUP: Mutex<Option<(u64, Arc<Pause>)>> = Mutex::new(None);
    pub static READ_ADMITTED: Mutex<Option<(u64, Arc<Pause>)>> = Mutex::new(None);
    pub static READ_TERMINAL: Mutex<Option<(u64, Arc<Pause>)>> = Mutex::new(None);
    pub static START_BLOCKING: Mutex<Option<(u64, Arc<Pause>)>> = Mutex::new(None);
    pub static START_CLEANUP: Mutex<Option<(u64, Arc<Pause>)>> = Mutex::new(None);
    pub fn start_blocking(h: u64) {
        at(h, &START_BLOCKING)
    }
    pub fn start_cleanup(h: u64) {
        at(h, &START_CLEANUP)
    }
    fn at(h: u64, slot: &Mutex<Option<(u64, Arc<Pause>)>>) {
        let p = lock(slot)
            .as_ref()
            .filter(|(target, _)| *target == h)
            .map(|(_, p)| p.clone());
        if let Some(p) = p {
            p.reached.wait();
            p.resume.wait();
        }
    }
    pub fn operation_lookup(h: u64) {
        at(h, &OP_LOOKUP)
    }
    pub fn read_admitted(h: u64) {
        at(h, &READ_ADMITTED)
    }
    pub fn read_terminal(h: u64) {
        at(h, &READ_TERMINAL)
    }
    #[test]
    fn destroyed_context_cannot_admit_orphan_operation() {
        unsafe {
            let path = "/ffi-destroyed-context-no-storage";
            let cfg = Config {
                struct_size: size_of::<Config>() as u32,
                abi_version: 1,
                storage_root: Bytes {
                    ptr: path.as_ptr(),
                    len: path.len() as u32,
                },
                reserved: [0; 4],
            };
            let mut h = 0;
            assert_eq!(wr_v1_context_create(&cfg, &mut h), OK);
            let pause = Pause::new();
            *lock(&OP_LOOKUP) = Some((h, pause.clone()));
            let worker = std::thread::spawn(move || {
                let mut o = 99;
                let status = wr_v1_operation_create(h, &mut o);
                (status, o)
            });
            pause.reached.wait();
            *lock(&OP_LOOKUP) = None;
            assert_eq!(wr_v1_context_destroy(h), OK);
            let mut next = 0;
            assert_eq!(wr_v1_context_create(&cfg, &mut next), OK);
            assert_ne!(next, h);
            pause.resume.wait();
            assert_eq!(worker.join().unwrap(), (INVALID_HANDLE, 0));
            assert!(operations(h).is_empty());
            assert_eq!(wr_v1_context_destroy(next), OK);
        }
    }
    #[test]
    fn start_deadline_retains_owned_initialization_and_live_epilogue() {
        unsafe {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("start-home");
            let path = path.to_str().unwrap();
            let cfg = Config {
                struct_size: size_of::<Config>() as u32,
                abi_version: 1,
                storage_root: Bytes {
                    ptr: path.as_ptr(),
                    len: path.len() as u32,
                },
                reserved: [0; 4],
            };
            let mut h = 0;
            assert_eq!(wr_v1_context_create(&cfg, &mut h), OK);
            let mut o = 0;
            assert_eq!(wr_v1_operation_create(h, &mut o), OK);
            let initialization = Pause::new();
            let cleanup = Pause::new();
            *lock(&START_BLOCKING) = Some((h, initialization.clone()));
            *lock(&START_CLEANUP) = Some((h, cleanup.clone()));
            let worker = std::thread::spawn(move || {
                let mut r = ResultV1 {
                    struct_size: size_of::<ResultV1>() as u32,
                    ..Default::default()
                };
                let result = wr_v1_start(h, o, 5000, &mut r);
                (result, r)
            });
            initialization.reached.wait();
            *lock(&START_BLOCKING) = None;
            assert_eq!(wr_v1_operation_cancel(o), OK);
            cleanup.reached.wait();
            *lock(&START_CLEANUP) = None;
            assert_eq!(wr_v1_operation_release(o), BUSY);
            assert_eq!(wr_v1_context_destroy(h), BUSY);
            cleanup.resume.wait();
            let (status, r) = worker.join().unwrap();
            assert_eq!(status, CANCELLED);
            assert_eq!(r.flags, 1);
            let mut phase = 99;
            let mut connected = 99;
            assert_eq!(wr_v1_context_state(h, &mut phase, &mut connected), OK);
            assert_eq!(phase, STOPPING);
            assert_eq!(wr_v1_stop(h, 1), DEADLINE);
            assert_eq!(wr_v1_operation_release(o), OK);
            initialization.resume.wait();
            assert_eq!(wr_v1_stop(h, 5000), OK);
            assert_eq!(wr_v1_context_destroy(h), OK);
        }
    }
}
