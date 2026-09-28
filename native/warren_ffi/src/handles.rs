use crate::{abi::*, stream::Stream};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};
use tokio::{runtime::Runtime, sync::Notify};
use tokio_util::sync::CancellationToken;
use warren::node::embedded::{EmbeddedClient, PublicIdentity};
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
pub fn runtime() -> Result<&'static Runtime, Status> {
    static RT: OnceLock<Result<Runtime, ()>> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| ())
    })
    .as_ref()
    .map_err(|_| INTERNAL)
}
pub struct Context {
    pub home: PathBuf,
    pub inner: Mutex<ContextState>,
    pub notify: Notify,
}
pub struct ContextState {
    pub alive: bool,
    pub starting: bool,
    pub phase: u32,
    pub active: usize,
    pub calls: usize,
    pub control: bool,
    pub client: Option<Arc<EmbeddedClient>>,
    pub identity: Option<PublicIdentity>,
    pub cleanup: bool,
    pub faulted: bool,
}
impl Context {
    pub fn new(home: PathBuf) -> Self {
        Self {
            home,
            inner: Mutex::new(ContextState {
                alive: true,
                starting: false,
                phase: STOPPED,
                active: 0,
                calls: 0,
                control: false,
                client: None,
                identity: None,
                cleanup: false,
                faulted: false,
            }),
            notify: Notify::new(),
        }
    }
}
pub struct Operation {
    pub context: u64,
    pub inner: Mutex<OpState>,
    pub cancel: CancellationToken,
    pub peer: Mutex<Option<String>>,
}
pub struct OpState {
    pub active_call: bool,
    pub phase: u8,
    pub cancelled: bool,
}
impl Operation {
    pub fn cancel(&self) {
        let mut s = lock(&self.inner);
        if s.phase == 2 {
            return;
        }
        s.cancelled = true;
        if s.phase == 0 {
            s.phase = 2;
        }
        self.cancel.cancel();
    }
    pub fn finish(&self, status: Status) -> Status {
        let mut s = lock(&self.inner);
        if s.phase != 1 {
            return INTERNAL;
        }
        let result = if s.cancelled { CANCELLED } else { status };
        s.phase = 2;
        result
    }
}
pub struct Slot<T> {
    generation: u64,
    value: Option<Arc<T>>,
}
pub struct Table<T> {
    kind: u64,
    cap: usize,
    slots: Vec<Slot<T>>,
}
impl<T> Table<T> {
    pub fn new(kind: u64, cap: usize) -> Self {
        Self {
            kind,
            cap,
            slots: Vec::new(),
        }
    }
    pub fn insert(&mut self, value: Arc<T>) -> Result<u64, Status> {
        for (i, s) in self.slots.iter_mut().enumerate() {
            if s.value.is_none() && s.generation < (u64::MAX >> 16) {
                s.generation += 1;
                s.value = Some(value);
                return Ok((s.generation << 16) | ((i as u64) << 8) | self.kind);
            }
        }
        if self.slots.len() >= self.cap {
            return Err(LIMIT);
        }
        let i = self.slots.len();
        self.slots.push(Slot {
            generation: 1,
            value: Some(value),
        });
        Ok((1 << 16) | ((i as u64) << 8) | self.kind)
    }
    pub fn get(&self, h: u64) -> Result<Arc<T>, Status> {
        if h & 255 != self.kind {
            return Err(INVALID_HANDLE);
        }
        let i = ((h >> 8) & 255) as usize;
        let s = self.slots.get(i).ok_or(INVALID_HANDLE)?;
        if h >> 16 != s.generation {
            return Err(INVALID_HANDLE);
        }
        s.value.clone().ok_or(INVALID_HANDLE)
    }
    pub fn remove(&mut self, h: u64) -> Result<(), Status> {
        self.get(h)?;
        self.slots[((h >> 8) & 255) as usize].value = None;
        Ok(())
    }
    pub fn entries(&self) -> Vec<(u64, Arc<T>)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                s.value
                    .clone()
                    .map(|v| ((s.generation << 16) | ((i as u64) << 8) | self.kind, v))
            })
            .collect()
    }
}
pub struct Registry {
    pub contexts: Table<Context>,
    pub operations: Table<Operation>,
    pub streams: Table<Stream>,
}
pub fn registry() -> &'static Mutex<Registry> {
    static R: OnceLock<Mutex<Registry>> = OnceLock::new();
    R.get_or_init(|| {
        Mutex::new(Registry {
            contexts: Table::new(1, 1),
            operations: Table::new(2, 64),
            streams: Table::new(3, 32),
        })
    })
}
pub fn context(h: u64) -> Result<Arc<Context>, Status> {
    lock(registry()).contexts.get(h)
}
pub fn operation(h: u64) -> Result<Arc<Operation>, Status> {
    lock(registry()).operations.get(h)
}
pub fn stream(h: u64) -> Result<Arc<Stream>, Status> {
    lock(registry()).streams.get(h)
}
pub fn streams(ctx: u64, peer: Option<&str>) -> Vec<(u64, Arc<Stream>)> {
    lock(registry())
        .streams
        .entries()
        .into_iter()
        .filter(|(_, s)| s.context == ctx && peer.is_none_or(|p| s.peer == p))
        .collect()
}
pub fn operations(ctx: u64) -> Vec<Arc<Operation>> {
    lock(registry())
        .operations
        .entries()
        .into_iter()
        .filter(|(_, o)| o.context == ctx)
        .map(|(_, o)| o)
        .collect()
}
/// Outer FFI epilogue keeps handles and stream drain acknowledgements live
/// through caller-output writes and panic containment.
#[derive(Default)]
pub struct Epilogue {
    pub context: Option<Arc<Context>>,
    pub operation: Option<Arc<Operation>>,
    pub stream: Option<crate::stream::User>,
}
impl Drop for Epilogue {
    fn drop(&mut self) {
        self.stream.take();
        if let Some(op) = self.operation.take() {
            lock(&op.inner).active_call = false;
        }
        if let Some(context) = self.context.take() {
            lock(&context.inner).calls -= 1;
            context.notify.notify_waiters();
        }
    }
}
pub struct Call {
    pub context: Arc<Context>,
    pub operation: Arc<Operation>,
    done: bool,
    handle: u64,
    context_active: bool,
}
impl Call {
    pub fn begin(ctx: u64, op: u64, epilogue: &mut Epilogue) -> Result<Self, Status> {
        let context = context(ctx)?;
        let operation = operation(op)?;
        if operation.context != ctx {
            return Err(INVALID_HANDLE);
        }
        {
            let mut c = lock(&context.inner);
            if !c.alive {
                return Err(INVALID_HANDLE);
            }
            let mut o = lock(&operation.inner);
            if o.phase != 0 {
                return Err(if o.cancelled { CANCELLED } else { BAD_STATE });
            }
            if [STOPPING, FAULTED].contains(&c.phase) {
                o.phase = 2;
                return Err(BAD_STATE);
            }
            o.phase = 1;
            o.active_call = true;
            epilogue.operation = Some(operation.clone());
            epilogue.context = Some(context.clone());
            c.active += 1;
            c.calls += 1;
        }
        Ok(Self {
            context,
            operation,
            done: false,
            handle: ctx,
            context_active: true,
        })
    }
    pub fn quiesce(&mut self) {
        if self.context_active {
            lock(&self.context.inner).active -= 1;
            self.context_active = false;
            self.context.notify.notify_waiters();
        }
    }
    pub fn done_mark(&mut self) {
        self.done = true;
    }
    pub fn finish(&mut self, status: Status) -> Status {
        self.done = true;
        self.operation.finish(status)
    }
}
impl Drop for Call {
    fn drop(&mut self) {
        if !self.done {
            self.operation.cancel();
            let mut s = lock(&self.context.inner);
            s.phase = FAULTED;
            s.faulted = true;
            drop(s);
            let _ = self.operation.finish(INTERNAL);
        }
        self.quiesce();
        if !self.done {
            let _ = crate::begin_cleanup(self.handle, &self.context);
        }
    }
}
pub struct Control(pub Arc<Context>);
impl Control {
    pub fn acquire(c: &Arc<Context>, phase: u32, exclusive: bool) -> Result<Self, Status> {
        let mut s = lock(&c.inner);
        if s.phase != phase {
            return Err(BAD_STATE);
        }
        if s.control || (exclusive && s.calls != 1) {
            return Err(BUSY);
        }
        s.control = true;
        Ok(Self(c.clone()))
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        lock(&self.0.inner).control = false;
        self.0.notify.notify_waiters();
    }
}
pub fn client(c: &Arc<Context>, opening: bool) -> Result<Arc<EmbeddedClient>, Status> {
    let s = lock(&c.inner);
    if s.phase != RUNNING {
        return Err(BAD_STATE);
    }
    if opening && s.control {
        return Err(BUSY);
    }
    s.client.clone().ok_or(BAD_STATE)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generations_and_kind_and_limit() {
        let mut t = Table::new(7, 1);
        let h = t.insert(Arc::new(3)).unwrap();
        assert_eq!(t.insert(Arc::new(4)).unwrap_err(), LIMIT);
        assert!(t.get(h ^ 1).is_err());
        t.remove(h).unwrap();
        let n = t.insert(Arc::new(4)).unwrap();
        assert_ne!(h, n);
        assert!(t.get(h).is_err());
        assert_eq!(*t.get(n).unwrap(), 4);
    }
    #[test]
    fn cancel_completion_linearization() {
        let a = Operation {
            context: 1,
            inner: Mutex::new(OpState {
                active_call: true,
                phase: 1,
                cancelled: false,
            }),
            cancel: CancellationToken::new(),
            peer: Mutex::new(None),
        };
        assert_eq!(a.finish(OK), OK);
        a.cancel();
        assert!(!a.cancel.is_cancelled());
        let b = Operation {
            context: 1,
            inner: Mutex::new(OpState {
                active_call: true,
                phase: 1,
                cancelled: false,
            }),
            cancel: CancellationToken::new(),
            peer: Mutex::new(None),
        };
        b.cancel();
        assert_eq!(b.finish(OK), CANCELLED);
    }
}
