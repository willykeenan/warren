use crate::{
    abi::*,
    handles::{lock, Context},
};
use std::sync::{Arc, Mutex};
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio_util::sync::CancellationToken;
use warren::noise::{SecureAbort, SecureChannel, SecureReceiver, SecureSender};
pub struct Stream {
    pub context: u64,
    pub peer: String,
    pub _expected_key: [u8; 32],
    pub tx: AsyncMutex<Option<SecureSender>>,
    pub rx: AsyncMutex<Read>,
    pub abort: SecureAbort,
    pub cancel: CancellationToken,
    pub meta: Mutex<Meta>,
    pub notify: Notify,
}
pub struct Meta {
    pub closing: bool,
    pub active: usize,
    pub finished: bool,
}
pub struct Read {
    pub rx: Option<SecureReceiver>,
    pub remainder: Vec<u8>,
    pub offset: usize,
    pub eof: bool,
}
impl Drop for Read {
    fn drop(&mut self) {
        clear(&mut self.remainder)
    }
}
impl Stream {
    pub fn new(context: u64, peer: String, key: [u8; 32], channel: SecureChannel) -> Arc<Self> {
        let abort = channel.abort_handle();
        Arc::new(Self {
            context,
            peer,
            _expected_key: key,
            tx: AsyncMutex::new(Some(channel.tx)),
            rx: AsyncMutex::new(Read {
                rx: Some(channel.rx),
                remainder: vec![],
                offset: 0,
                eof: false,
            }),
            abort,
            cancel: CancellationToken::new(),
            meta: Mutex::new(Meta {
                closing: false,
                active: 0,
                finished: false,
            }),
            notify: Notify::new(),
        })
    }
    pub fn begin(self: &Arc<Self>, ctx: &Arc<Context>) -> Result<User, Status> {
        if lock(&ctx.inner).phase != RUNNING {
            return Err(BAD_STATE);
        }
        let mut m = lock(&self.meta);
        if m.closing {
            return Err(BAD_STATE);
        }
        m.active += 1;
        Ok(User(self.clone()))
    }
    pub fn close(&self) {
        lock(&self.meta).closing = true;
        self.cancel.cancel();
        self.abort.abort();
        self.notify.notify_waiters();
    }
    pub async fn drain(&self) {
        loop {
            let n = self.notify.notified();
            if lock(&self.meta).active == 0 {
                break;
            }
            n.await;
        }
        *self.tx.lock().await = None;
        let mut r = self.rx.lock().await;
        clear(&mut r.remainder);
        r.remainder.clear();
        r.offset = 0;
        r.rx = None;
    }
}
pub struct User(pub Arc<Stream>);
impl Drop for User {
    fn drop(&mut self) {
        let mut m = lock(&self.0.meta);
        m.active -= 1;
        drop(m);
        self.0.notify.notify_waiters();
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.abort.abort();
    }
}
