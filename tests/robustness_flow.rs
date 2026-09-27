//! Flow control versus link-level queue caps, and data forwarded on streams
//! the destination has not accepted: per-stream windows bound memory without
//! tearing down healthy links.

mod common;

use bytes::Bytes;
use common::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use warren::limits::MAX_LINK_QUEUE;
use warren::mux::{self, LinkOut, Slot, StreamHost};
use warren::proto::*;

struct Host {
    out: LinkOut,
    table: Mutex<HashMap<u32, Slot>>,
}

impl StreamHost for Host {
    fn out(&self) -> &LinkOut {
        &self.out
    }
    fn remove_stream(&self, id: u32) {
        self.table.lock().unwrap().remove(&id);
    }
}

/// Every stream stays within its own 256 KiB window, the stream count stays
/// under the 1024 per-node cap, and the writer simply has not flushed yet
/// (a slow uplink). The link is not torn down: stream data has its own
/// budget, which covers every legal window (1024 x 256 KiB), so a sender that
/// obeys every window never closes its own link, even though the aggregate
/// exceeds MAX_LINK_QUEUE (64 MiB, the cap for other frames).
#[tokio::test]
async fn windows_within_limits_do_not_close_the_link() {
    let streams = (MAX_LINK_QUEUE / STREAM_WINDOW as usize) + 4; // 260, well under 1024
    assert!(streams < MAX_STREAMS_PER_NODE);

    let (out, _undrained_wire) = LinkOut::new(CancellationToken::new());
    let host = Arc::new(Host {
        out: out.clone(),
        table: Mutex::new(HashMap::new()),
    });
    let mut senders = Vec::new();
    for i in 0..streams as u32 {
        let id = 2 * i + 1;
        let h: Arc<dyn StreamHost> = host.clone();
        let (slot, tx, rx, _) = mux::new_stream(id, h, true);
        host.table.lock().unwrap().insert(id, slot);
        senders.push((tx, rx));
    }
    let window = vec![0u8; STREAM_WINDOW as usize];
    for (tx, _) in &senders {
        // Exactly the initial credit: no WINDOW is needed, nothing is overrun.
        let r = tokio::time::timeout(Duration::from_secs(5), tx.send_all(&window)).await;
        assert!(r.is_ok(), "send within the initial window must not block");
        if r.unwrap().is_err() {
            break;
        }
    }
    assert!(
        !out.is_closed(),
        "link closed after {} bytes queued by {streams} streams that each stayed inside \
         their {STREAM_WINDOW}-byte window (MAX_LINK_QUEUE = {MAX_LINK_QUEUE})",
        out.queued_bytes()
    );
}

/// The relay holds DATA for a stream until the destination has accepted it
/// (OPEN_OK), so an enrolled node cannot push a window of data per OPEN into
/// another node's outbound queue for ports that node never shared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_holds_data_until_destination_accepts() {
    let relay = start_relay().await;
    let a = enroll(&relay, "a").await;
    let b = enroll(&relay, "b").await;
    let mut ra = RawNode::connect(&relay, &a).await;
    let mut rb = RawNode::connect(&relay, &b).await;

    // Port 9 is not shared by anyone. Send OPEN and data back to back.
    ra.send(open_frame(1, "b", 9)).await;
    ra.send(Frame::data(1, Bytes::from(vec![0x5a; 60_000])))
        .await;

    let open = rb.next(Duration::from_secs(5)).await.expect("OPEN at b");
    assert_eq!(open.ty, FrameType::Open);
    // b has not answered (no OPEN_OK, no OPEN_ERR). Nothing else should be
    // delivered on that stream yet.
    let early = rb.next(Duration::from_millis(500)).await;
    assert!(
        !matches!(&early, Some(f) if f.ty == FrameType::Data && f.stream == open.stream),
        "relay forwarded {} DATA bytes on stream {} before the destination accepted it",
        early.as_ref().map(|f| f.payload.len()).unwrap_or(0),
        open.stream
    );
}
