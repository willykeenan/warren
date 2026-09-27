//! Revocation cannot be escaped by authenticating while the relay reloads
//! its registry.
//!
//! The relay registers a node's link only after re-checking the registry
//! under its `online` lock, so an authentication that read the registry
//! before a revocation cannot add a link after the reload has disconnected
//! the node's links.
//!
//! The relay here uses a long revision poll and the test calls
//! `inner.reload()` once after `db.revoke`, which is exactly what the poller
//! does once per revision change.

mod common;

use common::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use warren::proto::*;

/// Welcomed links one trial keeps. A new link for the same node replaces the
/// previous one on the relay, so only the newest ones can still be open.
const KEEP_LINKS: usize = 64;

/// Keep authenticating as `node` until `stop`; keep the welcomed links that
/// are still open.
async fn auth_loop(
    relay_url: String,
    pin: [u8; 32],
    ident: warren::crypto::Identity,
    node_id: String,
    stop: Arc<AtomicBool>,
    links: Arc<Mutex<Vec<RawNode>>>,
) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let url = warren::net::RelayUrl::parse(&relay_url).unwrap();
    // After a failure, pause briefly instead of retrying in a tight loop (a
    // failure can mean the process is out of file descriptors).
    let pause = || tokio::time::sleep(Duration::from_millis(5));
    let step = Duration::from_secs(10);
    while !stop.load(Ordering::SeqCst) {
        let Ok(mut ws) = warren::ws::connect_relay(&url, Some(pin)).await else {
            pause().await;
            continue;
        };
        let Ok(Some(Ok(Message::Text(t)))) = tokio::time::timeout(step, ws.next()).await else {
            pause().await;
            continue;
        };
        let RelayHello::Challenge { challenge, .. } = serde_json::from_str(t.as_str()).unwrap();
        let c = warren::crypto::parse_key32(&challenge).unwrap();
        let hello = auth_hello(&ident, &node_id, &c, "127.0.0.1");
        if ws
            .send(Message::text(serde_json::to_string(&hello).unwrap()))
            .await
            .is_err()
        {
            pause().await;
            continue;
        }
        let Ok(Some(Ok(Message::Text(t)))) = tokio::time::timeout(step, ws.next()).await else {
            pause().await;
            continue;
        };
        match serde_json::from_str::<RelayVerdict>(t.as_str()) {
            Ok(RelayVerdict::Welcome { .. }) => {
                let mut l = links.lock().unwrap();
                l.retain(|n| !n.is_closed());
                if l.len() >= KEEP_LINKS {
                    l.remove(0);
                }
                l.push(RawNode::from_ws(ws));
            }
            // Refused (revoked): nothing more to gain.
            _ => pause().await,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn revoked_node_cannot_outlive_revocation_by_racing_the_reload() {
    // Fail instead of hanging if something goes wrong.
    tokio::time::timeout(Duration::from_secs(180), race_trials())
        .await
        .expect("the revocation race trials did not finish within 180 s");
}

async fn race_trials() {
    let relay = start_relay_with(|c| c.revision_poll = Duration::from_secs(3600)).await;
    let b = enroll_started(&relay, "b").await;
    let (echo, _) = echo_server().await;
    b.share(echo, None);

    const TRIALS: usize = 40;
    const LOOPS: usize = 24;
    for trial in 0..TRIALS {
        let name = format!("x{trial}");
        let x = enroll(&relay, &name).await;
        let ident = x.identity();
        let node_id = x.ident().node_id;
        let stop = Arc::new(AtomicBool::new(false));
        let links: Arc<Mutex<Vec<RawNode>>> = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for _ in 0..LOOPS {
            tasks.push(tokio::spawn(auth_loop(
                relay.url(),
                relay.pin,
                ident.clone(),
                node_id.clone(),
                stop.clone(),
                links.clone(),
            )));
        }
        // Let the authentications get going, then revoke exactly as the
        // relay's revision poller would: one reload after the DB change.
        wait_for("first welcome", Duration::from_secs(10), || {
            !links.lock().unwrap().is_empty()
        })
        .await;
        tokio::time::sleep(Duration::from_millis(20 + (trial as u64 % 7) * 3)).await;
        assert!(relay
            .h()
            .inner
            .db
            .revoke(&name, warren::now_secs())
            .unwrap());
        relay.h().inner.reload().unwrap();
        // Any authentication started from now on is refused.
        tokio::time::sleep(Duration::from_millis(200)).await;
        stop.store(true, Ordering::SeqCst);
        for mut t in tasks {
            if tokio::time::timeout(Duration::from_secs(5), &mut t)
                .await
                .is_err()
            {
                t.abort();
                let _ = t.await;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        if relay.online().contains(&name) {
            // Show that the surviving link of a revoked node is fully usable:
            // it reaches b's shared port end to end.
            let survivor = {
                let mut l = links.lock().unwrap();
                let i = l.iter().position(|n| !n.is_closed()).expect("live link");
                l.swap_remove(i)
            };
            let mut s = survivor;
            s.send(open_frame(1, "b", echo)).await;
            let f = s
                .next(Duration::from_secs(10))
                .await
                .expect("reply to OPEN");
            assert_eq!(f.ty, FrameType::OpenOk, "{f:?}");
            let mut hs = snow::Builder::new(warren::crypto::NOISE_PARAMS.parse().unwrap())
                .local_private_key(&ident.static_secret)
                .unwrap()
                .remote_public_key(&b.identity().static_pub)
                .unwrap()
                .prologue(warren::crypto::NOISE_PROLOGUE)
                .unwrap()
                .build_initiator()
                .unwrap();
            let mut buf = vec![0u8; 65535];
            let hello = serde_json::to_vec(&warren::noise::Hello {
                v: 1,
                src: name.clone(),
                dest: "b".into(),
                port: echo,
            })
            .unwrap();
            let n = hs.write_message(&hello, &mut buf).unwrap();
            s.send(Frame::data(1, bytes::Bytes::copy_from_slice(&buf[..n])))
                .await;
            let msg2 = loop {
                let f = s.next(Duration::from_secs(10)).await.expect("msg2");
                if f.ty == FrameType::Data {
                    break f;
                }
            };
            let mut out = vec![0u8; 65535];
            hs.read_message(&msg2.payload, &mut out).unwrap();
            let t = hs.into_stateless_transport_mode().unwrap();
            let n = t
                .write_message(0, b"revoked but still here", &mut buf)
                .unwrap();
            s.send(Frame::data(1, bytes::Bytes::copy_from_slice(&buf[..n])))
                .await;
            let echoed = loop {
                let f = s.next(Duration::from_secs(10)).await.expect("echo");
                if f.ty == FrameType::Data {
                    break f;
                }
            };
            let n = t.read_message(0, &echoed.payload, &mut out).unwrap();
            panic!(
                "trial {trial}: node {name} was revoked (db + reload) but its link is still \
                 online on the relay, and through it b's shared port echoed {:?}",
                String::from_utf8_lossy(&out[..n])
            );
        }
        // Clean up this trial's links.
        links.lock().unwrap().clear();
    }
}
