//! A revocation holds even while other registry reloads run concurrently.
//!
//! The relay reloads its registry from the revision poller, after every
//! publish/unpublish and after every enrollment. Reloads are serialized, so a
//! reload that read the node table before a revocation can never install its
//! registry after the reload that saw the revocation. (The poller does not
//! reload again for the same revision, so such a stale registry would keep
//! the revoked key able to authenticate until some unrelated change.)

mod common;

use common::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_holds_during_concurrent_reloads() {
    // The poller is disabled here; the test performs the poller's reload
    // itself (exactly one reload after the revision change, like the poller).
    let relay = start_relay_with(|c| c.revision_poll = Duration::from_secs(3600)).await;
    let inner = relay.h().inner.clone();

    const TRIALS: usize = 100;
    const SPINNERS: usize = 4;
    for trial in 0..TRIALS {
        let name = format!("x{trial}");
        let x = enroll(&relay, &name).await;
        let node_id = x.ident().node_id;

        // Other reloads that happen to run at the same time (publish,
        // unpublish, enrollment all call reload()). They keep starting new
        // reloads until the revocation's own reload is about to run, so
        // several are in flight around it.
        let stop = Arc::new(AtomicBool::new(false));
        let pause = Arc::new(AtomicBool::new(false));
        let spinners: Vec<_> = (0..SPINNERS)
            .map(|_| {
                let inner = inner.clone();
                let stop = stop.clone();
                let pause = pause.clone();
                std::thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        if pause.load(Ordering::SeqCst) {
                            std::thread::sleep(Duration::from_micros(200));
                            continue;
                        }
                        let _ = inner.reload();
                    }
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(2));
        assert!(inner.db.revoke(&name, warren::now_secs()).unwrap());
        pause.store(true, Ordering::SeqCst);
        inner.reload().unwrap(); // what the poller does for this revision
        stop.store(true, Ordering::SeqCst);
        for s in spinners {
            s.join().unwrap();
        }

        let stale = inner.registry.read().unwrap().nodes.contains_key(&node_id);
        if stale {
            // The revoked key authenticates and gets a live link.
            let mut ws = raw_ws(&relay).await;
            let c = challenge(&mut ws).await;
            let v = send_hello(
                &mut ws,
                &auth_hello(&x.identity(), &node_id, &c, "127.0.0.1"),
            )
            .await;
            panic!(
                "trial {trial}: {name} was revoked and the poller-equivalent reload ran, \
                 but a concurrent reload installed a registry read before the revocation; \
                 {name} is still active in memory and its authentication now gets {v:?}; \
                 online: {:?}",
                relay.online()
            );
        }
    }
}
