//! SR5: the pin store fails closed: an unreadable or corrupt
//! known_peers.json is an error and `trust` never rewrites it.

mod common;

use common::*;
use warren::node::control::ControlRequest;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trust_does_not_discard_other_pins_when_the_store_is_unreadable() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let c = enroll_started(&relay, "c").await;
    let (echo, _) = echo_server().await;
    b.share(echo, None);
    c.share(echo, None);
    let lb = a.forward("b", echo).await;
    let lc = a.forward("c", echo).await;
    assert_eq!(echo_roundtrip(lb, b"1").await, b"1");
    assert_eq!(echo_roundtrip(lc, b"2").await, b"2");
    let before = warren::node::KnownPeers::load(&a.paths).unwrap();
    assert!(before.pinned("c").is_some());

    // The pin store becomes unreadable (truncated write, disk error, hand edit).
    std::fs::write(a.paths.known_peers(), b"{\"relay\": \"https://127.0.0.1").unwrap();
    // Opening now fails closed, as it should.
    assert!(a.d().inner.open_private("c", echo).await.is_err());

    // The user runs `warren trust b`.
    let r = a
        .ctl(ControlRequest::Trust {
            name: "b".into(),
            expect: None,
        })
        .await;
    let after = warren::node::KnownPeers::load(&a.paths).unwrap_or_default();
    assert!(
        !r.ok || after.pinned("c").is_some(),
        "`trust b` answered {r:?} and rewrote known_peers.json without c's pin: \
         pinned peers now {:?}",
        after.peers.keys().collect::<Vec<_>>()
    );
}
