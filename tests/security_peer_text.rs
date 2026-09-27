//! Text from peers and the relay (OPEN_ERR messages, CTRL errors, names) is
//! escaped before it reaches the terminal.

mod common;

use common::*;
use std::time::Duration;
use warren::proto::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusal_text_from_a_peer_is_not_passed_through_raw() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll(&relay, "b").await;
    // "b" is a hostile enrolled machine speaking the protocol directly.
    let mut hostile = RawNode::connect(&relay, &b).await;
    let payload = "\u{1b}]0;owned\u{7}\u{1b}[2J\u{1b}[1;1Huser@host:~$ ";
    let answer = tokio::spawn(async move {
        loop {
            let f = hostile.next(Duration::from_secs(10)).await.expect("OPEN");
            if f.ty == FrameType::Open {
                hostile
                    .send(Frame::open_err(f.stream, ErrorCode::NotShared, payload))
                    .await;
                return hostile;
            }
        }
    });
    let e = a.d().inner.open_private("b", 22).await.err().unwrap();
    let _hostile = answer.await.unwrap();
    let shown = e.to_string();
    assert!(
        !shown.chars().any(|c| c.is_control()),
        "the error `warren nc b 22` prints to the terminal carries the peer's control \
         characters: {shown:?}"
    );
}
