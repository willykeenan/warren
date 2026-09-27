//! Stream tables drain after connection churn, including clients that
//! disconnect abruptly mid-transfer.

mod common;

use common::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_tables_drain_after_churn() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let (echo, _) = echo_server().await;
    b.share(echo, None);
    let local = a.forward("b", echo).await;
    assert_eq!(echo_roundtrip(local, b"warm").await, b"warm");

    // 4 rounds of 40 connections (under the open bucket), alternating clean
    // half-close and abrupt drop after a partial write.
    for round in 0..4 {
        let mut tasks = Vec::new();
        for i in 0..40 {
            tasks.push(tokio::spawn(async move {
                let mut s = tokio::net::TcpStream::connect(("127.0.0.1", local))
                    .await
                    .unwrap();
                let _ = s.write_all(&vec![7u8; 100_000]).await;
                if (i + round) % 2 == 0 {
                    let _ = s.shutdown().await;
                    let mut v = Vec::new();
                    let _ =
                        tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut v)).await;
                } else {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    drop(s); // abrupt
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(1100)).await;
    }

    let relay_streams = || {
        relay
            .h()
            .inner
            .online
            .lock()
            .unwrap()
            .values()
            .map(|l| l.stream_count())
            .sum::<usize>()
    };
    let node_streams = |n: &TestNode| n.d().inner.current().map(|s| s.stream_count()).unwrap_or(0);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let (r, na, nb) = (relay_streams(), node_streams(&a), node_streams(&b));
        if r == 0 && na == 0 && nb == 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "streams still open after churn: relay {r}, a {na}, b {nb}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
