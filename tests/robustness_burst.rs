//! A burst of ordinary local connections through one forward, larger than
//! the relay's 64-opens-per-second bucket, is paced (or retried) by the node
//! rather than dropped.

mod common;

use common::*;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_burst_above_open_rate_is_paced_not_dropped() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let (echo, _) = echo_server().await;
    b.share(echo, None);
    let local = a.forward("b", echo).await;

    let n = 100;
    let mut tasks = Vec::new();
    for i in 0..n {
        tasks.push(tokio::spawn(async move {
            let msg = format!("conn-{i}").into_bytes();
            let got = tokio::time::timeout(Duration::from_secs(30), async {
                let mut s = tokio::net::TcpStream::connect(("127.0.0.1", local))
                    .await
                    .unwrap();
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                s.write_all(&msg).await.unwrap();
                s.shutdown().await.unwrap();
                let mut v = Vec::new();
                let _ = s.read_to_end(&mut v).await;
                v
            })
            .await
            .unwrap_or_default();
            got == msg
        }));
    }
    let mut ok = 0;
    for t in tasks {
        if t.await.unwrap() {
            ok += 1;
        }
    }
    let status = a
        .ctl_ok(warren::node::control::ControlRequest::Status)
        .await;
    assert_eq!(
        ok,
        n,
        "{} of {n} parallel connections through the forward failed; recent errors: {}",
        n - ok,
        status["recent_errors"]
    );
}

/// Same burst after the peer key is already pinned (no lookups needed), so
/// only the 64-opens-per-second bucket is in play.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn warm_forward_burst_above_open_rate_is_paced_not_dropped() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let (echo, _) = echo_server().await;
    b.share(echo, None);
    let local = a.forward("b", echo).await;
    assert_eq!(echo_roundtrip(local, b"warm").await, b"warm");
    // Let the open bucket refill completely.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let n = 100;
    let mut tasks = Vec::new();
    for i in 0..n {
        tasks.push(tokio::spawn(async move {
            let msg = format!("conn-{i}").into_bytes();
            let got = tokio::time::timeout(Duration::from_secs(30), async {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut s = tokio::net::TcpStream::connect(("127.0.0.1", local))
                    .await
                    .unwrap();
                s.write_all(&msg).await.unwrap();
                s.shutdown().await.unwrap();
                let mut v = Vec::new();
                let _ = s.read_to_end(&mut v).await;
                v
            })
            .await
            .unwrap_or_default();
            got == msg
        }));
    }
    let mut ok = 0;
    for t in tasks {
        if t.await.unwrap() {
            ok += 1;
        }
    }
    let status = a
        .ctl_ok(warren::node::control::ControlRequest::Status)
        .await;
    let errs = status["recent_errors"].to_string();
    assert_eq!(
        ok,
        n,
        "{} of {n} parallel connections failed with the peer already pinned; last error: {}",
        n - ok,
        &errs[errs.len().saturating_sub(200)..]
    );
}
