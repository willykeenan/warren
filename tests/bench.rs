//! Loopback performance of a private link (relay + two nodes, all in-process,
//! full TLS + Noise). Ignored by default; run with:
//!
//! ```text
//! cargo test --release --test bench -- --ignored --nocapture
//! ```
//!
//! Targets: at least 200 Mbit/s and less than 2 ms of added median latency.

mod common;

use common::*;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Reads until EOF, then answers with the byte count.
async fn sink_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 256 * 1024];
                let mut total: u64 = 0;
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => total += n as u64,
                    }
                }
                let _ = s.write_all(&total.to_be_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    port
}

async fn push(port: u16, bytes: u64) -> Duration {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.set_nodelay(true).unwrap();
    let chunk = vec![0x5au8; 256 * 1024];
    let t0 = Instant::now();
    let mut sent = 0u64;
    while sent < bytes {
        let n = chunk.len().min((bytes - sent) as usize);
        s.write_all(&chunk[..n]).await.unwrap();
        sent += n as u64;
    }
    s.shutdown().await.unwrap();
    let mut ack = [0u8; 8];
    s.read_exact(&mut ack).await.unwrap();
    assert_eq!(u64::from_be_bytes(ack), bytes);
    t0.elapsed()
}

async fn rtts(port: u16, n: usize) -> Vec<Duration> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.set_nodelay(true).unwrap();
    let mut b = [0u8; 1];
    // warm up
    for _ in 0..50 {
        s.write_all(b"x").await.unwrap();
        s.read_exact(&mut b).await.unwrap();
    }
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        s.write_all(b"x").await.unwrap();
        s.read_exact(&mut b).await.unwrap();
        v.push(t0.elapsed());
    }
    v.sort();
    v
}

fn pct(v: &[Duration], p: f64) -> Duration {
    v[((v.len() - 1) as f64 * p) as usize]
}

async fn nodelay_echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let _ = s.set_nodelay(true);
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "benchmark; run with --release -- --ignored --nocapture"]
async fn loopback_throughput_and_latency() {
    let relay = start_relay_with(|c| c.tap = None).await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let sink = sink_server().await;
    let echo = nodelay_echo().await;
    b.share(sink, None);
    b.share(echo, None);
    let sink_fwd = a.forward("b", sink).await;
    let echo_fwd = a.forward("b", echo).await;
    let _ = push(sink_fwd, 1 << 20).await;

    // Throughput: best of three 512 MiB transfers through the link.
    let bytes: u64 = 512 * 1024 * 1024;
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let d = push(sink_fwd, bytes).await;
        best = best.min(d);
    }
    let mbit = bytes as f64 * 8.0 / best.as_secs_f64() / 1e6;
    let direct = push(sink, bytes).await;
    let direct_mbit = bytes as f64 * 8.0 / direct.as_secs_f64() / 1e6;

    // Latency: 1-byte ping-pong.
    let via = rtts(echo_fwd, 2000).await;
    let base = rtts(echo, 2000).await;
    let added = pct(&via, 0.5).saturating_sub(pct(&base, 0.5));

    println!("--- warren loopback benchmark ---");
    println!("throughput via private link: {mbit:.0} Mbit/s (best of 3 x 512 MiB)");
    println!("throughput direct loopback:  {direct_mbit:.0} Mbit/s");
    println!(
        "rtt via link: p50 {:?} p90 {:?} p99 {:?}",
        pct(&via, 0.5),
        pct(&via, 0.9),
        pct(&via, 0.99)
    );
    println!(
        "rtt direct:   p50 {:?} p90 {:?} p99 {:?}",
        pct(&base, 0.5),
        pct(&base, 0.9),
        pct(&base, 0.99)
    );
    println!("added median latency: {added:?}");
    assert!(
        mbit >= 200.0,
        "throughput {mbit:.0} Mbit/s below 200 Mbit/s"
    );
    assert!(added < Duration::from_millis(2), "added latency {added:?}");
}
