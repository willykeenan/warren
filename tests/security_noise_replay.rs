//! A relay replaying a recorded private-stream opening cannot make the
//! destination connect to its local service.
//!
//! Noise IK message 1 carries no contribution from the responder, so the
//! responder cannot tell a replayed message 1 from a fresh one. The
//! destination therefore connects to `127.0.0.1:PORT` only after the opener
//! has confirmed the handshake with its first transport message, which a
//! relay without the opener's keys cannot produce.

mod common;

use common::*;
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::tungstenite::Message;
use warren::mux::TapDir;
use warren::proto::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_handshake_does_not_reach_the_local_service() {
    // 1. A real session a -> b through an honest relay, recorded by the relay.
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let mut b = enroll_started(&relay, "b").await;
    let (echo, accepts) = echo_server().await;
    b.share(echo, Some(vec!["a".into()]));
    let local = a.forward("b", echo).await;
    assert_eq!(echo_roundtrip(local, b"legit").await, b"legit");
    assert_eq!(accepts.load(Ordering::SeqCst), 1);

    // What the relay sent to b: the forwarded OPEN and handshake message 1.
    let frames: Vec<Frame> = relay
        .captures
        .lock()
        .unwrap()
        .iter()
        .filter(|(d, _)| *d == TapDir::Out)
        .filter_map(|(_, m)| Frame::decode(bytes::Bytes::from(m.clone())).ok())
        .collect();
    let open = frames
        .iter()
        .find(|f| {
            f.ty == FrameType::Open
                && f.stream % 2 == 0
                && OpenPayload::decode(&f.payload).is_ok_and(|p| p.src == "a" && p.port == echo)
        })
        .expect("recorded OPEN to b")
        .clone();
    let msg1 = frames
        .iter()
        .find(|f| f.ty == FrameType::Data && f.stream == open.stream)
        .expect("recorded handshake message 1")
        .clone();

    // 2. The relay turns hostile (modelled by pointing b at a fake relay that
    // only has the recorded bytes, no keys of any node). a is gone.
    let mut a = a;
    a.stop().await;
    b.stop().await;
    let dir = tempfile::tempdir().unwrap();
    let (ck, pin) = warren::tls::persistent_self_signed(dir.path(), &["127.0.0.1".into()]).unwrap();
    let resolver = std::sync::Arc::new(warren::tls::CertResolver::new());
    resolver.set_default(ck);
    let acceptor = tokio_rustls::TlsAcceptor::from(warren::tls::server_config(resolver).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    repoint(&b, &format!("https://127.0.0.1:{}", addr.port()), &pin);
    b.start_with(|c| c.ping_interval = Duration::from_secs(60))
        .await;
    let (tcp, _) = listener.accept().await.unwrap();
    let tls = acceptor.accept(tcp).await.unwrap();
    let mut conn = warren::http::BufConn::new(tls, None);
    let req = conn.read_request(32 * 1024).await.unwrap().unwrap();
    let key = req.header("sec-websocket-key").unwrap().to_vec();
    conn.inner
        .write_all(warren::ws::upgrade_response(&key).as_bytes())
        .await
        .unwrap();
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        conn.inner,
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        None,
    )
    .await;
    let hello = RelayHello::Challenge {
        version: PROTOCOL_VERSION,
        challenge: hex::encode([7u8; 32]),
    };
    ws.send(Message::text(serde_json::to_string(&hello).unwrap()))
        .await
        .unwrap();
    let _auth = ws.next().await.unwrap().unwrap();
    let welcome = RelayVerdict::Welcome {
        node_id: b.ident().node_id,
        name: "b".into(),
        publish_domain: "x".into(),
        relay_version: "evil".into(),
    };
    ws.send(Message::text(serde_json::to_string(&welcome).unwrap()))
        .await
        .unwrap();
    assert!(b.d().wait_connected(Duration::from_secs(5)).await);

    // 3. Replay the recording several times on fresh stream ids.
    const REPLAYS: u32 = 5;
    for i in 0..REPLAYS {
        let id = 1000 + 2 * i;
        ws.send(Message::Binary(
            Frame::new(FrameType::Open, id, open.payload.clone()).encode(),
        ))
        .await
        .unwrap();
        ws.send(Message::Binary(
            Frame::data(id, msg1.payload.clone()).encode(),
        ))
        .await
        .unwrap();
    }
    // Collect b's answers.
    let mut handshake_replies = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while let Ok(Some(Ok(m))) = tokio::time::timeout_at(deadline, ws.next()).await {
        if let Message::Binary(bin) = m {
            if let Ok(f) = Frame::decode(bin) {
                if f.stream >= 1000 && f.ty == FrameType::Data {
                    handshake_replies += 1;
                }
            }
        }
    }
    let extra = accepts.load(Ordering::SeqCst) - 1;
    assert_eq!(
        extra, 0,
        "a relay holding no keys replayed one recorded handshake {REPLAYS} times: b answered \
         {handshake_replies} of them with handshake message 2 and opened {extra} new \
         connections to its local service on a's behalf (a is not even running)"
    );
}
