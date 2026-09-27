//! Wire protocol: frame layout, stream-open payloads, error codes and the JSON
//! messages used during authentication and on the control channel.
//!
//! Every binary WebSocket message carries exactly one frame:
//!
//! ```text
//! +---------+-------------+-------------+-----------------+
//! | type u8 | stream u32  | len u16     | payload (len)   |
//! +---------+-------------+-------------+-----------------+
//! ```
//!
//! Integers are big-endian. See `docs/protocol.md` for the full description.

use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Protocol version spoken by this build.
pub const PROTOCOL_VERSION: u32 = 1;
/// Frame header length in bytes.
pub const HEADER_LEN: usize = 7;
/// Maximum frame payload (the `len` field is a u16, so just under 64 KiB).
pub const MAX_PAYLOAD: usize = u16::MAX as usize;
/// Maximum size of one binary WebSocket message (one frame).
pub const MAX_WS_MESSAGE: usize = HEADER_LEN + MAX_PAYLOAD;
/// Per-stream receive window in bytes.
pub const STREAM_WINDOW: u32 = 256 * 1024;
/// Maximum number of concurrent streams per node connection.
pub const MAX_STREAMS_PER_NODE: usize = 1024;
/// Maximum stream opens per second per node.
pub const MAX_OPENS_PER_SEC: u32 = 64;
/// Maximum size of a JSON control message.
pub const MAX_CTRL_PAYLOAD: usize = MAX_PAYLOAD;

/// OPEN flag: the stream carries public (published) traffic terminated at the relay.
pub const FLAG_PUBLIC: u8 = 0x01;

/// Stream id used for connection-level frames (PING, PONG, CTRL).
pub const CONTROL_STREAM: u32 = 0;

/// Frame types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Open = 1,
    OpenOk = 2,
    OpenErr = 3,
    Data = 4,
    Window = 5,
    Close = 6,
    Ping = 7,
    Pong = 8,
    Ctrl = 9,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Option<FrameType> {
        Some(match v {
            1 => FrameType::Open,
            2 => FrameType::OpenOk,
            3 => FrameType::OpenErr,
            4 => FrameType::Data,
            5 => FrameType::Window,
            6 => FrameType::Close,
            7 => FrameType::Ping,
            8 => FrameType::Pong,
            9 => FrameType::Ctrl,
            _ => return None,
        })
    }
}

/// Protocol violations detected while decoding.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtoError {
    #[error("frame shorter than header")]
    Short,
    #[error("unknown frame type {0}")]
    UnknownType(u8),
    #[error("frame length field does not match message size")]
    LengthMismatch,
    #[error("frame payload too large")]
    TooLarge,
    #[error("malformed {0} payload")]
    Malformed(&'static str),
}

/// One multiplexing frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub ty: FrameType,
    pub stream: u32,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(ty: FrameType, stream: u32, payload: impl Into<Bytes>) -> Frame {
        Frame {
            ty,
            stream,
            payload: payload.into(),
        }
    }

    /// Serialize into one WebSocket message body.
    pub fn encode(&self) -> Bytes {
        debug_assert!(self.payload.len() <= MAX_PAYLOAD);
        let mut b = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        b.put_u8(self.ty as u8);
        b.put_u32(self.stream);
        b.put_u16(self.payload.len() as u16);
        b.extend_from_slice(&self.payload);
        b.freeze()
    }

    /// Parse one WebSocket message body. The `len` field must match exactly.
    pub fn decode(msg: Bytes) -> Result<Frame, ProtoError> {
        if msg.len() < HEADER_LEN {
            return Err(ProtoError::Short);
        }
        if msg.len() > MAX_WS_MESSAGE {
            return Err(ProtoError::TooLarge);
        }
        let ty = FrameType::from_u8(msg[0]).ok_or(ProtoError::UnknownType(msg[0]))?;
        let stream = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
        let len = u16::from_be_bytes([msg[5], msg[6]]) as usize;
        if len != msg.len() - HEADER_LEN {
            return Err(ProtoError::LengthMismatch);
        }
        Ok(Frame {
            ty,
            stream,
            payload: msg.slice(HEADER_LEN..),
        })
    }

    pub fn data(stream: u32, payload: Bytes) -> Frame {
        Frame::new(FrameType::Data, stream, payload)
    }

    pub fn window(stream: u32, credit: u32) -> Frame {
        Frame::new(
            FrameType::Window,
            stream,
            Bytes::copy_from_slice(&credit.to_be_bytes()),
        )
    }

    pub fn fin(stream: u32) -> Frame {
        Frame::new(FrameType::Close, stream, Bytes::new())
    }

    pub fn reset(stream: u32, code: ErrorCode) -> Frame {
        Frame::new(
            FrameType::Close,
            stream,
            Bytes::copy_from_slice(&[code as u8]),
        )
    }

    pub fn open_ok(stream: u32) -> Frame {
        Frame::new(FrameType::OpenOk, stream, Bytes::new())
    }

    pub fn open_err(stream: u32, code: ErrorCode, msg: &str) -> Frame {
        let mut b = BytesMut::with_capacity(1 + msg.len());
        b.put_u8(code as u8);
        let m = msg.as_bytes();
        b.extend_from_slice(&m[..m.len().min(1024)]);
        Frame::new(FrameType::OpenErr, stream, b.freeze())
    }

    pub fn ctrl(value: &impl Serialize) -> Frame {
        let v = serde_json::to_vec(value).unwrap_or_default();
        Frame::new(FrameType::Ctrl, CONTROL_STREAM, Bytes::from(v))
    }

    /// Parse a WINDOW payload.
    pub fn window_credit(&self) -> Result<u32, ProtoError> {
        if self.payload.len() != 4 {
            return Err(ProtoError::Malformed("WINDOW"));
        }
        Ok(u32::from_be_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
        ]))
    }

    /// Parse a CLOSE payload: `None` is a graceful FIN, `Some(code)` a reset.
    pub fn close_kind(&self) -> Option<ErrorCode> {
        self.payload.first().map(|c| ErrorCode::from_u8(*c))
    }

    /// Parse an OPEN_ERR payload.
    pub fn open_error(&self) -> (ErrorCode, String) {
        match self.payload.split_first() {
            Some((c, rest)) => (
                ErrorCode::from_u8(*c),
                String::from_utf8_lossy(rest).into_owned(),
            ),
            None => (ErrorCode::Internal, String::new()),
        }
    }
}

/// Error codes carried by OPEN_ERR and CLOSE(reset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ErrorCode {
    NoSuchNode = 1,
    NodeOffline = 2,
    NotShared = 3,
    Forbidden = 4,
    TooManyStreams = 5,
    RateLimited = 6,
    ConnectFailed = 7,
    KeyChanged = 8,
    NoSuchPublish = 9,
    BadRequest = 10,
    Internal = 11,
    Protocol = 12,
    WindowOverrun = 13,
    Aborted = 14,
    HandshakeFailed = 15,
    LinkClosed = 16,
}

impl ErrorCode {
    pub fn from_u8(v: u8) -> ErrorCode {
        match v {
            1 => ErrorCode::NoSuchNode,
            2 => ErrorCode::NodeOffline,
            3 => ErrorCode::NotShared,
            4 => ErrorCode::Forbidden,
            5 => ErrorCode::TooManyStreams,
            6 => ErrorCode::RateLimited,
            7 => ErrorCode::ConnectFailed,
            8 => ErrorCode::KeyChanged,
            9 => ErrorCode::NoSuchPublish,
            10 => ErrorCode::BadRequest,
            12 => ErrorCode::Protocol,
            13 => ErrorCode::WindowOverrun,
            14 => ErrorCode::Aborted,
            15 => ErrorCode::HandshakeFailed,
            16 => ErrorCode::LinkClosed,
            _ => ErrorCode::Internal,
        }
    }

    /// Stable machine-readable name.
    pub fn name(self) -> &'static str {
        match self {
            ErrorCode::NoSuchNode => "no_such_node",
            ErrorCode::NodeOffline => "node_offline",
            ErrorCode::NotShared => "not_shared",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::TooManyStreams => "too_many_streams",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::ConnectFailed => "connect_failed",
            ErrorCode::KeyChanged => "key_changed",
            ErrorCode::NoSuchPublish => "no_such_publish",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Internal => "internal",
            ErrorCode::Protocol => "protocol",
            ErrorCode::WindowOverrun => "window_overrun",
            ErrorCode::Aborted => "aborted",
            ErrorCode::HandshakeFailed => "handshake_failed",
            ErrorCode::LinkClosed => "link_closed",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Payload of an OPEN frame.
///
/// Nodes fill `flags`, `port` and `dest`. When the relay forwards a private
/// OPEN it fills `src` and `src_static` from its registry; these are *claims*
/// that the destination verifies through the Noise handshake. For public
/// streams the relay sets [`FLAG_PUBLIC`], `dest` is the published name and
/// `client` is the remote address of the public client.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenPayload {
    pub flags: u8,
    pub port: u16,
    pub dest: String,
    pub src: String,
    pub src_static: Option<[u8; 32]>,
    pub client: String,
}

impl OpenPayload {
    pub fn is_public(&self) -> bool {
        self.flags & FLAG_PUBLIC != 0
    }

    pub fn encode(&self) -> Bytes {
        let mut b = BytesMut::with_capacity(64);
        b.put_u8(self.flags);
        b.put_u16(self.port);
        put_short(&mut b, self.dest.as_bytes());
        put_short(&mut b, self.src.as_bytes());
        match &self.src_static {
            Some(k) => put_short(&mut b, k),
            None => b.put_u8(0),
        }
        put_short(&mut b, self.client.as_bytes());
        b.freeze()
    }

    pub fn decode(p: &[u8]) -> Result<OpenPayload, ProtoError> {
        let bad = ProtoError::Malformed("OPEN");
        if p.len() < 3 {
            return Err(bad);
        }
        let flags = p[0];
        let port = u16::from_be_bytes([p[1], p[2]]);
        let mut rest = &p[3..];
        let dest = get_short(&mut rest).ok_or(ProtoError::Malformed("OPEN"))?;
        let src = get_short(&mut rest).ok_or(ProtoError::Malformed("OPEN"))?;
        let key = get_short(&mut rest).ok_or(ProtoError::Malformed("OPEN"))?;
        let client = get_short(&mut rest).ok_or(ProtoError::Malformed("OPEN"))?;
        if !rest.is_empty() {
            return Err(bad);
        }
        let src_static = match key.len() {
            0 => None,
            32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                Some(k)
            }
            _ => return Err(bad),
        };
        let s = |v: &[u8]| String::from_utf8(v.to_vec()).map_err(|_| ProtoError::Malformed("OPEN"));
        Ok(OpenPayload {
            flags,
            port,
            dest: s(dest)?,
            src: s(src)?,
            src_static,
            client: s(client)?,
        })
    }
}

fn put_short(b: &mut BytesMut, v: &[u8]) {
    let n = v.len().min(255);
    b.put_u8(n as u8);
    b.extend_from_slice(&v[..n]);
}

fn get_short<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (&n, tail) = rest.split_first()?;
    let n = n as usize;
    if tail.len() < n {
        return None;
    }
    let (v, tail) = tail.split_at(n);
    *rest = tail;
    Some(v)
}

/// First message from the relay on a new node connection (WebSocket text).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayHello {
    Challenge {
        version: u32,
        /// 32 random bytes, hex.
        challenge: String,
    },
}

/// Node's answer to the challenge (WebSocket text).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeHello {
    /// Authenticate an enrolled node.
    Auth {
        version: u32,
        node_id: String,
        /// Ed25519 public key, hex.
        sign_pub: String,
        /// Signature over `"warren-v1-auth" || challenge || relay_host`, hex.
        signature: String,
    },
    /// Enroll a new node with a one-time code.
    Join {
        version: u32,
        code: String,
        name: Option<String>,
        sign_pub: String,
        static_pub: String,
        /// Signature over `"warren-v1-join" || challenge || relay_host || static_pub`, hex.
        signature: String,
    },
}

// Hand-written Debug for NodeHello would be needed if it ever carried secrets
// beyond the one-time code; the code is redacted by `redacted()`.
impl NodeHello {
    /// A copy safe to log (the enrollment code is removed).
    pub fn redacted(&self) -> NodeHello {
        match self {
            NodeHello::Join {
                version,
                name,
                sign_pub,
                static_pub,
                signature,
                ..
            } => NodeHello::Join {
                version: *version,
                code: "[redacted]".into(),
                name: name.clone(),
                sign_pub: sign_pub.clone(),
                static_pub: static_pub.clone(),
                signature: signature.clone(),
            },
            other => other.clone(),
        }
    }
}

/// Relay's verdict (WebSocket text). After `Welcome` the connection switches to
/// binary frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayVerdict {
    Welcome {
        node_id: String,
        name: String,
        publish_domain: String,
        relay_version: String,
    },
    Joined {
        node_id: String,
        name: String,
        publish_domain: String,
    },
    Error {
        code: String,
        message: String,
    },
}

/// Public view of a registered node, as returned by the relay registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceInfo {
    pub node_id: String,
    pub name: String,
    /// X25519 static key, hex.
    pub static_pub: String,
    /// Ed25519 key, hex.
    pub sign_pub: String,
    pub online: bool,
    pub last_seen: Option<i64>,
    pub created_at: i64,
}

impl DeviceInfo {
    pub fn static_key(&self) -> Option<[u8; 32]> {
        crate::crypto::parse_key32(&self.static_pub)
    }
}

/// Control request (node to relay), carried in CTRL frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtrlRequest {
    pub id: u64,
    #[serde(flatten)]
    pub op: CtrlOp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CtrlOp {
    Devices,
    Lookup {
        name: String,
    },
    Publish {
        name: String,
        #[serde(default)]
        replace: bool,
        #[serde(default)]
        reclaim: bool,
        #[serde(default)]
        allow: Vec<String>,
    },
    Unpublish {
        name: String,
    },
    Publishes,
}

/// Control response (relay to node).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtrlResponse {
    pub id: u64,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub result: serde_json::Value,
}

/// Relay-pushed event (no id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtrlEvent {
    pub event: String,
    #[serde(default)]
    pub detail: serde_json::Value,
}

/// Sanity limits on CTRL JSON size.
pub fn ctrl_payload_ok(p: &[u8]) -> bool {
    p.len() <= MAX_CTRL_PAYLOAD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let f = Frame::data(7, Bytes::from_static(b"hello"));
        let enc = f.encode();
        assert_eq!(enc.len(), HEADER_LEN + 5);
        assert_eq!(enc[0], FrameType::Data as u8);
        let d = Frame::decode(enc).unwrap();
        assert_eq!(d, f);
    }

    #[test]
    fn frame_max_payload() {
        let f = Frame::data(1, Bytes::from(vec![7u8; MAX_PAYLOAD]));
        let enc = f.encode();
        assert_eq!(enc.len(), MAX_WS_MESSAGE);
        assert_eq!(Frame::decode(enc).unwrap().payload.len(), MAX_PAYLOAD);
    }

    #[test]
    fn frame_rejects_bad_input() {
        assert_eq!(
            Frame::decode(Bytes::from_static(b"\x04\0\0")),
            Err(ProtoError::Short)
        );
        assert_eq!(
            Frame::decode(Bytes::from_static(b"\x63\0\0\0\x01\0\0")),
            Err(ProtoError::UnknownType(0x63))
        );
        // len says 5 but only 2 bytes follow
        assert_eq!(
            Frame::decode(Bytes::from_static(b"\x04\0\0\0\x01\0\x05ab")),
            Err(ProtoError::LengthMismatch)
        );
        // trailing garbage beyond len
        assert_eq!(
            Frame::decode(Bytes::from_static(b"\x04\0\0\0\x01\0\x01abc")),
            Err(ProtoError::LengthMismatch)
        );
        let big = vec![4u8; MAX_WS_MESSAGE + 1];
        assert_eq!(Frame::decode(Bytes::from(big)), Err(ProtoError::TooLarge));
    }

    #[test]
    fn window_close_openerr() {
        let w = Frame::window(3, 12345);
        assert_eq!(
            Frame::decode(w.encode()).unwrap().window_credit().unwrap(),
            12345
        );
        assert!(Frame::fin(3).close_kind().is_none());
        assert_eq!(
            Frame::reset(3, ErrorCode::WindowOverrun).close_kind(),
            Some(ErrorCode::WindowOverrun)
        );
        let e = Frame::open_err(5, ErrorCode::NotShared, "port 22 is not shared");
        assert_eq!(
            e.open_error(),
            (ErrorCode::NotShared, "port 22 is not shared".to_string())
        );
        for c in 1..=16u8 {
            let code = ErrorCode::from_u8(c);
            if c != 11 {
                assert_eq!(code as u8, c);
            }
            assert!(!code.name().is_empty());
        }
    }

    #[test]
    fn open_payload_roundtrip() {
        let p = OpenPayload {
            flags: 0,
            port: 22,
            dest: "b".into(),
            src: "a".into(),
            src_static: Some([9u8; 32]),
            client: String::new(),
        };
        assert_eq!(OpenPayload::decode(&p.encode()).unwrap(), p);
        let q = OpenPayload {
            flags: FLAG_PUBLIC,
            port: 0,
            dest: "web".into(),
            src: String::new(),
            src_static: None,
            client: "203.0.113.9:5555".into(),
        };
        let d = OpenPayload::decode(&q.encode()).unwrap();
        assert!(d.is_public());
        assert_eq!(d, q);
        assert!(OpenPayload::decode(&[0, 0]).is_err());
        let mut bad = p.encode().to_vec();
        bad.push(1);
        assert!(OpenPayload::decode(&bad).is_err());
        // key of wrong length
        let mut wrong = vec![0u8, 0, 22, 1, b'b', 0, 3, 1, 2, 3, 0];
        assert!(OpenPayload::decode(&wrong).is_err());
        wrong.truncate(4);
        assert!(OpenPayload::decode(&wrong).is_err());
    }

    #[test]
    fn ctrl_json_shape() {
        let r = CtrlRequest {
            id: 4,
            op: CtrlOp::Publish {
                name: "web".into(),
                replace: true,
                reclaim: false,
                allow: vec!["10.0.0.0/8".into()],
            },
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"op\":\"publish\""));
        let back: CtrlRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, 4);
        let hello = NodeHello::Join {
            version: 1,
            code: "SECRETCODE".into(),
            name: None,
            sign_pub: "aa".into(),
            static_pub: "bb".into(),
            signature: "cc".into(),
        };
        assert!(!format!("{:?}", hello.redacted()).contains("SECRETCODE"));
    }
}
