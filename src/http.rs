//! Minimal, strict HTTP/1.1 message handling for the relay: bounded request
//! heads, body framing (Content-Length, chunked, close-delimited) and header
//! rewriting. Bodies are streamed, never buffered whole.

use bytes::{Bytes, BytesMut};
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::limits::MAX_HEADERS;
use crate::mux::MuxSender;
use crate::proto::MAX_PAYLOAD;

/// Maximum length of a chunk-size line.
const MAX_CHUNK_LINE: usize = 4096;
/// Maximum total size of chunked trailers.
const MAX_TRAILERS: usize = 32 * 1024;
/// Read granularity.
const READ_CHUNK: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
    #[error("message head too large")]
    TooLarge,
    #[error("malformed message: {0}")]
    Malformed(&'static str),
    #[error("connection closed mid-message")]
    Truncated,
}

/// Last-activity clock shared by both directions of a proxied connection.
#[derive(Debug)]
pub struct Activity {
    start: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    pub fn new() -> Arc<Activity> {
        Arc::new(Activity {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
        })
    }

    pub fn touch(&self) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    pub fn idle_for(&self) -> std::time::Duration {
        let now = self.start.elapsed().as_millis() as u64;
        std::time::Duration::from_millis(now.saturating_sub(self.last_ms.load(Ordering::Relaxed)))
    }
}

/// A reader with a buffer, used to parse heads and frame bodies.
pub struct BufConn<R> {
    pub inner: R,
    pub buf: BytesMut,
    activity: Option<Arc<Activity>>,
}

impl<R: AsyncRead + Unpin> BufConn<R> {
    pub fn new(inner: R, activity: Option<Arc<Activity>>) -> BufConn<R> {
        BufConn {
            inner,
            buf: BytesMut::with_capacity(8192),
            activity,
        }
    }

    /// Read more bytes into the buffer; returns the number read (0 at EOF).
    pub async fn fill(&mut self) -> io::Result<usize> {
        self.buf.reserve(READ_CHUNK);
        let n = self.inner.read_buf(&mut self.buf).await?;
        if n > 0 {
            if let Some(a) = &self.activity {
                a.touch();
            }
        }
        Ok(n)
    }

    /// Wait until at least one byte is buffered. False at EOF.
    pub async fn wait_readable(&mut self) -> io::Result<bool> {
        while self.buf.is_empty() {
            if self.fill().await? == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Read a `\r\n`-terminated line of at most `max` bytes (including CRLF).
    pub async fn read_line(&mut self, max: usize) -> Result<Bytes, HttpError> {
        let mut scanned = 0;
        loop {
            if let Some(pos) = self.buf[scanned..].iter().position(|b| *b == b'\n') {
                let end = scanned + pos + 1;
                if end < 2 || self.buf[end - 2] != b'\r' {
                    return Err(HttpError::Malformed("bare LF"));
                }
                if end > max {
                    return Err(HttpError::TooLarge);
                }
                return Ok(self.buf.split_to(end).freeze());
            }
            scanned = self.buf.len();
            if scanned > max {
                return Err(HttpError::TooLarge);
            }
            if self.fill().await? == 0 {
                return Err(HttpError::Truncated);
            }
        }
    }

    /// Read and parse a request head of at most `max` bytes. `Ok(None)` if the
    /// peer closed cleanly before sending anything.
    pub async fn read_request(&mut self, max: usize) -> Result<Option<Request>, HttpError> {
        loop {
            // Tolerate stray CRLFs between keep-alive requests (RFC 9112 2.2).
            while self.buf.starts_with(b"\r\n") {
                let _ = self.buf.split_to(2);
            }
            if !self.buf.is_empty() {
                let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
                let mut req = httparse::Request::new(&mut headers);
                match req.parse(&self.buf) {
                    Ok(httparse::Status::Complete(n)) => {
                        if n > max {
                            return Err(HttpError::TooLarge);
                        }
                        let parsed = Request::from_parsed(&req)?;
                        let _ = self.buf.split_to(n);
                        return Ok(Some(parsed));
                    }
                    Ok(httparse::Status::Partial) => {
                        if self.buf.len() > max {
                            return Err(HttpError::TooLarge);
                        }
                    }
                    Err(httparse::Error::TooManyHeaders) => return Err(HttpError::TooLarge),
                    Err(_) => return Err(HttpError::Malformed("request head")),
                }
            }
            if self.fill().await? == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(HttpError::Truncated)
                };
            }
        }
    }

    /// Read and parse a response head.
    pub async fn read_response(&mut self, max: usize) -> Result<Response, HttpError> {
        loop {
            if !self.buf.is_empty() {
                let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
                let mut resp = httparse::Response::new(&mut headers);
                match resp.parse(&self.buf) {
                    Ok(httparse::Status::Complete(n)) => {
                        let parsed = Response::from_parsed(&resp, &self.buf[..n])?;
                        let _ = self.buf.split_to(n);
                        return Ok(parsed);
                    }
                    Ok(httparse::Status::Partial) => {}
                    Err(httparse::Error::TooManyHeaders) => return Err(HttpError::TooLarge),
                    Err(_) => return Err(HttpError::Malformed("response head")),
                }
                if self.buf.len() > max {
                    return Err(HttpError::TooLarge);
                }
            }
            if self.fill().await? == 0 {
                return Err(HttpError::Truncated);
            }
        }
    }

    /// Stream exactly `n` body bytes into `sink`.
    pub async fn copy_exact<S: ByteSink>(
        &mut self,
        mut n: u64,
        sink: &mut S,
    ) -> Result<(), HttpError> {
        while n > 0 {
            if self.buf.is_empty() && self.fill().await? == 0 {
                return Err(HttpError::Truncated);
            }
            let take = (self.buf.len() as u64).min(n) as usize;
            let chunk = self.buf.split_to(take).freeze();
            n -= take as u64;
            sink.put(chunk).await?;
        }
        Ok(())
    }

    /// Stream a chunked body (including trailers) into `sink`, validating framing.
    pub async fn copy_chunked<S: ByteSink>(&mut self, sink: &mut S) -> Result<(), HttpError> {
        loop {
            let line = self.read_line(MAX_CHUNK_LINE).await?;
            let size = parse_chunk_size(&line)?;
            sink.put(line).await?;
            if size == 0 {
                let mut total = 0usize;
                loop {
                    let t = self.read_line(MAX_CHUNK_LINE).await?;
                    total += t.len();
                    if total > MAX_TRAILERS {
                        return Err(HttpError::TooLarge);
                    }
                    let end = t.as_ref() == b"\r\n";
                    sink.put(t).await?;
                    if end {
                        return Ok(());
                    }
                }
            }
            self.copy_exact(size, sink).await?;
            let crlf = self.read_line(2).await?;
            if crlf.as_ref() != b"\r\n" {
                return Err(HttpError::Malformed("chunk terminator"));
            }
            sink.put(crlf).await?;
        }
    }

    /// Stream everything until EOF into `sink`.
    pub async fn copy_to_eof<S: ByteSink>(&mut self, sink: &mut S) -> Result<(), HttpError> {
        loop {
            if !self.buf.is_empty() {
                let chunk = self.buf.split().freeze();
                sink.put(chunk).await?;
            }
            if self.fill().await? == 0 {
                return Ok(());
            }
        }
    }

    /// Copy a body described by `kind`.
    pub async fn copy_body<S: ByteSink>(
        &mut self,
        kind: BodyKind,
        sink: &mut S,
    ) -> Result<(), HttpError> {
        match kind {
            BodyKind::None => Ok(()),
            BodyKind::Length(n) => self.copy_exact(n, sink).await,
            BodyKind::Chunked => self.copy_chunked(sink).await,
            BodyKind::UntilClose => self.copy_to_eof(sink).await,
        }
    }
}

fn parse_chunk_size(line: &[u8]) -> Result<u64, HttpError> {
    let body = &line[..line.len() - 2];
    let hex_part = match body.iter().position(|b| *b == b';') {
        Some(p) => &body[..p],
        None => body,
    };
    // Allow optional whitespace before extensions, nothing else.
    let hex_part = trim_ows(hex_part);
    if hex_part.is_empty() || hex_part.len() > 15 || !hex_part.iter().all(|b| b.is_ascii_hexdigit())
    {
        return Err(HttpError::Malformed("chunk size"));
    }
    let s = std::str::from_utf8(hex_part).map_err(|_| HttpError::Malformed("chunk size"))?;
    u64::from_str_radix(s, 16).map_err(|_| HttpError::Malformed("chunk size"))
}

fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }
    v
}

/// How a message body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

/// A parsed request head.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// Minor version: 0 or 1.
    pub version: u8,
    pub headers: Vec<(String, Vec<u8>)>,
}

fn has_token(value: &[u8], token: &str) -> bool {
    String::from_utf8_lossy(value)
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

impl Request {
    fn from_parsed(r: &httparse::Request<'_, '_>) -> Result<Request, HttpError> {
        let method = r.method.ok_or(HttpError::Malformed("method"))?.to_string();
        let path = r.path.ok_or(HttpError::Malformed("target"))?.to_string();
        let version = r.version.ok_or(HttpError::Malformed("version"))?;
        let headers = r
            .headers
            .iter()
            .map(|h| (h.name.to_string(), h.value.to_vec()))
            .collect();
        Ok(Request {
            method,
            path,
            version,
            headers,
        })
    }

    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    pub fn header_str(&self, name: &str) -> Option<String> {
        self.header(name)
            .map(|v| String::from_utf8_lossy(v).trim().to_string())
    }

    fn count(&self, name: &str) -> usize {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .count()
    }

    /// Host without port, lower-case.
    pub fn host(&self) -> Option<String> {
        let h = self.header_str("host")?;
        Some(strip_port(&h).to_ascii_lowercase())
    }

    /// Validate framing headers strictly (request smuggling defenses) and
    /// return how the body is delimited.
    pub fn body_kind(&self) -> Result<BodyKind, HttpError> {
        if self.count("host") > 1 {
            return Err(HttpError::Malformed("multiple Host headers"));
        }
        if self.version == 1 && self.count("host") == 0 {
            return Err(HttpError::Malformed("missing Host"));
        }
        let te = self.count("transfer-encoding");
        let cl = self.count("content-length");
        if te > 0 {
            if cl > 0 {
                return Err(HttpError::Malformed(
                    "both Transfer-Encoding and Content-Length",
                ));
            }
            if te > 1 || self.version == 0 {
                return Err(HttpError::Malformed("Transfer-Encoding"));
            }
            let v = self.header_str("transfer-encoding").unwrap_or_default();
            if !v.eq_ignore_ascii_case("chunked") {
                return Err(HttpError::Malformed("unsupported Transfer-Encoding"));
            }
            return Ok(BodyKind::Chunked);
        }
        if cl > 0 {
            let mut value: Option<u64> = None;
            for (n, v) in &self.headers {
                if !n.eq_ignore_ascii_case("content-length") {
                    continue;
                }
                let n = parse_content_length(v)?;
                if value.is_some_and(|x| x != n) {
                    return Err(HttpError::Malformed("conflicting Content-Length"));
                }
                value = Some(n);
            }
            return Ok(match value {
                Some(0) | None => BodyKind::None,
                Some(n) => BodyKind::Length(n),
            });
        }
        Ok(BodyKind::None)
    }

    /// True for a protocol upgrade request (e.g. WebSocket).
    pub fn is_upgrade(&self) -> bool {
        self.header("upgrade").is_some()
            && self
                .headers
                .iter()
                .any(|(n, v)| n.eq_ignore_ascii_case("connection") && has_token(v, "upgrade"))
    }

    pub fn is_websocket_upgrade(&self) -> bool {
        self.is_upgrade()
            && self
                .header_str("upgrade")
                .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
    }

    /// Whether the client asked to close after this request.
    pub fn wants_close(&self) -> bool {
        let conn = self
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("connection"));
        let mut close = false;
        let mut keep = false;
        for (_, v) in conn {
            close |= has_token(v, "close");
            keep |= has_token(v, "keep-alive");
        }
        close || (self.version == 0 && !keep)
    }

    /// Serialize with the named headers removed (case-insensitive) and extra
    /// headers appended.
    pub fn encode(&self, remove: &[&str], add: &[(&str, String)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(self.method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.path.as_bytes());
        out.extend_from_slice(if self.version == 0 {
            b" HTTP/1.0\r\n"
        } else {
            b" HTTP/1.1\r\n"
        });
        for (n, v) in &self.headers {
            if remove.iter().any(|r| n.eq_ignore_ascii_case(r)) {
                continue;
            }
            out.extend_from_slice(n.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v);
            out.extend_from_slice(b"\r\n");
        }
        for (n, v) in add {
            out.extend_from_slice(n.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out
    }
}

fn parse_content_length(v: &[u8]) -> Result<u64, HttpError> {
    let s = std::str::from_utf8(v)
        .map_err(|_| HttpError::Malformed("Content-Length"))?
        .trim();
    if s.is_empty() || s.len() > 18 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HttpError::Malformed("Content-Length"));
    }
    s.parse()
        .map_err(|_| HttpError::Malformed("Content-Length"))
}

/// Strip a `:port` suffix from a Host value (handles IPv6 literals).
pub fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match host.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    }
}

/// A parsed response head; `raw` is forwarded unchanged.
#[derive(Debug, Clone)]
pub struct Response {
    pub code: u16,
    pub version: u8,
    pub headers: Vec<(String, Vec<u8>)>,
    pub raw: Bytes,
}

impl Response {
    fn from_parsed(r: &httparse::Response<'_, '_>, raw: &[u8]) -> Result<Response, HttpError> {
        Ok(Response {
            code: r.code.ok_or(HttpError::Malformed("status"))?,
            version: r.version.ok_or(HttpError::Malformed("version"))?,
            headers: r
                .headers
                .iter()
                .map(|h| (h.name.to_string(), h.value.to_vec()))
                .collect(),
            raw: Bytes::copy_from_slice(raw),
        })
    }

    fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    /// Body framing for this response to a request with `method`.
    pub fn body_kind(&self, method: &str) -> Result<BodyKind, HttpError> {
        if method.eq_ignore_ascii_case("HEAD")
            || (100..200).contains(&self.code)
            || self.code == 204
            || self.code == 304
        {
            return Ok(BodyKind::None);
        }
        if let Some(te) = self.header("transfer-encoding") {
            let last = String::from_utf8_lossy(te)
                .rsplit(',')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            return Ok(if last == "chunked" {
                BodyKind::Chunked
            } else {
                BodyKind::UntilClose
            });
        }
        if let Some(cl) = self.header("content-length") {
            return Ok(match parse_content_length(cl)? {
                0 => BodyKind::None,
                n => BodyKind::Length(n),
            });
        }
        Ok(BodyKind::UntilClose)
    }

    /// Whether the connection ends after this response.
    pub fn closes(&self) -> bool {
        let mut close = false;
        let mut keep = false;
        for (n, v) in &self.headers {
            if n.eq_ignore_ascii_case("connection") {
                close |= has_token(v, "close");
                keep |= has_token(v, "keep-alive");
            }
        }
        close || (self.version == 0 && !keep)
    }
}

/// Destination for streamed body bytes.
pub trait ByteSink: Send {
    fn put(&mut self, data: Bytes) -> impl Future<Output = io::Result<()>> + Send;
}

/// Sink writing into a multiplexed stream (split into frames).
pub struct MuxSink<'a>(pub &'a MuxSender);

impl ByteSink for MuxSink<'_> {
    async fn put(&mut self, data: Bytes) -> io::Result<()> {
        let mut data = data;
        while !data.is_empty() {
            let n = data.len().min(MAX_PAYLOAD);
            self.0.send(data.split_to(n)).await?;
        }
        Ok(())
    }
}

/// Sink writing into any async writer.
pub struct WriteSink<W>(pub W);

impl<W: AsyncWrite + Unpin + Send> ByteSink for WriteSink<W> {
    async fn put(&mut self, data: Bytes) -> io::Result<()> {
        self.0.write_all(&data).await?;
        // TLS can accept plaintext while its ciphertext is still buffered by
        // socket backpressure. Flush before waiting for more upstream input.
        self.0.flush().await
    }
}

/// A simple complete response with a text body (relay-generated errors).
pub fn simple_response(code: u16, reason: &str, body: &str, close: bool) -> Vec<u8> {
    format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n{}Cache-Control: no-store\r\n\r\n{body}",
        body.len(),
        if close { "Connection: close\r\n" } else { "" }
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VecSink(Vec<u8>);
    impl ByteSink for VecSink {
        fn put(&mut self, data: Bytes) -> impl Future<Output = io::Result<()>> + Send {
            self.0.extend_from_slice(&data);
            async { Ok(()) }
        }
    }

    fn conn(data: &'static [u8]) -> BufConn<&'static [u8]> {
        BufConn::new(data, None)
    }

    #[tokio::test]
    async fn parse_request_and_rewrite() {
        let mut c = conn(b"GET /x HTTP/1.1\r\nHost: App.Example:443\r\nX-Forwarded-For: 6.6.6.6\r\nx-forwarded-proto: http\r\nForwarded: for=1.2.3.4\r\nAccept: */*\r\n\r\nrest");
        let r = c.read_request(32 * 1024).await.unwrap().unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.host().unwrap(), "app.example");
        assert_eq!(r.body_kind().unwrap(), BodyKind::None);
        let out = r.encode(
            &["x-forwarded-for", "x-forwarded-proto", "forwarded"],
            &[("X-Forwarded-For", "203.0.113.7".into())],
        );
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("6.6.6.6"));
        assert!(!s.contains("1.2.3.4"));
        assert!(!s.to_ascii_lowercase().contains("proto: http"));
        assert!(s.contains("X-Forwarded-For: 203.0.113.7\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
        assert_eq!(&c.buf[..], b"rest");
    }

    #[tokio::test]
    async fn smuggling_defenses() {
        let cases: &[&[u8]] = &[
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1 2\r\n\r\n",
            b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"GET / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        ];
        for raw in cases {
            let mut c = conn(raw);
            let r = c.read_request(32 * 1024).await.unwrap().unwrap();
            assert!(r.body_kind().is_err(), "{}", String::from_utf8_lossy(raw));
        }
        let mut c =
            conn(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n");
        let r = c.read_request(1024).await.unwrap().unwrap();
        assert_eq!(r.body_kind().unwrap(), BodyKind::Length(3));
    }

    #[tokio::test]
    async fn head_size_limit() {
        let mut big = b"GET / HTTP/1.1\r\nHost: a\r\nX-Big: ".to_vec();
        big.extend(std::iter::repeat_n(b'a', 40 * 1024));
        big.extend_from_slice(b"\r\n\r\n");
        let leaked: &'static [u8] = Box::leak(big.into_boxed_slice());
        let mut c = conn(leaked);
        assert!(matches!(
            c.read_request(32 * 1024).await,
            Err(HttpError::TooLarge)
        ));
        // Just under the limit is fine.
        let mut ok = b"GET / HTTP/1.1\r\nHost: a\r\nX-Big: ".to_vec();
        ok.extend(std::iter::repeat_n(b'a', 30 * 1024));
        ok.extend_from_slice(b"\r\n\r\n");
        let leaked: &'static [u8] = Box::leak(ok.into_boxed_slice());
        let mut c = conn(leaked);
        assert!(c.read_request(32 * 1024).await.unwrap().is_some());
        // Clean EOF.
        let mut c = conn(b"");
        assert!(c.read_request(1024).await.unwrap().is_none());
        let mut c = conn(b"GET / HT");
        assert!(matches!(
            c.read_request(1024).await,
            Err(HttpError::Truncated)
        ));
    }

    #[tokio::test]
    async fn chunked_copy() {
        let mut c = conn(b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nTrailer: x\r\n\r\nNEXT");
        let mut s = VecSink(Vec::new());
        c.copy_chunked(&mut s).await.unwrap();
        assert_eq!(
            s.0,
            b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nTrailer: x\r\n\r\n".to_vec()
        );
        assert_eq!(&c.buf[..], b"NEXT");
        for bad in [
            &b"zz\r\nhello\r\n0\r\n\r\n"[..],
            b"5\r\nhelloXX0\r\n\r\n",
            b"5\nhello\r\n0\r\n\r\n",
            b"5\r\nhel",
        ] {
            let mut c = BufConn::new(bad, None);
            let mut s = VecSink(Vec::new());
            assert!(c.copy_chunked(&mut s).await.is_err());
        }
    }

    #[tokio::test]
    async fn responses() {
        let mut c = conn(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
        let r = c.read_response(1024).await.unwrap();
        assert_eq!(r.code, 200);
        assert_eq!(r.body_kind("GET").unwrap(), BodyKind::Length(2));
        assert_eq!(r.body_kind("HEAD").unwrap(), BodyKind::None);
        assert!(!r.closes());
        let mut c = conn(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
        let r = c.read_response(1024).await.unwrap();
        assert_eq!(r.code, 101);
        let mut c = conn(b"HTTP/1.0 200 OK\r\n\r\nbody");
        let r = c.read_response(1024).await.unwrap();
        assert_eq!(r.body_kind("GET").unwrap(), BodyKind::UntilClose);
        assert!(r.closes());
        let mut c = conn(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(
            c.read_response(1024)
                .await
                .unwrap()
                .body_kind("GET")
                .unwrap(),
            BodyKind::Chunked
        );
    }

    #[test]
    fn helpers() {
        assert_eq!(strip_port("a.b:8080"), "a.b");
        assert_eq!(strip_port("a.b"), "a.b");
        assert_eq!(strip_port("[::1]:80"), "::1");
        let r = Request {
            method: "GET".into(),
            path: "/".into(),
            version: 1,
            headers: vec![
                ("Connection".into(), b"keep-alive, Upgrade".to_vec()),
                ("Upgrade".into(), b"websocket".to_vec()),
            ],
        };
        assert!(r.is_upgrade());
        assert!(r.is_websocket_upgrade());
        assert!(!r.wants_close());
        let r10 = Request {
            version: 0,
            headers: vec![],
            ..r.clone()
        };
        assert!(r10.wants_close());
        assert!(
            String::from_utf8(simple_response(404, "Not Found", "nope", true))
                .unwrap()
                .contains("Content-Length: 4")
        );
        let a = Activity::new();
        a.touch();
        assert!(a.idle_for() < std::time::Duration::from_secs(1));
    }
}
