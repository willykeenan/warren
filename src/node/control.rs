//! The CLI talks to the running daemon over a Unix socket inside the node's
//! 0700 home directory. Requests and responses are single JSON lines; after a
//! successful `open`, the socket becomes a raw byte pipe to the remote port.

use super::NodePaths;
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

/// Maximum size of one request line (what the daemon accepts from a client).
pub const MAX_LINE: u64 = 64 * 1024;
/// Maximum size of one response line (what the CLI accepts from the daemon;
/// `devices` on a large relay is the biggest).
pub const MAX_RESPONSE_LINE: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    Status,
    Open {
        node: String,
        port: u16,
    },
    ForwardAdd {
        local: u16,
        node: String,
        port: u16,
    },
    ForwardRemove {
        local: u16,
    },
    Publish {
        port: u16,
        name: String,
        #[serde(default)]
        replace: bool,
        #[serde(default)]
        allow: Vec<String>,
    },
    Unpublish {
        name: String,
    },
    Devices,
    Trust {
        name: String,
        #[serde(default)]
        expect: Option<String>,
    },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub result: serde_json::Value,
}

impl ControlResponse {
    pub fn ok(result: serde_json::Value) -> ControlResponse {
        ControlResponse {
            ok: true,
            code: None,
            error: None,
            result,
        }
    }

    pub fn err(code: &str, error: impl Into<String>) -> ControlResponse {
        ControlResponse {
            ok: false,
            code: Some(code.to_string()),
            error: Some(error.into()),
            result: serde_json::Value::Null,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("warren is not running here; start it with `warren up` (or `warren install`)")]
    NotRunning,
    #[error("control socket: {0}")]
    Io(#[from] io::Error),
    #[error("malformed reply from the daemon")]
    Protocol,
}

async fn connect(paths: &NodePaths) -> Result<UnixStream, ControlError> {
    match UnixStream::connect(paths.socket()).await {
        Ok(s) => Ok(s),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Err(ControlError::NotRunning)
        }
        Err(e) => Err(e.into()),
    }
}

/// Read one JSON request line (at most [`MAX_LINE`] bytes).
pub async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
) -> io::Result<Option<String>> {
    read_line_limited(r, MAX_LINE).await
}

/// Read one JSON line of at most `max` bytes.
pub async fn read_line_limited<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
    max: u64,
) -> io::Result<Option<String>> {
    use tokio::io::AsyncReadExt;
    let mut line = String::new();
    let n = (&mut *r).take(max).read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    if !line.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control line too long",
        ));
    }
    Ok(Some(line))
}

/// Send one request and wait for the response.
pub async fn request(
    paths: &NodePaths,
    req: &ControlRequest,
) -> Result<ControlResponse, ControlError> {
    let s = connect(paths).await?;
    let (r, mut w) = s.into_split();
    let mut line = serde_json::to_vec(req).map_err(|_| ControlError::Protocol)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    let mut r = BufReader::new(r);
    let resp = read_line_limited(&mut r, MAX_RESPONSE_LINE)
        .await?
        .ok_or(ControlError::Protocol)?;
    serde_json::from_str(&resp).map_err(|_| ControlError::Protocol)
}

/// True if a daemon answers on this home's control socket.
pub async fn daemon_running(paths: &NodePaths) -> bool {
    paths.socket().exists() && UnixStream::connect(paths.socket()).await.is_ok()
}

/// Ask the daemon to open a private stream; on success returns the pipe.
pub async fn open(
    paths: &NodePaths,
    node: &str,
    port: u16,
) -> Result<Result<(BufReader<OwnedReadHalf>, OwnedWriteHalf), ControlResponse>, ControlError> {
    let s = connect(paths).await?;
    let (r, mut w) = s.into_split();
    let mut line = serde_json::to_vec(&ControlRequest::Open {
        node: node.to_string(),
        port,
    })
    .map_err(|_| ControlError::Protocol)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    let mut r = BufReader::new(r);
    let resp = read_line_limited(&mut r, MAX_RESPONSE_LINE)
        .await?
        .ok_or(ControlError::Protocol)?;
    let resp: ControlResponse = serde_json::from_str(&resp).map_err(|_| ControlError::Protocol)?;
    if resp.ok {
        Ok(Ok((r, w)))
    } else {
        Ok(Err(resp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_json() {
        let r = ControlRequest::ForwardAdd {
            local: 2222,
            node: "b".into(),
            port: 22,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(
            s,
            r#"{"op":"forward_add","local":2222,"node":"b","port":22}"#
        );
        let back: ControlRequest =
            serde_json::from_str(r#"{"op":"publish","port":1,"name":"x"}"#).unwrap();
        assert!(matches!(
            back,
            ControlRequest::Publish { replace: false, .. }
        ));
    }

    #[tokio::test]
    async fn not_running() {
        let t = tempfile::tempdir().unwrap();
        let p = NodePaths::new(t.path());
        assert!(matches!(
            request(&p, &ControlRequest::Status).await,
            Err(ControlError::NotRunning)
        ));
    }
}
