//! The only place the binary opens outbound TCP connections.
//!
//! Warren connects to exactly two kinds of destination:
//!
//! * the configured relay ([`dial_relay`]), and
//! * services on the local machine's loopback interface ([`dial_local`]),
//!   which is how shares and publishes reach the service they expose.
//!
//! The relay additionally talks to its configured ACME directory (see
//! `relay::acme`). A test (`tests/network_audit.rs`) checks that no other
//! module opens connections.

use anyhow::{bail, Context, Result};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;

/// A parsed relay URL (`https://host[:port]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayUrl {
    /// Host name or IP literal, lower-case, without brackets.
    pub host: String,
    pub port: u16,
}

impl RelayUrl {
    pub fn parse(s: &str) -> Result<RelayUrl> {
        let s = s.trim();
        let rest = if let Some(r) = s.strip_prefix("https://") {
            r
        } else if let Some(r) = s.strip_prefix("wss://") {
            r
        } else if s.contains("://") {
            bail!("relay URL must use https:// (got {s})");
        } else {
            s
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.is_empty() || authority.contains('@') {
            bail!("invalid relay URL {s}");
        }
        let (host, port) = if let Some(r) = authority.strip_prefix('[') {
            let (h, tail) = r.split_once(']').context("unterminated IPv6 literal")?;
            let port = match tail.strip_prefix(':') {
                Some(p) => p.parse().context("invalid port")?,
                None if tail.is_empty() => 443,
                None => bail!("invalid relay URL {s}"),
            };
            (h.to_string(), port)
        } else if let Some((h, p)) = authority.rsplit_once(':') {
            (h.to_string(), p.parse().context("invalid port")?)
        } else {
            (authority.to_string(), 443)
        };
        if host.is_empty() || port == 0 {
            bail!("invalid relay URL {s}");
        }
        Ok(RelayUrl {
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    /// The host name bound into authentication signatures.
    pub fn auth_host(&self) -> &str {
        &self.host
    }

    /// Canonical `https://` form.
    pub fn https(&self) -> String {
        let h = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 443 {
            format!("https://{h}")
        } else {
            format!("https://{h}:{}", self.port)
        }
    }

    /// WebSocket endpoint for nodes.
    pub fn node_ws(&self) -> String {
        format!("{}/v1/node", self.https().replacen("https://", "wss://", 1))
    }
}

/// Connect to the configured relay.
pub async fn dial_relay(url: &RelayUrl) -> io::Result<TcpStream> {
    let s = TcpStream::connect((url.host.as_str(), url.port)).await?;
    s.set_nodelay(true)?;
    Ok(s)
}

/// Connect to a service on this machine's loopback interface.
pub async fn dial_local(port: u16) -> io::Result<TcpStream> {
    dial_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)).await
}

/// Connect to a loopback address; anything else is refused.
pub async fn dial_loopback(addr: SocketAddr) -> io::Result<TcpStream> {
    if !addr.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "only loopback destinations may be dialed locally",
        ));
    }
    let s = TcpStream::connect(addr).await?;
    s.set_nodelay(true)?;
    Ok(s)
}

/// How long an accept loop waits after a failed `accept`.
pub const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(50);

/// The accepted connection, or `None` after logging the error and pausing
/// for [`ACCEPT_ERROR_PAUSE`]. Accept errors such as running out of file
/// descriptors repeat immediately, so retrying at once would spin a core.
pub async fn accepted<T>(r: io::Result<T>, what: &str) -> Option<T> {
    match r {
        Ok(x) => Some(x),
        Err(e) => {
            tracing::warn!("{what}: accept failed: {e}");
            tokio::time::sleep(ACCEPT_ERROR_PAUSE).await;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn failed_accepts_pause() {
        let t = std::time::Instant::now();
        assert_eq!(accepted(Ok(7), "test").await, Some(7));
        assert!(t.elapsed() < ACCEPT_ERROR_PAUSE);
        let t = std::time::Instant::now();
        let e = io::Error::from_raw_os_error(24); // EMFILE
        assert_eq!(accepted::<u8>(Err(e), "test").await, None);
        assert!(t.elapsed() >= ACCEPT_ERROR_PAUSE);
    }

    #[test]
    fn parse_urls() {
        let u = RelayUrl::parse("https://Relay.Example.com").unwrap();
        assert_eq!(u.host, "relay.example.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.https(), "https://relay.example.com");
        assert_eq!(u.node_ws(), "wss://relay.example.com/v1/node");
        let u = RelayUrl::parse("https://127.0.0.1:8443/").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("127.0.0.1", 8443));
        assert_eq!(u.node_ws(), "wss://127.0.0.1:8443/v1/node");
        let u = RelayUrl::parse("https://[::1]:9000").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 9000));
        assert_eq!(u.https(), "https://[::1]:9000");
        let u = RelayUrl::parse("relay.example.com").unwrap();
        assert_eq!(u.port, 443);
        assert!(RelayUrl::parse("http://relay.example.com").is_err());
        assert!(RelayUrl::parse("https://").is_err());
        assert!(RelayUrl::parse("https://user@host").is_err());
        assert!(RelayUrl::parse("https://host:0").is_err());
    }

    #[tokio::test]
    async fn local_dial_refuses_non_loopback() {
        let e = dial_loopback("192.0.2.1:80".parse().unwrap())
            .await
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    }
}
