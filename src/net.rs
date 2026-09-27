//! The only place the binary opens outbound TCP connections.
//!
//! Warren connects to exactly three kinds of destination:
//!
//! * the configured relay ([`dial_relay`]), and
//! * exact validated LAN gateway targets ([`dial_gateway`]), and
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

/// Resolve both endpoints for each gateway connection. Only the complete,
/// validated numeric result may be dialed; no hostname reaches connect here.
pub async fn dial_gateway(
    target: &crate::gateway_policy::GatewayTarget,
    relay: &RelayUrl,
    connected_relay_ips: &[IpAddr],
) -> io::Result<TcpStream> {
    dial_gateway_resolved(
        target,
        relay,
        connected_relay_ips,
        |host, port| async move {
            Ok(tokio::net::lookup_host((host, port))
                .await?
                .take(33)
                .collect())
        },
    )
    .await
}

// The same resolver boundary is injected by tests; dialing remains numeric-only.
async fn dial_gateway_resolved<F, R>(
    target: &crate::gateway_policy::GatewayTarget,
    relay: &RelayUrl,
    connected_relay_ips: &[IpAddr],
    resolve: F,
) -> io::Result<TcpStream>
where
    F: Fn(String, u16) -> R,
    R: std::future::Future<Output = io::Result<Vec<SocketAddr>>>,
{
    let stream =
        dial_gateway_resolved_with_dial(target, relay, connected_relay_ips, resolve, |address| {
            TcpStream::connect(address)
        })
        .await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

// A numeric-dial seam keeps policy ordering independently testable without I/O.
// The production wrapper above is the only caller that opens gateway sockets.
async fn dial_gateway_resolved_with_dial<F, R, D, C, T>(
    target: &crate::gateway_policy::GatewayTarget,
    relay: &RelayUrl,
    connected_relay_ips: &[IpAddr],
    resolve: F,
    dial: D,
) -> io::Result<T>
where
    F: Fn(String, u16) -> R,
    R: std::future::Future<Output = io::Result<Vec<SocketAddr>>>,
    D: Fn(SocketAddr) -> C,
    C: std::future::Future<Output = io::Result<T>>,
{
    let attempt = async {
        let (target_result, relay_result) = tokio::join!(
            resolve(target.host.clone(), target.port),
            resolve(relay.host.clone(), relay.port),
        );
        let addresses = target_result?;
        let mut relay_addresses: Vec<_> = relay_result?.into_iter().map(|a| a.ip()).collect();
        if relay_addresses.len() > 32 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "too many relay addresses",
            ));
        }
        if relay_addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "empty relay resolution",
            ));
        }
        relay_addresses.extend_from_slice(connected_relay_ips);
        let valid = crate::gateway_policy::validate_resolved(target, &addresses, &relay_addresses)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "gateway address policy refused",
                )
            })?;
        let mut last = io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "no validated gateway address connected",
        );
        for address in valid {
            match dial(address).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last = e,
            }
        }
        Err(last)
    };
    tokio::time::timeout(Duration::from_secs(5), attempt)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "gateway resolve/connect timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn gateway_resolution_rejects_whole_poisoned_sets_and_relay_aliases() {
        let target = crate::gateway_policy::GatewayTarget::parse("camera.local:554").unwrap();
        let relay = RelayUrl::parse("https://relay.example:443").unwrap();
        let private: SocketAddr = "192.168.1.7:554".parse().unwrap();
        let public: SocketAddr = "8.8.8.8:554".parse().unwrap();
        for (answers, relay_answers, connected) in [
            (
                vec![private, public],
                vec!["1.1.1.1:443".parse().unwrap()],
                vec![],
            ),
            (vec![public], vec!["1.1.1.1:443".parse().unwrap()], vec![]),
            (
                vec![private],
                vec!["192.168.1.7:443".parse().unwrap()],
                vec![],
            ),
            (vec![private], vec![], vec![]),
            (
                vec![private],
                vec!["1.1.1.1:443".parse().unwrap()],
                vec![private.ip()],
            ),
            (
                vec![private; 33],
                vec!["1.1.1.1:443".parse().unwrap()],
                vec![],
            ),
            (
                vec![private],
                vec!["1.1.1.1:443".parse().unwrap(); 33],
                vec![],
            ),
        ] {
            let calls = std::sync::atomic::AtomicUsize::new(0);
            let result = dial_gateway_resolved_with_dial(
                &target,
                &relay,
                &connected,
                |host, port| {
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let resolved = if host == target.host {
                        assert_eq!(port, 554);
                        answers.clone()
                    } else {
                        assert_eq!(host, relay.host);
                        assert_eq!(port, 443);
                        relay_answers.clone()
                    };
                    async { Ok(resolved) }
                },
                |_address| async {
                    panic!("unsafe answer set reached numeric dial");
                    #[allow(unreachable_code)]
                    Ok::<(), io::Error>(())
                },
            )
            .await;
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        }
    }

    #[tokio::test]
    async fn gateway_reresolves_before_each_numeric_dial() {
        let address: SocketAddr = "192.168.1.7:554".parse().unwrap();
        let target = crate::gateway_policy::GatewayTarget::parse("camera.local:554").unwrap();
        let relay = RelayUrl::parse("https://relay.example").unwrap();
        let resolutions = std::sync::Mutex::new(Vec::new());
        let dials = std::sync::Mutex::new(Vec::new());
        for (attempt, poisoned) in [false, true].into_iter().enumerate() {
            let result = dial_gateway_resolved_with_dial(
                &target,
                &relay,
                &[],
                |host, port| {
                    resolutions.lock().unwrap().push((host.clone(), port));
                    let answers = if host == target.host {
                        if poisoned {
                            vec![address, "8.8.8.8:554".parse().unwrap()]
                        } else {
                            vec![address]
                        }
                    } else {
                        vec!["1.1.1.1:443".parse().unwrap()]
                    };
                    async move { Ok(answers) }
                },
                |numeric| {
                    dials.lock().unwrap().push(numeric);
                    async move { Ok(numeric) }
                },
            )
            .await;
            if poisoned {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            } else {
                assert_eq!(result.unwrap(), address);
            }
            // Both endpoints must be freshly resolved, including the denied attempt.
            let expected: Vec<_> = (0..=attempt)
                .flat_map(|_| {
                    [
                        (target.host.clone(), target.port),
                        (relay.host.clone(), relay.port),
                    ]
                })
                .collect();
            assert_eq!(*resolutions.lock().unwrap(), expected);
            // The first allowed set dials its exact numeric address once. The later
            // mixed private/public set must be rejected before ANY numeric dial.
            assert_eq!(*dials.lock().unwrap(), vec![address]);
        }
    }

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
