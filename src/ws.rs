//! WebSocket plumbing shared by the relay (server side) and nodes (client side).

use crate::net::{self, RelayUrl};
use crate::proto::MAX_WS_MESSAGE;
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::WebSocketStream;

/// WebSocket stream a node holds to its relay.
pub type ClientWs = WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// Time allowed to establish TCP + TLS + WebSocket to the relay.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// WebSocket limits: one frame per message, never more than [`MAX_WS_MESSAGE`].
pub fn config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE))
        .max_frame_size(Some(MAX_WS_MESSAGE))
}

/// Connect to the relay's node endpoint over TLS.
pub async fn connect_relay(url: &RelayUrl, pin: Option<[u8; 32]>) -> Result<ClientWs> {
    let fut = async {
        let tcp = net::dial_relay(url)
            .await
            .with_context(|| format!("connecting to {}", url.https()))?;
        let connector = TlsConnector::from(crate::tls::client_config(pin)?);
        let tls = connector
            .connect(crate::tls::server_name(&url.host)?, tcp)
            .await
            .context("TLS handshake with the relay")?;
        let upgrade =
            tokio_tungstenite::client_async_with_config(url.node_ws(), tls, Some(config())).await;
        match upgrade {
            Ok((ws, _)) => Ok(ws),
            // The relay answers 404 for any host other than its own domain.
            Err(tokio_tungstenite::tungstenite::Error::Http(r)) if r.status() == 404 => {
                anyhow::bail!(
                    "the relay did not accept {}/v1/node (HTTP 404); the host in --relay \
                     must be the relay's --domain",
                    url.https()
                )
            }
            Err(e) => Err(anyhow::Error::new(e).context("WebSocket upgrade with the relay")),
        }
    };
    tokio::time::timeout(CONNECT_TIMEOUT, fut)
        .await
        .context("timed out connecting to the relay")?
}

/// The `101 Switching Protocols` response for a client key.
pub fn upgrade_response(client_key: &[u8]) -> String {
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(client_key);
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_matches_rfc_example() {
        // RFC 6455 section 1.3 example.
        let r = upgrade_response(b"dGhlIHNhbXBsZSBub25jZQ==");
        assert!(r.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        assert!(r.starts_with("HTTP/1.1 101"));
    }

    #[test]
    fn limits() {
        let c = config();
        assert_eq!(c.max_message_size, Some(MAX_WS_MESSAGE));
        assert_eq!(c.max_frame_size, Some(MAX_WS_MESSAGE));
    }
}
