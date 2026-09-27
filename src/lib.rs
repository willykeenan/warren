//! Warren: private links between your machines through a relay you run yourself.
//!
//! One binary provides three roles:
//!
//! * the **relay** ([`relay`]), which authenticates nodes, forwards multiplexed
//!   streams between them and terminates TLS for published names;
//! * the **node daemon** ([`node`]), which keeps one WebSocket open to the relay,
//!   enforces its own share policy and runs forwards;
//! * the **CLI** ([`cli`]), which talks to the daemon over a private Unix socket.
//!
//! Private streams are end-to-end encrypted with
//! `Noise_IK_25519_ChaChaPoly_BLAKE2s` ([`noise`]); the relay only ever sees
//! ciphertext for them. See `docs/protocol.md` for the wire format.

#![forbid(unsafe_code)]

pub mod cli;
pub mod crypto;
pub mod fsutil;
pub mod http;
pub mod install;
pub mod limits;
pub mod mux;
pub mod net;
pub mod node;
pub mod noise;
pub mod proto;
pub mod relay;
pub mod tls;
pub mod ws;

/// Version string reported by the binary and the protocol handshake.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Current time as whole seconds since the Unix epoch.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Validate a node or publish name: `[a-z0-9-]{1,32}`.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Validate a publish name: a node name that is also a valid DNS label
/// (no leading or trailing hyphen).
pub fn valid_publish_name(name: &str) -> bool {
    valid_name(name) && !name.starts_with('-') && !name.ends_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(valid_name("a"));
        assert!(valid_name("laptop-2"));
        assert!(valid_name(&"a".repeat(32)));
        assert!(!valid_name(&"a".repeat(33)));
        assert!(!valid_name(""));
        assert!(!valid_name("Laptop"));
        assert!(!valid_name("a.b"));
        assert!(!valid_name("a_b"));
        assert!(valid_publish_name("webapp"));
        assert!(!valid_publish_name("-x"));
        assert!(!valid_publish_name("x-"));
    }
}
