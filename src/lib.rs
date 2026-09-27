//! Warren: private links between your machines through a relay you run yourself.
//!
//! One binary provides three roles:
//!
//! * the **relay** ([`relay`]), which authenticates nodes, forwards multiplexed
//!   streams between them and terminates TLS for published names;
//! * the **node daemon** ([`node`]), which keeps one WebSocket open to the relay,
//!   enforces its own share policy and runs forwards;
//! * the **CLI** ([`cli`]), which talks to the daemon over a private local
//!   channel (a Unix socket, or a named pipe on Windows).
//!
//! Private streams are end-to-end encrypted with
//! `Noise_IK_25519_ChaChaPoly_BLAKE2s` ([`noise`]); the relay only ever sees
//! ciphertext for them. See `docs/protocol.md` for the wire format.

// No `unsafe` anywhere except `sys::windows`, which wraps the Win32 security
// and console calls that have no safe API (`tests/network_audit.rs` checks
// that no other file uses it).
#![deny(unsafe_code)]

pub mod cli;
pub mod crypto;
pub mod fsutil;
pub mod http;
#[cfg(unix)]
pub mod install;
#[cfg(windows)]
#[path = "install_windows.rs"]
pub mod install;
#[cfg(all(unix, test))]
#[allow(dead_code)]
#[path = "install_windows.rs"]
mod install_windows_tests;
pub mod limits;
pub mod mux;
pub mod net;
pub mod node;
pub mod noise;
pub mod proto;
pub mod relay;
pub mod sys;
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

/// Longest text accepted from another machine or the relay for display.
pub const MAX_REMOTE_TEXT: usize = 512;

/// Make text that came from another machine or from the relay (refusal
/// messages, control errors, names) safe to show on a terminal or in a log:
/// control characters and invisible bidirectional/formatting characters are
/// escaped (`\u{1b}`), and the text is cut at [`MAX_REMOTE_TEXT`] characters.
pub fn sanitize_remote_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_REMOTE_TEXT));
    for (i, c) in s.chars().enumerate() {
        if i >= MAX_REMOTE_TEXT {
            out.push_str("...");
            break;
        }
        let invisible = matches!(
            c,
            '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        );
        if c.is_control() || invisible {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// A machine-readable code received from a remote: kept if it looks like one
/// of ours (`[a-z0-9_]{1,40}`), otherwise replaced by `"error"`.
pub fn sanitize_remote_code(code: &str) -> String {
    if !code.is_empty()
        && code.len() <= 40
        && code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        code.to_string()
    } else {
        "error".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_text_is_made_safe() {
        let hostile = "\u{1b}]0;owned\u{7}\u{1b}[2Jok \u{202e}evil\u{200b}";
        let s = sanitize_remote_text(hostile);
        assert!(!s.chars().any(|c| c.is_control()), "{s:?}");
        assert!(!s.contains('\u{202e}') && !s.contains('\u{200b}'));
        assert!(s.contains("\\u{1b}") && s.contains("ok "));
        assert_eq!(
            sanitize_remote_text("port 22 is not shared"),
            "port 22 is not shared"
        );
        assert_eq!(sanitize_remote_text("日本語"), "日本語");
        let long = sanitize_remote_text(&"x".repeat(5000));
        assert_eq!(long.len(), MAX_REMOTE_TEXT + 3);
        assert_eq!(sanitize_remote_code("name_taken"), "name_taken");
        assert_eq!(sanitize_remote_code("\u{1b}[2J"), "error");
        assert_eq!(sanitize_remote_code(""), "error");
    }

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
