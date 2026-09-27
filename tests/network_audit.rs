//! SR9: the binary makes no network connection other than to the configured
//! relay (and, on the relay, to its ACME directory).
//!
//! Enforced structurally: every outbound TCP connection goes through
//! `src/net.rs` (`dial_relay` for the relay URL from the node's identity file,
//! `dial_loopback` for local services), the only other network client is the
//! ACME client in `src/relay/acme.rs`, and no dependency is an HTTP client,
//! telemetry or update library. This test scans the sources and the manifest;
//! `tests/cli.rs` additionally lists the running relay's and daemons' sockets
//! and checks that every connection goes to the relay or to loopback.

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Strip `#[cfg(test)] mod tests { ... }` blocks: tests may open sockets freely.
fn non_test_source(src: &str) -> String {
    match src.find("#[cfg(test)]\nmod tests") {
        Some(i) => src[..i].to_string(),
        None => src.to_string(),
    }
}

#[test]
fn outbound_connections_only_in_the_dial_module() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    assert!(files.len() > 15);

    // (pattern, files allowed to contain it)
    let rules: &[(&str, &[&str])] = &[
        ("TcpStream::connect", &["src/net.rs"]),
        ("UdpSocket", &[]),
        ("lookup_host", &[]),
        ("to_socket_addrs", &[]),
        ("ToSocketAddrs", &[]),
        ("connect_async", &[]),
        ("TcpSocket", &[]),
        ("client_async", &["src/ws.rs"]),
        ("net::dial_relay", &["src/ws.rs"]),
        ("instant_acme", &["src/relay/acme.rs"]),
        (
            "UnixStream::connect",
            &["src/node/control.rs", "src/node/daemon.rs"],
        ),
        ("reqwest", &[]),
        ("ureq", &[]),
        ("hyper", &[]),
        (
            "Command::new",
            &["src/install.rs", "src/cli.rs", "src/node/mod.rs"],
        ),
    ];
    let mut violations = Vec::new();
    for f in &files {
        let rel = f
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let src = non_test_source(&std::fs::read_to_string(f).unwrap());
        for (pat, allowed) in rules {
            if src.contains(pat) && !allowed.contains(&rel.as_str()) {
                violations.push(format!("{rel}: {pat}"));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "unexpected network code: {violations:#?}"
    );

    // The dial module only dials the relay URL and loopback addresses.
    let net = std::fs::read_to_string(root.join("src/net.rs")).unwrap();
    let net = non_test_source(&net);
    assert_eq!(net.matches("TcpStream::connect(").count(), 2);
    assert!(net.contains("if !addr.ip().is_loopback()"));
    // The relay URL comes only from the node's identity file (or `join --relay`).
    let daemon = std::fs::read_to_string(root.join("src/node/daemon.rs")).unwrap();
    assert!(daemon.contains("connect_relay(&self.relay, self.pin)"));
    // Processes spawned: service managers for `install`, `ssh` for `warren
    // ssh`, `uname -n` for the default name. None of them is a network client
    // started on our own initiative.
    let cli = non_test_source(&std::fs::read_to_string(root.join("src/cli.rs")).unwrap());
    assert!(cli.contains("Command::new(\"ssh\")"));
    let install = non_test_source(&std::fs::read_to_string(root.join("src/install.rs")).unwrap());
    for line in install.lines().filter(|l| l.contains("Command::new(")) {
        assert!(
            line.contains("\"launchctl\"") || line.contains("\"systemctl\""),
            "{line}"
        );
    }
}

#[test]
fn no_network_client_dependencies() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .unwrap()
        .split("\n[")
        .next()
        .unwrap();
    let names: Vec<&str> = deps
        .lines()
        .filter_map(|l| l.split('=').next())
        .map(str::trim)
        .filter(|n| !n.is_empty() && !n.starts_with('#'))
        .collect();
    let allowed = [
        "anyhow",
        "bytes",
        "clap",
        "ed25519-dalek",
        "futures-util",
        "hex",
        "httparse",
        "instant-acme",
        "ipnet",
        "rand",
        "rcgen",
        "rusqlite",
        "rustls",
        "serde",
        "serde_json",
        "sha2",
        "snow",
        "thiserror",
        "tokio",
        "tokio-rustls",
        "tokio-tungstenite",
        "tokio-util",
        "tracing",
        "tracing-subscriber",
        "webpki-roots",
    ];
    for n in &names {
        assert!(allowed.contains(n), "unreviewed dependency {n}");
    }
    assert!(names.len() >= 20);
}
