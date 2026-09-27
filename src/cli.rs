//! Command-line interface. Every command accepts `--json`.
//!
//! Exit codes:
//!
//! | code | meaning |
//! |-----:|---------|
//! | 0 | success |
//! | 1 | other error |
//! | 2 | usage error |
//! | 3 | this machine is not enrolled |
//! | 4 | the daemon is not running |
//! | 5 | not connected to the relay |
//! | 6 | refused (not shared, forbidden, offline, unknown node, connect failed, limits) |
//! | 7 | a pinned key changed, or a fingerprint did not match |
//! | 8 | authentication or enrollment refused |
//! | 9 | name conflict (publish) |

use crate::install::{self, Flavor, InstallOptions};
use crate::node::control::{self, ControlError, ControlRequest, ControlResponse};
use crate::node::daemon::{self, DaemonConfig};
use crate::node::{
    self, ForwardsFile, IdentityFile, JoinError, NodePaths, PublishesFile, SharesFile,
};
use crate::relay::{self, db::Db, RelayConfig, TlsMode};
use clap::{Args, Parser, Subcommand};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;

pub mod exit {
    pub const OK: i32 = 0;
    pub const ERROR: i32 = 1;
    pub const USAGE: i32 = 2;
    pub const NOT_ENROLLED: i32 = 3;
    pub const NOT_RUNNING: i32 = 4;
    pub const NOT_CONNECTED: i32 = 5;
    pub const REFUSED: i32 = 6;
    pub const KEY_CHANGED: i32 = 7;
    pub const AUTH: i32 = 8;
    pub const CONFLICT: i32 = 9;
}

#[derive(Parser, Debug)]
#[command(
    name = "warren",
    version,
    about = "Private links between your machines, through a relay you run yourself",
    propagate_version = true
)]
pub struct Cli {
    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Run the relay, or administer it (invite, nodes, revoke, domain, info).
    Relay(RelayCmd),
    /// Enroll this machine with a one-time code.
    Join {
        code: String,
        /// Relay URL, e.g. https://relay.example.com
        #[arg(long)]
        relay: String,
        /// Name for this machine (default: host name; an invite's name wins).
        #[arg(long)]
        name: Option<String>,
        /// Pin the relay's self-signed certificate by SHA-256 (hex) instead of using web PKI.
        #[arg(long, value_name = "HEX")]
        insecure_relay_cert_sha256: Option<String>,
        /// Re-enroll with new keys even if already enrolled.
        #[arg(long)]
        force: bool,
    },
    /// Connect to the relay and serve shares, forwards and publishes (foreground).
    Up,
    /// Stop the running daemon.
    Down,
    /// Show connection state, latency, shares, forwards, publishes and recent errors.
    Status,
    /// Share a local port with other machines (no PORT: list shares).
    Share {
        port: Option<u16>,
        /// Only these nodes may connect (comma-separated).
        #[arg(long, value_delimiter = ',')]
        to: Option<Vec<String>>,
    },
    /// Stop sharing a port.
    Unshare { port: u16 },
    /// Forward a local port to NODE:PORT (no arguments: list forwards).
    Forward {
        local: Option<u16>,
        #[arg(value_name = "NODE:PORT")]
        target: Option<String>,
        /// Remove the forward on this local port.
        #[arg(long, value_name = "LOCAL", conflicts_with_all = ["local", "target"])]
        remove: Option<u16>,
    },
    /// Connect stdin/stdout to NODE:PORT (usable as an ssh ProxyCommand).
    Nc { node: String, port: u16 },
    /// ssh to a node through warren.
    Ssh {
        /// [USER@]NODE
        destination: String,
        /// sshd port on the node.
        #[arg(short, long, default_value_t = 22)]
        port: u16,
        /// Extra arguments passed to ssh after the destination.
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Publish a local port at https://NAME.<relay domain>/.
    Publish {
        port: u16,
        #[arg(long)]
        name: String,
        /// Change an existing publish of this node (port or allowlist).
        #[arg(long)]
        replace: bool,
        /// Only these client CIDRs may connect (comma-separated).
        #[arg(long, value_delimiter = ',')]
        allow: Vec<String>,
    },
    /// Stop publishing a name.
    Unpublish { name: String },
    /// List machines on the relay with fingerprints and online state.
    Devices,
    /// Accept a peer's current key (after a legitimate key change).
    Trust {
        name: String,
        /// Refuse unless the current fingerprint matches this one.
        #[arg(long)]
        expect: Option<String>,
    },
    /// Start `warren up` at login (launchd on macOS, systemd user service on Linux).
    Install {
        /// Write the service file only; do not load it.
        #[arg(long)]
        no_start: bool,
        /// Directory for the service file (also WARREN_LAUNCHD_DIR / WARREN_SYSTEMD_DIR).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Remove the login service.
    Uninstall {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true)]
pub struct RelayCmd {
    #[command(subcommand)]
    pub sub: Option<RelaySub>,
    #[command(flatten)]
    pub run: RelayRun,
}

#[derive(Args, Debug)]
pub struct RelayRun {
    /// Address to listen on for TLS (nodes and public traffic).
    #[arg(long, default_value = "0.0.0.0:443")]
    pub listen: SocketAddr,
    /// The relay's own host name (what nodes put in --relay).
    #[arg(long)]
    pub domain: Option<String>,
    /// Published names live at NAME.<publish-domain> (default: --domain).
    #[arg(long)]
    pub publish_domain: Option<String>,
    /// State directory (default: $WARREN_HOME/relay or ~/.warren/relay).
    #[arg(long)]
    pub state: Option<PathBuf>,
    /// Certificate chain (PEM) covering the relay and published names.
    #[arg(long, requires = "key")]
    pub cert: Option<PathBuf>,
    /// Private key (PEM) for --cert.
    #[arg(long, requires = "cert")]
    pub key: Option<PathBuf>,
    /// Obtain certificates automatically via ACME HTTP-01 (contact e-mail).
    #[arg(long, value_name = "EMAIL", conflicts_with_all = ["cert", "self_signed"])]
    pub acme: Option<String>,
    /// ACME directory URL.
    #[arg(long, default_value = crate::relay::acme::LETS_ENCRYPT)]
    pub acme_directory: String,
    /// Plain-HTTP listener for ACME challenges and redirects (default 0.0.0.0:80 with --acme).
    #[arg(long)]
    pub http_listen: Option<SocketAddr>,
    /// Use a persistent self-signed certificate (testing / local development).
    #[arg(long, conflicts_with = "cert")]
    pub self_signed: bool,
}

#[derive(Subcommand, Debug)]
pub enum RelaySub {
    /// Print a one-time enrollment code (valid 10 minutes).
    Invite {
        /// Name the enrolling machine must use.
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        state: Option<PathBuf>,
    },
    /// List enrolled nodes.
    Nodes {
        #[arg(long)]
        state: Option<PathBuf>,
    },
    /// Revoke a node: it is disconnected and can no longer connect.
    Revoke {
        name: String,
        #[arg(long)]
        state: Option<PathBuf>,
    },
    /// Map custom domains to published names.
    Domain {
        #[command(subcommand)]
        action: DomainAction,
        #[arg(long, global = true)]
        state: Option<PathBuf>,
    },
    /// Show relay state (certificate pin in self-signed mode).
    Info {
        #[arg(long)]
        state: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum DomainAction {
    /// Serve HOST as the published NAME.
    Add { host: String, name: String },
    /// Remove a custom domain.
    Remove { host: String },
    /// List custom domains.
    List,
}

/// A CLI failure with its exit code.
#[derive(Debug)]
pub struct CliError {
    pub exit: i32,
    pub code: String,
    pub message: String,
}

impl CliError {
    fn new(exit: i32, code: &str, message: impl Into<String>) -> CliError {
        CliError {
            exit,
            code: code.to_string(),
            message: message.into(),
        }
    }
}

impl From<anyhow::Error> for CliError {
    fn from(e: anyhow::Error) -> CliError {
        let msg = format!("{e:#}");
        if msg.contains("not enrolled") {
            return CliError::new(exit::NOT_ENROLLED, "not_enrolled", msg);
        }
        CliError::new(exit::ERROR, "error", msg)
    }
}

impl From<ControlError> for CliError {
    fn from(e: ControlError) -> CliError {
        match e {
            ControlError::NotRunning => {
                CliError::new(exit::NOT_RUNNING, "not_running", e.to_string())
            }
            _ => CliError::new(exit::ERROR, "control", e.to_string()),
        }
    }
}

/// Exit code for a machine-readable error code.
pub fn exit_for_code(code: &str) -> i32 {
    match code {
        "not_connected" => exit::NOT_CONNECTED,
        "not_running" => exit::NOT_RUNNING,
        "not_enrolled" => exit::NOT_ENROLLED,
        "key_changed" | "fingerprint_mismatch" => exit::KEY_CHANGED,
        "name_taken" | "already_published" => exit::CONFLICT,
        "invalid_code" | "rate_limited_join" | "bad_signature" | "revoked" | "unknown_node"
        | "name_taken_join" => exit::AUTH,
        "not_shared" | "forbidden" | "no_such_node" | "node_offline" | "connect_failed"
        | "too_many_streams" | "rate_limited" | "handshake_failed" | "aborted"
        | "no_such_publish" | "link_closed" => exit::REFUSED,
        _ => exit::ERROR,
    }
}

fn from_response(r: ControlResponse) -> CliError {
    let code = r.code.unwrap_or_else(|| "error".into());
    CliError::new(exit_for_code(&code), &code, r.error.unwrap_or_default())
}

type CliResult = Result<Value, CliError>;

struct Out {
    json: bool,
}

impl Out {
    fn print(&self, v: &Value, human: impl FnOnce() -> String) {
        if self.json {
            println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
        } else {
            let s = human();
            if !s.is_empty() {
                println!("{}", s.trim_end());
            }
        }
    }
}

fn init_logging(default: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("WARREN_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

/// Entry point used by `main`.
pub fn main() -> i32 {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let code = match e.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                    exit::OK
                }
                _ => exit::USAGE,
            };
            let _ = e.print();
            return code;
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("warren: cannot start runtime: {e}");
            return exit::ERROR;
        }
    };
    let json = cli.json;
    let result = rt.block_on(run(cli));
    let code = match result {
        Ok(()) => exit::OK,
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({"ok": false, "code": e.code, "error": e.message})
                    )
                    .unwrap_or_default()
                );
            } else {
                eprintln!("warren: {}", e.message);
            }
            e.exit
        }
    };
    rt.shutdown_timeout(std::time::Duration::from_millis(200));
    code
}

async fn run(cli: Cli) -> Result<(), CliError> {
    let out = Out { json: cli.json };
    match cli.command {
        Command::Relay(r) => relay_cmd(r, &out).await,
        Command::Up => {
            init_logging("info");
            let paths = NodePaths::from_env()?;
            IdentityFile::load(&paths)?;
            daemon::run(DaemonConfig::new(paths)).await?;
            Ok(())
        }
        other => {
            init_logging("warn");
            let paths = NodePaths::from_env()?;
            node_cmd(other, &paths, &out).await
        }
    }
}

fn state_dir(explicit: Option<PathBuf>) -> Result<PathBuf, CliError> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    Ok(NodePaths::from_env()?.home.join("relay"))
}

async fn relay_cmd(r: RelayCmd, out: &Out) -> Result<(), CliError> {
    match r.sub {
        None => run_relay(r.run, out).await,
        Some(RelaySub::Invite { name, state }) => {
            let db = Db::open(&state_dir(state)?)?;
            let ttl = crate::limits::INVITE_TTL;
            let now = crate::now_secs();
            let code = db.create_invite(name.as_deref(), ttl, now)?;
            let v = json!({"code": code, "name": name, "expires_at": now + ttl.as_secs() as i64});
            out.print(&v, || {
                format!(
                    "{code}\n\nOne-time code, valid for 10 minutes{}. On the new machine run:\n  warren join {code} --relay https://<relay host>",
                    name.as_ref().map(|n| format!(", for a machine named {n}")).unwrap_or_default()
                )
            });
            Ok(())
        }
        Some(RelaySub::Nodes { state }) => {
            let db = Db::open(&state_dir(state)?)?;
            let nodes = db.nodes()?;
            let v: Vec<Value> = nodes
                .iter()
                .map(|n| {
                    json!({
                        "name": n.name,
                        "node_id": n.node_id,
                        "fingerprint": crate::crypto::fingerprint(&n.static_pub),
                        "created_at": n.created_at,
                        "last_seen": n.last_seen,
                        "revoked": n.revoked_at.is_some(),
                    })
                })
                .collect();
            out.print(&Value::Array(v), || {
                let mut s = format!("{:<20} {:<40} {:<8}\n", "NAME", "FINGERPRINT", "STATE");
                for n in &nodes {
                    s += &format!(
                        "{:<20} {:<40} {:<8}\n",
                        n.name,
                        crate::crypto::fingerprint(&n.static_pub),
                        if n.revoked_at.is_some() {
                            "revoked"
                        } else {
                            "active"
                        }
                    );
                }
                s
            });
            Ok(())
        }
        Some(RelaySub::Revoke { name, state }) => {
            let db = Db::open(&state_dir(state)?)?;
            if !db.revoke(&name, crate::now_secs())? {
                return Err(CliError::new(
                    exit::ERROR,
                    "not_found",
                    format!("no active node named {name:?}"),
                ));
            }
            out.print(&json!({"revoked": name}), || {
                format!("revoked {name}; a running relay disconnects it within a few seconds")
            });
            Ok(())
        }
        Some(RelaySub::Domain { action, state }) => {
            let db = Db::open(&state_dir(state)?)?;
            match action {
                DomainAction::Add { host, name } => {
                    if !crate::valid_publish_name(&name) {
                        return Err(CliError::new(
                            exit::USAGE,
                            "bad_name",
                            format!("invalid name {name:?}"),
                        ));
                    }
                    db.add_domain(&host, &name)?;
                    out.print(&json!({"host": host, "name": name}), || {
                        format!("{host} now serves the published name {name}; point its DNS at the relay")
                    });
                }
                DomainAction::Remove { host } => {
                    let removed = db.remove_domain(&host)?;
                    out.print(&json!({"host": host, "removed": removed}), || {
                        if removed {
                            format!("removed {host}")
                        } else {
                            format!("{host} was not configured")
                        }
                    });
                }
                DomainAction::List => {
                    let d = db.domains()?;
                    let v: Vec<Value> = d
                        .iter()
                        .map(|(h, n)| json!({"host": h, "name": n}))
                        .collect();
                    out.print(&Value::Array(v), || {
                        d.iter().map(|(h, n)| format!("{h} -> {n}\n")).collect()
                    });
                }
            }
            Ok(())
        }
        Some(RelaySub::Info { state }) => {
            let dir = state_dir(state)?;
            let db = Db::open(&dir)?;
            let nodes = db.nodes()?;
            let mut pins = Vec::new();
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if n.starts_with("self-signed-") && n.ends_with(".crt") {
                        if let Ok(pem) = std::fs::read(&p) {
                            use rustls::pki_types::pem::PemObject;
                            if let Ok(der) = rustls::pki_types::CertificateDer::from_pem_slice(&pem)
                            {
                                pins.push(hex::encode(crate::tls::cert_sha256(der.as_ref())));
                            }
                        }
                    }
                }
            }
            let v = json!({
                "state": dir,
                "nodes": nodes.iter().filter(|n| n.revoked_at.is_none()).count(),
                "revoked": nodes.iter().filter(|n| n.revoked_at.is_some()).count(),
                "publishes": db.publishes()?.len(),
                "self_signed_cert_sha256": pins,
            });
            out.print(&v, || {
                let mut s = format!("state: {}\nnodes: {}\n", dir.display(), v["nodes"]);
                for p in &pins {
                    s += &format!("self-signed certificate SHA-256: {p}\n");
                }
                s
            });
            Ok(())
        }
    }
}

async fn run_relay(r: RelayRun, out: &Out) -> Result<(), CliError> {
    init_logging("info");
    let domain = r
        .domain
        .ok_or_else(|| {
            CliError::new(
                exit::USAGE,
                "usage",
                "--domain is required to run the relay",
            )
        })?
        .to_ascii_lowercase();
    let tls = if let Some(email) = r.acme {
        TlsMode::Acme {
            email,
            directory: r.acme_directory,
        }
    } else if let (Some(cert), Some(key)) = (r.cert, r.key) {
        TlsMode::Files { cert, key }
    } else if r.self_signed {
        TlsMode::SelfSigned
    } else {
        return Err(CliError::new(
            exit::USAGE,
            "usage",
            "choose a certificate source: --cert/--key, --acme EMAIL or --self-signed",
        ));
    };
    let mut cfg = RelayConfig::new(r.listen, &domain, state_dir(r.state)?, tls.clone());
    if let Some(p) = r.publish_domain {
        cfg.publish_domain = p.to_ascii_lowercase();
    }
    cfg.http_listen = r.http_listen.or_else(|| {
        matches!(tls, TlsMode::Acme { .. }).then(|| "0.0.0.0:80".parse().expect("addr"))
    });
    let h = relay::start(cfg).await?;
    let pin = h.cert_sha256.map(hex::encode);
    let v = json!({"event": "listening", "addr": h.addr.to_string(), "http_addr": h.http_addr.map(|a| a.to_string()), "domain": domain, "cert_sha256": pin});
    out.print(&v, || {
        let mut s = format!("warren relay listening on {} for {domain}\n", h.addr);
        if let Some(p) = &pin {
            s += &format!(
                "self-signed certificate; nodes join with --insecure-relay-cert-sha256 {p}\n"
            );
        }
        s
    });
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| CliError::new(exit::ERROR, "error", e.to_string()))?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    h.shutdown().await;
    Ok(())
}

async fn ctl(paths: &NodePaths, req: ControlRequest) -> CliResult {
    let r = control::request(paths, &req).await?;
    if r.ok {
        Ok(r.result)
    } else {
        Err(from_response(r))
    }
}

fn parse_target(s: &str) -> Result<(String, u16), CliError> {
    let (n, p) = s
        .rsplit_once(':')
        .ok_or_else(|| CliError::new(exit::USAGE, "usage", "target must be NODE:PORT"))?;
    let port: u16 = p
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| CliError::new(exit::USAGE, "usage", format!("invalid port {p:?}")))?;
    if !crate::valid_name(n) {
        return Err(CliError::new(
            exit::USAGE,
            "usage",
            format!("invalid node name {n:?}"),
        ));
    }
    Ok((n.to_string(), port))
}

/// Quote a string for the POSIX shell ssh uses to run ProxyCommand, escaping
/// ssh's own `%` tokens.
pub fn proxy_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''").replace('%', "%%"))
}

/// Arguments for `warren ssh`.
pub fn ssh_args(exe: &str, destination: &str, port: u16, extra: &[String]) -> Vec<String> {
    let mut v = vec![
        "-o".to_string(),
        format!("ProxyCommand={} nc %h {port}", proxy_quote(exe)),
        destination.to_string(),
    ];
    v.extend(extra.iter().cloned());
    v
}

fn human_status(v: &Value) -> String {
    let mut s = String::new();
    let conn = &v["connection"];
    s += &format!(
        "node:      {} ({})\nrelay:     {}\ndaemon:    {}\nstate:     {}{}\n",
        v["node"]["name"].as_str().unwrap_or("?"),
        v["node"]["fingerprint"].as_str().unwrap_or(""),
        v["relay"].as_str().unwrap_or("?"),
        if v["daemon"]["running"].as_bool() == Some(true) {
            "running"
        } else {
            "not running"
        },
        conn["state"].as_str().unwrap_or("?"),
        conn["latency_ms"]
            .as_f64()
            .map(|l| format!(" (latency {l:.2} ms)"))
            .unwrap_or_default(),
    );
    let shares = v["shares"].as_array().cloned().unwrap_or_default();
    s += "shares:\n";
    if shares.is_empty() {
        s += "  (none: nothing on this machine is reachable)\n";
    }
    for sh in shares {
        let to = sh["to"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "every node".into());
        s += &format!("  port {} -> {to}\n", sh["port"]);
    }
    s += "forwards:\n";
    for f in v["forwards"].as_array().cloned().unwrap_or_default() {
        s += &format!(
            "  127.0.0.1:{} -> {}:{}{}\n",
            f["local"],
            f["node"].as_str().unwrap_or(""),
            f["port"],
            f["error"]
                .as_str()
                .map(|e| format!("  [{e}]"))
                .unwrap_or_default()
        );
    }
    s += "publishes:\n";
    for p in v["publishes"].as_array().cloned().unwrap_or_default() {
        s += &format!(
            "  {} -> 127.0.0.1:{}\n",
            p["url"]
                .as_str()
                .filter(|u| !u.is_empty())
                .unwrap_or(p["name"].as_str().unwrap_or("")),
            p["port"]
        );
    }
    let errs = v["recent_errors"].as_array().cloned().unwrap_or_default();
    if !errs.is_empty() {
        s += "recent errors:\n";
        for e in errs.iter().rev().take(10) {
            s += &format!("  {}\n", e["message"].as_str().unwrap_or(""));
        }
    }
    s
}

async fn node_cmd(cmd: Command, paths: &NodePaths, out: &Out) -> Result<(), CliError> {
    match cmd {
        Command::Join {
            code,
            relay,
            name,
            insecure_relay_cert_sha256,
            force,
        } => {
            let pin = match insecure_relay_cert_sha256 {
                Some(h) => Some(crate::crypto::parse_key32(&h).ok_or_else(|| {
                    CliError::new(
                        exit::USAGE,
                        "usage",
                        "--insecure-relay-cert-sha256 needs 64 hex characters",
                    )
                })?),
                None => None,
            };
            let name = name.unwrap_or_else(node::default_name);
            match node::join(paths, &code, &relay, Some(&name), pin, force).await {
                Ok(f) => {
                    let v = json!({
                        "name": f.name,
                        "node_id": f.node_id,
                        "relay": f.relay,
                        "fingerprint": f.fingerprint(),
                        "home": paths.home,
                    });
                    out.print(&v, || {
                        format!(
                            "enrolled as {} on {}\nfingerprint {}\nnext: `warren up` (or `warren install` to start at login)",
                            f.name,
                            f.relay,
                            f.fingerprint()
                        )
                    });
                    Ok(())
                }
                Err(JoinError::AlreadyEnrolled(n)) => Err(CliError::new(
                    exit::ERROR,
                    "already_enrolled",
                    format!("already enrolled as {n:?}; use --force to enroll again with new keys"),
                )),
                Err(JoinError::Refused { code, message }) => {
                    let exit = if code == "name_taken" || code == "bad_name" {
                        exit::CONFLICT
                    } else {
                        exit::AUTH
                    };
                    Err(CliError::new(exit, &code, message))
                }
                Err(JoinError::Other(e)) => Err(CliError::new(
                    exit::NOT_CONNECTED,
                    "relay_unreachable",
                    format!("{e:#}"),
                )),
            }
        }
        Command::Down => {
            ctl(paths, ControlRequest::Shutdown).await?;
            out.print(&json!({"stopping": true}), || "stopping warren".into());
            Ok(())
        }
        Command::Status => {
            let v = match control::request(paths, &ControlRequest::Status).await {
                Ok(r) if r.ok => r.result,
                Ok(r) => return Err(from_response(r)),
                Err(ControlError::NotRunning) => {
                    let ident = IdentityFile::load(paths)?;
                    json!({
                        "node": {"name": ident.name, "node_id": ident.node_id, "fingerprint": ident.fingerprint()},
                        "relay": ident.relay,
                        "connection": {"state": "stopped", "latency_ms": null},
                        "daemon": {"running": false},
                        "shares": SharesFile::load(paths)?.shares,
                        "forwards": ForwardsFile::load(paths)?.forwards,
                        "publishes": PublishesFile::load(paths)?.publishes,
                        "recent_errors": [],
                    })
                }
                Err(e) => return Err(e.into()),
            };
            out.print(&v, || human_status(&v));
            Ok(())
        }
        Command::Share { port, to } => {
            let mut s = SharesFile::load(paths)?;
            if let Some(port) = port {
                if port == 0 {
                    return Err(CliError::new(exit::USAGE, "usage", "port must be 1-65535"));
                }
                if let Some(list) = &to {
                    if let Some(bad) = list.iter().find(|n| !crate::valid_name(n)) {
                        return Err(CliError::new(
                            exit::USAGE,
                            "usage",
                            format!("invalid node name {bad:?}"),
                        ));
                    }
                }
                s.set(port, to.clone());
                s.save(paths)?;
                let v = json!({"port": port, "to": to});
                out.print(&v, || match &to {
                    Some(l) => format!("sharing 127.0.0.1:{port} with {}", l.join(", ")),
                    None => format!("sharing 127.0.0.1:{port} with every enrolled node"),
                });
            } else {
                let v = serde_json::to_value(&s.shares).unwrap_or_default();
                out.print(&v, || {
                    if s.shares.is_empty() {
                        return "no ports shared".into();
                    }
                    s.shares
                        .iter()
                        .map(|x| {
                            format!(
                                "port {} -> {}\n",
                                x.port,
                                x.to.as_ref()
                                    .map(|l| l.join(", "))
                                    .unwrap_or_else(|| "every node".into())
                            )
                        })
                        .collect()
                });
            }
            Ok(())
        }
        Command::Unshare { port } => {
            let mut s = SharesFile::load(paths)?;
            let removed = s.remove(port);
            s.save(paths)?;
            out.print(&json!({"port": port, "removed": removed}), || {
                if removed {
                    format!("port {port} is no longer shared")
                } else {
                    format!("port {port} was not shared")
                }
            });
            Ok(())
        }
        Command::Forward {
            local,
            target,
            remove,
        } => {
            if let Some(l) = remove {
                match control::request(paths, &ControlRequest::ForwardRemove { local: l }).await {
                    Ok(r) if r.ok => {}
                    Ok(r) => return Err(from_response(r)),
                    Err(ControlError::NotRunning) => {
                        let mut f = ForwardsFile::load(paths)?;
                        let n = f.forwards.len();
                        f.forwards.retain(|x| x.local != l);
                        if n == f.forwards.len() {
                            return Err(CliError::new(
                                exit::ERROR,
                                "not_found",
                                format!("no forward on port {l}"),
                            ));
                        }
                        f.save(paths)?;
                    }
                    Err(e) => return Err(e.into()),
                }
                out.print(&json!({"removed": l}), || {
                    format!("removed forward on 127.0.0.1:{l}")
                });
                return Ok(());
            }
            match (local, target) {
                (Some(local), Some(t)) => {
                    let (node, port) = parse_target(&t)?;
                    let req = ControlRequest::ForwardAdd {
                        local,
                        node: node.clone(),
                        port,
                    };
                    let running = match control::request(paths, &req).await {
                        Ok(r) if r.ok => true,
                        Ok(r) => return Err(from_response(r)),
                        Err(ControlError::NotRunning) => {
                            IdentityFile::load(paths)?;
                            let mut f = ForwardsFile::load(paths)?;
                            f.forwards.retain(|x| x.local != local);
                            f.forwards.push(node::Forward {
                                local,
                                node: node.clone(),
                                port,
                            });
                            f.forwards.sort_by_key(|x| x.local);
                            f.save(paths)?;
                            false
                        }
                        Err(e) => return Err(e.into()),
                    };
                    let v = json!({"local": local, "node": node, "port": port, "active": running});
                    out.print(&v, || {
                        if running {
                            format!("forwarding 127.0.0.1:{local} -> {node}:{port}")
                        } else {
                            format!("saved 127.0.0.1:{local} -> {node}:{port}; it starts when `warren up` runs")
                        }
                    });
                    Ok(())
                }
                (None, None) => {
                    let v = match control::request(paths, &ControlRequest::Status).await {
                        Ok(r) if r.ok => r.result["forwards"].clone(),
                        _ => serde_json::to_value(ForwardsFile::load(paths)?.forwards)
                            .unwrap_or_default(),
                    };
                    out.print(&v, || {
                        let list = v.as_array().cloned().unwrap_or_default();
                        if list.is_empty() {
                            return "no forwards".into();
                        }
                        list.iter()
                            .map(|f| {
                                format!(
                                    "127.0.0.1:{} -> {}:{}\n",
                                    f["local"],
                                    f["node"].as_str().unwrap_or(""),
                                    f["port"]
                                )
                            })
                            .collect()
                    });
                    Ok(())
                }
                _ => Err(CliError::new(
                    exit::USAGE,
                    "usage",
                    "usage: warren forward LOCAL NODE:PORT",
                )),
            }
        }
        Command::Nc { node, port } => {
            let (mut r, mut w) = match control::open(paths, &node, port).await? {
                Ok(p) => p,
                Err(resp) => return Err(from_response(resp)),
            };
            let up = async {
                let mut stdin = tokio::io::stdin();
                let _ = tokio::io::copy(&mut stdin, &mut w).await;
                use tokio::io::AsyncWriteExt;
                let _ = w.shutdown().await;
            };
            let down = async {
                let mut stdout = tokio::io::stdout();
                let r = tokio::io::copy(&mut r, &mut stdout).await;
                use tokio::io::AsyncWriteExt;
                let _ = stdout.flush().await;
                r
            };
            tokio::pin!(up);
            tokio::pin!(down);
            // Finish when the remote side closes; stdin EOF only half-closes.
            let mut up_done = false;
            let res = loop {
                tokio::select! {
                    _ = &mut up, if !up_done => up_done = true,
                    r = &mut down => break r,
                }
            };
            // stdin may still be blocked in a read; exit without waiting for it.
            std::process::exit(if res.is_ok() { exit::OK } else { exit::ERROR });
        }
        Command::Ssh {
            destination,
            port,
            args,
        } => {
            let exe = std::env::current_exe()
                .map_err(|e| CliError::new(exit::ERROR, "error", e.to_string()))?;
            let argv = ssh_args(&exe.to_string_lossy(), &destination, port, &args);
            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new("ssh").args(&argv).exec();
            Err(CliError::new(
                exit::ERROR,
                "exec",
                format!("running ssh: {err}"),
            ))
        }
        Command::Publish {
            port,
            name,
            replace,
            allow,
        } => {
            if port == 0 {
                return Err(CliError::new(exit::USAGE, "usage", "port must be 1-65535"));
            }
            let v = ctl(
                paths,
                ControlRequest::Publish {
                    port,
                    name: name.clone(),
                    replace,
                    allow,
                },
            )
            .await?;
            out.print(&v, || {
                format!(
                    "{} -> 127.0.0.1:{port}\n(public traffic is TLS-terminated at the relay)",
                    v["url"].as_str().unwrap_or(&name)
                )
            });
            Ok(())
        }
        Command::Unpublish { name } => {
            let v = ctl(paths, ControlRequest::Unpublish { name: name.clone() }).await?;
            out.print(&v, || format!("unpublished {name}"));
            Ok(())
        }
        Command::Devices => {
            let v = ctl(paths, ControlRequest::Devices).await?;
            out.print(&v, || {
                let mut s = format!(
                    "{:<20} {:<40} {:<8} {:<8} {}\n",
                    "NAME", "FINGERPRINT", "ONLINE", "PIN", "LAST SEEN"
                );
                for d in v.as_array().cloned().unwrap_or_default() {
                    let last = d["last_seen"]
                        .as_i64()
                        .map(|t| format!("{}s ago", (crate::now_secs() - t).max(0)))
                        .unwrap_or_else(|| "never".into());
                    s += &format!(
                        "{:<20} {:<40} {:<8} {:<8} {}\n",
                        d["name"].as_str().unwrap_or(""),
                        d["fingerprint"].as_str().unwrap_or(""),
                        if d["online"].as_bool() == Some(true) {
                            "yes"
                        } else {
                            "no"
                        },
                        d["pin"].as_str().unwrap_or(""),
                        if d["online"].as_bool() == Some(true) {
                            "now".into()
                        } else {
                            last
                        },
                    );
                }
                s
            });
            Ok(())
        }
        Command::Trust { name, expect } => {
            let v = ctl(
                paths,
                ControlRequest::Trust {
                    name: name.clone(),
                    expect,
                },
            )
            .await?;
            out.print(&v, || {
                format!(
                    "{name}\n  previously pinned: {}\n  now trusted:       {}",
                    v["previous"].as_str().unwrap_or("(none)"),
                    v["current"].as_str().unwrap_or("")
                )
            });
            Ok(())
        }
        Command::Install { no_start, dir } => {
            let o = install_opts(paths, dir, !no_start)?;
            let r = install::install(&o)?;
            let v = serde_json::to_value(&r).unwrap_or_default();
            out.print(&v, || {
                if r.started {
                    format!("installed {} and started it", r.path.display())
                } else {
                    format!("wrote {} (not loaded)", r.path.display())
                }
            });
            Ok(())
        }
        Command::Uninstall { dir } => {
            let o = install_opts(paths, dir, false)?;
            let r = install::uninstall(&o)?;
            let v = serde_json::to_value(&r).unwrap_or_default();
            out.print(&v, || format!("removed {}", r.path.display()));
            Ok(())
        }
        Command::Relay(_) | Command::Up => unreachable!("handled in run"),
    }
}

fn install_opts(
    paths: &NodePaths,
    dir: Option<PathBuf>,
    start: bool,
) -> Result<InstallOptions, CliError> {
    let flavor = Flavor::current()?;
    let exe =
        std::env::current_exe().map_err(|e| CliError::new(exit::ERROR, "error", e.to_string()))?;
    let exe = exe.canonicalize().unwrap_or(exe);
    let custom_home = std::env::var_os("WARREN_HOME").is_some_and(|v| !v.is_empty());
    let home = if paths.home.is_absolute() {
        paths.home.clone()
    } else {
        std::env::current_dir()
            .map(|d| d.join(&paths.home))
            .unwrap_or_else(|_| paths.home.clone())
    };
    Ok(InstallOptions {
        flavor,
        exe,
        warren_home: home,
        custom_home,
        dir: dir.or_else(|| install::env_dir(flavor)),
        start,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses() {
        Cli::command().debug_assert();
        let c = Cli::try_parse_from(["warren", "share", "22", "--to", "a,b"]).unwrap();
        match c.command {
            Command::Share { port, to } => {
                assert_eq!(port, Some(22));
                assert_eq!(to, Some(vec!["a".into(), "b".into()]));
            }
            _ => panic!(),
        }
        let c = Cli::try_parse_from(["warren", "--json", "forward", "2222", "b:22"]).unwrap();
        assert!(c.json);
        let c = Cli::try_parse_from([
            "warren",
            "relay",
            "--domain",
            "r.example",
            "--self-signed",
            "--listen",
            "127.0.0.1:0",
        ])
        .unwrap();
        assert!(matches!(
            c.command,
            Command::Relay(RelayCmd { sub: None, .. })
        ));
        let c = Cli::try_parse_from(["warren", "relay", "invite", "--name", "b"]).unwrap();
        assert!(matches!(
            c.command,
            Command::Relay(RelayCmd {
                sub: Some(RelaySub::Invite { .. }),
                ..
            })
        ));
        let c = Cli::try_parse_from(["warren", "ssh", "me@b", "--", "uptime"]).unwrap();
        match c.command {
            Command::Ssh {
                destination,
                port,
                args,
            } => {
                assert_eq!(destination, "me@b");
                assert_eq!(port, 22);
                assert_eq!(args, vec!["uptime".to_string()]);
            }
            _ => panic!(),
        }
        assert!(
            Cli::try_parse_from(["warren", "relay", "--acme", "a@b", "--self-signed"]).is_err()
        );
    }

    use clap::CommandFactory;

    #[test]
    fn targets_and_quoting() {
        assert_eq!(parse_target("b:22").unwrap(), ("b".to_string(), 22));
        assert!(parse_target("b").is_err());
        assert!(parse_target("B:22").is_err());
        assert!(parse_target("b:0").is_err());
        let a = ssh_args("/opt/my tools/it's/warren%x", "me@b", 2200, &["-v".into()]);
        assert_eq!(a[0], "-o");
        assert_eq!(
            a[1],
            "ProxyCommand='/opt/my tools/it'\\''s/warren%%x' nc %h 2200"
        );
        assert_eq!(a[2], "me@b");
        assert_eq!(a[3], "-v");
    }

    #[test]
    fn exit_codes() {
        assert_eq!(exit_for_code("not_shared"), exit::REFUSED);
        assert_eq!(exit_for_code("key_changed"), exit::KEY_CHANGED);
        assert_eq!(exit_for_code("name_taken"), exit::CONFLICT);
        assert_eq!(exit_for_code("not_connected"), exit::NOT_CONNECTED);
        assert_eq!(exit_for_code("whatever"), exit::ERROR);
        let _ = Cli::command();
    }
}
