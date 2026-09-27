//! Drives the real `warren` binary: relay, two node daemons and the CLI
//! commands, each with its own temporary WARREN_HOME. HOME itself points at a
//! temporary directory so nothing can touch the real user configuration.
//! Also checks SR8: private file modes and no secrets in logs or `--json`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

const BIN: &str = env!("CARGO_BIN_EXE_warren");

struct Env {
    root: tempfile::TempDir,
    /// Everything any command printed (stdout and stderr), for secret scans.
    transcript: std::sync::Mutex<Vec<u8>>,
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Env {
    fn new() -> Env {
        Env {
            root: tempfile::tempdir().unwrap(),
            transcript: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn p(&self, s: &str) -> PathBuf {
        self.root.path().join(s)
    }

    fn cmd(&self, home: &str) -> Command {
        let mut c = Command::new(BIN);
        #[cfg(windows)]
        c.creation_flags(warren::sys::windows::CREATE_NEW_PROCESS_GROUP);
        c.env("HOME", self.p("fakehome"))
            .env("LOCALAPPDATA", self.p("fakehome"))
            .env("WARREN_TASK_DIR", self.p("tasks"))
            .env("WARREN_HOME", self.p(home))
            // The most verbose level: secrets must not appear even here.
            .env("WARREN_LOG", "trace")
            .env("WARREN_LAUNCHD_DIR", self.p("launchd"))
            .env("WARREN_SYSTEMD_DIR", self.p("systemd"))
            .env_remove("XDG_CONFIG_HOME")
            .kill_on_drop(true);
        c
    }

    async fn run(&self, home: &str, args: &[&str]) -> Out {
        self.run_stdin(home, args, b"").await
    }

    async fn run_stdin(&self, home: &str, args: &[&str], input: &[u8]) -> Out {
        let mut c = self.cmd(home);
        c.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(input).await.unwrap();
        drop(stdin);
        let o = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
            .await
            .unwrap_or_else(|_| panic!("warren {args:?} timed out"))
            .unwrap();
        let mut t = self.transcript.lock().unwrap();
        t.extend_from_slice(&o.stdout);
        t.extend_from_slice(&o.stderr);
        Out {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into(),
            stderr: String::from_utf8_lossy(&o.stderr).into(),
        }
    }

    async fn ok(&self, home: &str, args: &[&str]) -> serde_json::Value {
        let o = self.run(home, args).await;
        assert_eq!(o.code, 0, "warren {args:?}: {}\n{}", o.stdout, o.stderr);
        serde_json::from_str(&o.stdout).unwrap_or_else(|_| panic!("not JSON: {}", o.stdout))
    }

    /// Start a long-running command with stderr going to a log file.
    fn spawn(&self, home: &str, args: &[&str], log: &Path) -> Child {
        let f = std::fs::File::create(log).unwrap();
        let mut c = self.cmd(home);
        c.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(f));
        c.spawn().unwrap()
    }
}

async fn wait_connected(env: &Env, home: &str) {
    for _ in 0..100 {
        let o = env.run(home, &["--json", "status"]).await;
        if o.code == 0 && o.stdout.contains("\"connected\"") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{home} never connected");
}

async fn echo_server() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    port
}

async fn http_server() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (r, mut w) = s.into_split();
                let mut c = warren::http::BufConn::new(r, None);
                while let Ok(Some(req)) = c.read_request(32 * 1024).await {
                    let xff = req.header_str("x-forwarded-for").unwrap_or_default();
                    let body = format!("hello from c, you are {xff}");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if w.write_all(resp.as_bytes()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_end_to_end() {
    let env = Env::new();
    std::fs::create_dir_all(env.p("fakehome")).unwrap();
    let state = env.p("relay-state");
    let state_s = state.to_str().unwrap();

    // Relay.
    let relay_log = env.p("relay.log");
    let mut relay = env.spawn(
        "relayhome",
        &[
            "--json",
            "relay",
            "--self-signed",
            "--listen",
            "127.0.0.1:0",
            "--domain",
            "127.0.0.1",
            "--publish-domain",
            "warren.test",
            "--state",
            state_s,
        ],
        &relay_log,
    );
    let mut lines = BufReader::new(relay.stdout.take().unwrap());
    let mut first = String::new();
    // The listening event is pretty-printed JSON; read until it closes.
    loop {
        let mut l = String::new();
        let n = tokio::time::timeout(Duration::from_secs(20), lines.read_line(&mut l))
            .await
            .unwrap()
            .unwrap();
        assert!(
            n > 0,
            "relay exited: {}",
            std::fs::read_to_string(&relay_log).unwrap_or_default()
        );
        first.push_str(&l);
        if l.starts_with('}') {
            break;
        }
    }
    let ev: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(ev["event"], "listening");
    let addr = ev["addr"].as_str().unwrap().to_string();
    let port: u16 = addr.rsplit(':').next().unwrap().parse().unwrap();
    let pin = ev["cert_sha256"].as_str().unwrap().to_string();
    let url = format!("https://127.0.0.1:{port}");

    // Enrollment. The invite of a self-signed relay names its pin.
    let mut codes = Vec::new();
    let v = env
        .ok(
            "relayhome",
            &["--json", "relay", "invite", "--state", state_s],
        )
        .await;
    assert_eq!(v["self_signed_cert_sha256"], serde_json::json!([pin]));
    codes.push(v["code"].as_str().unwrap().to_string());
    let o = env
        .run("relayhome", &["relay", "invite", "--state", state_s])
        .await;
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(
        o.stdout.contains(&format!(
            "--relay https://<relay host> --insecure-relay-cert-sha256 {pin}"
        )),
        "{}",
        o.stdout
    );
    codes.push(o.stdout.lines().next().unwrap().trim().to_string());
    for code in &codes {
        assert_eq!(code.len(), 10);
    }
    // A relay URL whose host is not the relay's --domain is explained.
    let o = env
        .run(
            "c",
            &[
                "join",
                &codes[0],
                "--relay",
                &format!("https://localhost:{port}"),
                "--insecure-relay-cert-sha256",
                &pin,
            ],
        )
        .await;
    assert_eq!(o.code, 5, "{}", o.stderr);
    assert!(
        o.stderr.contains("HTTP 404") && o.stderr.contains("must be the relay's --domain"),
        "{}",
        o.stderr
    );
    for (home, code) in [("a", &codes[0]), ("b", &codes[1])] {
        let v = env
            .ok(
                home,
                &[
                    "--json",
                    "join",
                    code,
                    "--relay",
                    &url,
                    "--name",
                    home,
                    "--insecure-relay-cert-sha256",
                    &pin,
                ],
            )
            .await;
        assert_eq!(v["name"], home);
        assert!(!v.to_string().contains(code.as_str()));
    }
    // Re-joining without --force is refused.
    let o = env.run("a", &["join", "ABCDEFGHJK", "--relay", &url]).await;
    assert_ne!(o.code, 0);
    assert!(o.stderr.contains("already enrolled"));
    // A used code does not work twice.
    let o = env
        .run(
            "c",
            &[
                "--json",
                "join",
                &codes[0],
                "--relay",
                &url,
                "--name",
                "c",
                "--insecure-relay-cert-sha256",
                &pin,
            ],
        )
        .await;
    assert_eq!(o.code, 8, "{}", o.stdout);
    assert!(o.stdout.contains("invalid_code"));

    // Daemons.
    let mut da = env.spawn("a", &["up"], &env.p("a.log"));
    let mut db = env.spawn("b", &["up"], &env.p("b.log"));
    wait_connected(&env, "a").await;
    wait_connected(&env, "b").await;
    let o = env.run("a", &["up"]).await;
    assert_ne!(o.code, 0, "a second daemon must refuse to start");

    // share + forward + echo.
    let echo = echo_server().await;
    let echo_s = echo.to_string();
    let o = env.run("b", &["share", &echo_s, "--to", "a"]).await;
    assert_eq!(o.code, 0, "{}", o.stderr);
    let shares = env.ok("b", &["--json", "share"]).await;
    assert_eq!(shares[0]["port"], echo);
    let local = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let target = format!("b:{echo}");
    let v = env
        .ok("a", &["--json", "forward", &local.to_string(), &target])
        .await;
    assert_eq!(v["active"], true);
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", local))
        .await
        .unwrap();
    s.write_all(b"through the forward").await.unwrap();
    s.shutdown().await.unwrap();
    let mut got = Vec::new();
    s.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"through the forward");

    // nc (as an ssh ProxyCommand would use it).
    let o = env
        .run_stdin("a", &["nc", "b", &echo_s], b"hello via nc\n")
        .await;
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.stdout, "hello via nc\n");
    // `warren ssh` hands ssh a ProxyCommand running `warren nc`. A stand-in
    // ssh runs that ProxyCommand exactly as ssh would (via sh, %h = host).
    #[cfg(unix)]
    {
        let bin = env.p("fakebin");
        std::fs::create_dir_all(&bin).unwrap();
        let script = bin.join("ssh");
        std::fs::write(
            &script,
            "#!/bin/sh\npc=\"\"\nhost=\"\"\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    -o) shift; case \"$1\" in ProxyCommand=*) pc=\"${1#ProxyCommand=}\";; esac;;\n    *) [ -z \"$host\" ] && host=\"$1\";;\n  esac\n  shift\ndone\nhost=\"${host#*@}\"\npc=$(printf '%s' \"$pc\" | sed \"s/%h/$host/g; s/%%/%/g\")\nexec sh -c \"$pc\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut c = env.cmd("a");
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        c.env("PATH", path)
            .args(["ssh", "me@b", "-p", &echo_s])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"ssh bytes\n").await.unwrap();
        drop(stdin);
        let o = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        assert_eq!(o.stdout, b"ssh bytes\n");
    }
    #[cfg(windows)]
    {
        let sink = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = sink.local_addr().unwrap().port().to_string();
        env.ok("b", &["--json", "share", &port, "--to", "a"]).await;
        let banner = tokio::spawn(async move {
            let (stream, _) = sink.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            line
        });
        let bin_dir = env.p("my tools");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let exe = bin_dir.join("warren.exe");
        std::fs::copy(BIN, &exe).unwrap();
        let mut command = Command::new(&exe);
        command
            .env("WARREN_HOME", env.p("a"))
            .args([
                "ssh",
                "me@b",
                "-p",
                &port,
                "--",
                "-oBatchMode=yes",
                "-oConnectTimeout=5",
            ])
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(20), command.output())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(255),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(tokio::time::timeout(Duration::from_secs(5), banner)
            .await
            .unwrap()
            .unwrap()
            .starts_with("SSH-2.0-"));
    }
    // Unshared port: refused with the documented exit code.
    let o = env.run_stdin("a", &["nc", "b", "1"], b"x").await;
    assert_eq!(o.code, 6, "{} {}", o.stdout, o.stderr);
    assert!(o.stderr.contains("not shared"), "{}", o.stderr);
    // b may not reach a (nothing shared there).
    let o = env
        .run_stdin("b", &["--json", "nc", "a", &echo_s], b"x")
        .await;
    assert_eq!(o.code, 6);
    assert!(o.stdout.contains("not_shared"));

    // status / devices.
    let st = env.ok("a", &["--json", "status"]).await;
    assert_eq!(st["connection"]["state"], "connected");
    assert_eq!(st["forwards"][0]["local"], local);
    let dev = env.ok("a", &["--json", "devices"]).await;
    let names: Vec<&str> = dev
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["a", "b"]);
    assert!(dev.as_array().unwrap().iter().all(|d| d["online"] == true));
    let human = env.run("a", &["status"]).await;
    assert!(
        human.stdout.contains("state:     connected"),
        "{}",
        human.stdout
    );
    let nodes = env
        .ok(
            "relayhome",
            &["--json", "relay", "nodes", "--state", state_s],
        )
        .await;
    assert_eq!(nodes.as_array().unwrap().len(), 2);

    // publish.
    let web = http_server().await;
    let v = env
        .ok(
            "b",
            &["--json", "publish", &web.to_string(), "--name", "site"],
        )
        .await;
    assert_eq!(v["url"], format!("https://site.warren.test:{port}/"));
    let o = env
        .run(
            "a",
            &["--json", "publish", &web.to_string(), "--name", "site"],
        )
        .await;
    assert_eq!(o.code, 9, "hijack must be refused: {}", o.stdout);
    {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let cfg =
            warren::tls::client_config(Some(warren::crypto::parse_key32(&pin).unwrap())).unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(cfg)
            .connect(warren::tls::server_name("site.warren.test").unwrap(), tcp)
            .await
            .unwrap();
        tls.write_all(b"GET / HTTP/1.1\r\nHost: site.warren.test\r\nX-Forwarded-For: 6.6.6.6\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        let _ = tls.read_to_end(&mut resp).await;
        let resp = String::from_utf8_lossy(&resp);
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.ends_with("you are 127.0.0.1"), "{resp}");
    }
    env.ok("b", &["--json", "unpublish", "site"]).await;

    // SR9 at runtime: every TCP connection the relay and daemons hold goes to
    // the relay port or to loopback services; nothing else is contacted.
    // Needs lsof; set WARREN_REQUIRE_LSOF=1 (as CI does) to fail without it.
    #[cfg(unix)]
    for (who, pid) in [("relay", relay.id()), ("a", da.id()), ("b", db.id())] {
        let pid = pid.unwrap().to_string();
        let Ok(o) = std::process::Command::new("lsof")
            .args(["-nP", "-a", "-p", &pid, "-iTCP", "-iUDP"])
            .output()
        else {
            assert!(
                std::env::var_os("WARREN_REQUIRE_LSOF").is_none_or(|v| v != "1"),
                "lsof is not installed and WARREN_REQUIRE_LSOF=1"
            );
            eprintln!("lsof unavailable; skipping runtime connection check");
            break;
        };
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines().skip(1) {
            assert!(!line.contains("UDP"), "{who} opened a UDP socket: {line}");
            if let Some((_, remote)) = line.split_once("->") {
                let remote = remote.split_whitespace().next().unwrap_or("");
                assert!(
                    remote.starts_with("127.0.0.1:") || remote.starts_with("[::1]:"),
                    "{who} connected to {remote}"
                );
            }
        }
        if who != "relay" {
            let relay_port = format!("->127.0.0.1:{port}");
            assert!(
                text.contains(&relay_port),
                "{who} has no relay connection:\n{text}"
            );
        }
    }

    #[cfg(windows)]
    for (who, pid) in [("relay", relay.id()), ("a", da.id()), ("b", db.id())] {
        let pid = pid.unwrap().to_string();
        let o = std::process::Command::new("netstat")
            .args(["-ano"])
            .output()
            .unwrap();
        assert!(o.status.success());
        let text = String::from_utf8_lossy(&o.stdout);
        let mut relay_seen = false;
        for line in text.lines() {
            let cols: Vec<_> = line.split_whitespace().collect();
            if cols.last().copied() != Some(pid.as_str()) {
                continue;
            }
            assert_ne!(cols[0], "UDP", "{who}: {line}");
            if cols[0] == "TCP" && cols.len() >= 5 {
                let remote = cols[2];
                assert!(
                    remote.starts_with("127.0.0.1:")
                        || remote.starts_with("[::1]:")
                        || remote == "0.0.0.0:0"
                        || remote == "[::]:0",
                    "{who}: {line}"
                );
                relay_seen |= remote == format!("127.0.0.1:{port}");
            }
        }
        if who != "relay" {
            assert!(relay_seen, "{who} has no relay connection: {text}");
        }
    }
    // Exit codes for common failure modes.
    let o = env.run("fresh", &["--json", "status"]).await;
    assert_eq!(o.code, 3, "not enrolled: {}", o.stdout);
    let o = env.run("a", &["forward", "1234", "B:22"]).await;
    assert_eq!(o.code, 2);
    let o = env
        .run("a", &["--json", "trust", "b", "--expect", "0000"])
        .await;
    assert_eq!(o.code, 7);

    // install writes only into the overridden directory and never loads it.
    let v = env.ok("a", &["--json", "install"]).await;
    let path = PathBuf::from(v["path"].as_str().unwrap());
    let expected_dir = if cfg!(target_os = "macos") {
        env.p("launchd")
    } else if cfg!(windows) {
        env.p("tasks")
    } else {
        env.p("systemd")
    };
    assert!(path.starts_with(&expected_dir), "{}", path.display());
    assert_eq!(v["started"], false);
    #[cfg(unix)]
    let unit = std::fs::read_to_string(&path).unwrap();
    #[cfg(windows)]
    let unit = {
        let b = std::fs::read(&path).unwrap();
        String::from_utf16(
            &b[2..]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        )
        .unwrap()
    };
    assert!(
        unit.contains(BIN)
            || unit.contains(
                &std::fs::canonicalize(BIN)
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            )
    );
    assert!(unit.contains(if cfg!(windows) {
        "--home"
    } else {
        "WARREN_HOME"
    }));
    env.ok("a", &["--json", "uninstall"]).await;
    assert!(!path.exists());

    // Stop everything.
    env.ok("a", &["--json", "down"]).await;
    env.ok("b", &["--json", "down"]).await;
    for d in [&mut da, &mut db] {
        let st = tokio::time::timeout(Duration::from_secs(10), d.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(st.success());
    }
    let o = env.run("a", &["--json", "devices"]).await;
    assert_eq!(o.code, 4, "daemon not running: {}", o.stdout);
    let st = env.ok("a", &["--json", "status"]).await;
    assert_eq!(st["daemon"]["running"], false);
    #[cfg(unix)]
    {
        let pid = rustix::process::Pid::from_raw(relay.id().unwrap() as i32).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    }
    #[cfg(windows)]
    warren::sys::windows::send_ctrl_break(relay.id().unwrap()).unwrap();
    let st = tokio::time::timeout(Duration::from_secs(10), relay.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(st.success());

    // SR8: modes.
    let private = |p: &Path| warren::fsutil::is_private(p).unwrap();
    for home in ["a", "b"] {
        let h = env.p(home);
        assert!(private(&h), "{home}");
        for f in std::fs::read_dir(&h).unwrap() {
            let p = f.unwrap().path();
            if p.is_file() || p.is_dir() {
                assert!(private(&p), "{}", p.display());
            }
        }
    }
    assert!(private(&state));
    for f in std::fs::read_dir(&state).unwrap() {
        let p = f.unwrap().path();
        if p.is_file() {
            assert!(private(&p), "{}", p.display());
        }
    }

    // SR8: secrets never appear in logs or --json output.
    let mut everything = env.transcript.lock().unwrap().clone();
    let mut logs = Vec::new();
    for l in ["relay.log", "a.log", "b.log"] {
        logs.extend(std::fs::read(env.p(l)).unwrap());
    }
    assert!(logs.len() > 500, "trace logs were produced");
    everything.extend_from_slice(&logs);
    for home in ["a", "b"] {
        let id: serde_json::Value =
            serde_json::from_slice(&std::fs::read(env.p(home).join("identity.json")).unwrap())
                .unwrap();
        for k in ["sign_secret", "static_secret"] {
            let s = id[k].as_str().unwrap();
            assert_eq!(s.len(), 64);
            assert!(!contains(&everything, s.as_bytes()), "{home} {k} leaked");
            assert!(
                !contains(&everything, &s.as_bytes()[..20]),
                "{home} {k} prefix leaked"
            );
        }
    }
    // Enrollment codes appear only in `relay invite` output, never in logs.
    for c in &codes {
        assert!(!contains(&logs, c.as_bytes()), "enrollment code in logs");
    }
    // The relay key file stays private.
    let keyfile = std::fs::read_dir(&state)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "key"))
        .unwrap();
    let key_pem = std::fs::read_to_string(&keyfile).unwrap();
    let key_body: String = key_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    assert!(!contains(&everything, &key_body.as_bytes()[..40]));
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}
