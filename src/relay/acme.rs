//! Automatic certificates via ACME HTTP-01 (one certificate per host, issued
//! on first claim, renewed when fewer than 30 days remain) and the plain-HTTP
//! listener that answers challenges and redirects everything else to HTTPS.
//!
//! The ACME exchange itself needs a publicly reachable relay and cannot run in
//! tests; the pieces around it (challenge responder, renewal policy,
//! certificate storage, expiry parsing) are unit-tested.

use crate::fsutil;
use crate::http::{simple_response, BufConn};
use crate::tls::CertResolver;
use anyhow::{anyhow, bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Renew when fewer than this many seconds of validity remain.
pub const RENEW_BEFORE_SECS: i64 = 30 * 86_400;
/// Let's Encrypt production directory.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// Issues and renews certificates, publishing them into the TLS resolver.
pub struct AcmeManager {
    email: String,
    directory: String,
    dir: PathBuf,
    resolver: Arc<CertResolver>,
    challenges: RwLock<HashMap<String, String>>,
    inflight: Mutex<HashSet<String>>,
    expiry: Mutex<HashMap<String, i64>>,
}

/// True if a certificate expiring at `not_after` should be renewed at `now`.
pub fn needs_renewal(not_after: i64, now: i64) -> bool {
    not_after - now < RENEW_BEFORE_SECS
}

impl AcmeManager {
    pub fn new(
        email: String,
        directory: String,
        dir: PathBuf,
        resolver: Arc<CertResolver>,
    ) -> Result<AcmeManager> {
        fsutil::ensure_private_dir(&dir)?;
        Ok(AcmeManager {
            email,
            directory,
            dir,
            resolver,
            challenges: RwLock::new(HashMap::new()),
            inflight: Mutex::new(HashSet::new()),
            expiry: Mutex::new(HashMap::new()),
        })
    }

    fn paths(&self, host: &str) -> (PathBuf, PathBuf) {
        (
            self.dir.join(format!("{host}.crt")),
            self.dir.join(format!("{host}.key")),
        )
    }

    /// Store a certificate (0600) and install it in the resolver.
    pub fn install(&self, host: &str, cert_pem: &str, key_pem: &str) -> Result<()> {
        let ck = crate::tls::certified_key_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
        let not_after = not_after_unix(ck.cert[0].as_ref())?;
        let (c, k) = self.paths(host);
        fsutil::write_private(&k, key_pem.as_bytes())?;
        fsutil::write_private(&c, cert_pem.as_bytes())?;
        self.resolver.set_host(host, ck);
        self.expiry
            .lock()
            .unwrap()
            .insert(host.to_string(), not_after);
        Ok(())
    }

    /// Load previously issued certificates from disk.
    pub fn load_existing(&self) -> Result<()> {
        for e in std::fs::read_dir(&self.dir)? {
            let p = e?.path();
            if p.extension().and_then(|x| x.to_str()) != Some("crt") {
                continue;
            }
            let Some(host) = p.file_stem().and_then(|s| s.to_str()).map(str::to_string) else {
                continue;
            };
            let (c, k) = self.paths(&host);
            fsutil::ensure_private_file(&k)?;
            match crate::tls::load_cert_files(&c, &k) {
                Ok(ck) => {
                    if let Ok(na) = not_after_unix(ck.cert[0].as_ref()) {
                        self.expiry.lock().unwrap().insert(host.clone(), na);
                    }
                    self.resolver.set_host(&host, ck);
                }
                Err(e) => tracing::warn!(%host, "ignoring unreadable certificate: {e:#}"),
            }
        }
        Ok(())
    }

    /// Answer for an HTTP-01 challenge path, if any.
    pub fn challenge_response(&self, path: &str) -> Option<String> {
        let token = path.strip_prefix(CHALLENGE_PREFIX)?;
        self.challenges.read().unwrap().get(token).cloned()
    }

    fn wants(&self, host: &str, now: i64) -> bool {
        match self.expiry.lock().unwrap().get(host) {
            Some(na) => needs_renewal(*na, now),
            None => true,
        }
    }

    /// Make sure `host` has a valid certificate, issuing in the background if needed.
    pub fn ensure(self: &Arc<Self>, host: String) {
        if !self.wants(&host, crate::now_secs()) {
            return;
        }
        if !self.inflight.lock().unwrap().insert(host.clone()) {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            match me.issue(&host).await {
                Ok(()) => tracing::info!(%host, "certificate issued"),
                Err(e) => tracing::warn!(%host, "certificate issuance failed: {e:#}"),
            }
            me.inflight.lock().unwrap().remove(&host);
        });
    }

    /// Periodically renew certificates that are close to expiry.
    pub async fn renew_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(12 * 3600)).await;
            let hosts: Vec<String> = self.expiry.lock().unwrap().keys().cloned().collect();
            for h in hosts {
                self.ensure(h);
            }
        }
    }

    async fn account(&self) -> Result<instant_acme::Account> {
        use instant_acme::{Account, AccountCredentials, NewAccount};
        let cred_path = self.dir.join("account.json");
        fsutil::ensure_private_file(&cred_path)?;
        if let Some(creds) = fsutil::read_json::<AccountCredentials>(&cred_path)? {
            return Ok(Account::builder()?.from_credentials(creds).await?);
        }
        let contact = format!("mailto:{}", self.email);
        let (account, creds) = Account::builder()?
            .create(
                &NewAccount {
                    contact: &[&contact],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.directory.clone(),
                None,
            )
            .await?;
        fsutil::write_json(&cred_path, &creds)?;
        Ok(account)
    }

    async fn issue(&self, host: &str) -> Result<()> {
        use instant_acme::{
            AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus, RetryPolicy,
        };
        let account = self.account().await?;
        let ids = [Identifier::Dns(host.to_string())];
        let mut order = account.new_order(&NewOrder::new(&ids)).await?;
        let mut tokens = Vec::new();
        {
            let mut auths = order.authorizations();
            while let Some(a) = auths.next().await {
                let mut a = a?;
                match a.status {
                    AuthorizationStatus::Valid => continue,
                    AuthorizationStatus::Pending => {}
                    s => bail!("authorization in state {s:?}"),
                }
                let mut ch = a
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| anyhow!("no http-01 challenge offered"))?;
                let token = ch.token.clone();
                let key_auth = ch.key_authorization().as_str().to_string();
                self.challenges
                    .write()
                    .unwrap()
                    .insert(token.clone(), key_auth);
                tokens.push(token);
                ch.set_ready().await?;
            }
        }
        let status = order.poll_ready(&RetryPolicy::default()).await;
        let cleanup = |tokens: &[String]| {
            let mut c = self.challenges.write().unwrap();
            for t in tokens {
                c.remove(t);
            }
        };
        let status = match status {
            Ok(s) => s,
            Err(e) => {
                cleanup(&tokens);
                return Err(e.into());
            }
        };
        cleanup(&tokens);
        if status != OrderStatus::Ready {
            bail!("order not ready: {status:?}");
        }
        let key = rcgen::KeyPair::generate()?;
        let csr = rcgen::CertificateParams::new(vec![host.to_string()])?.serialize_request(&key)?;
        order.finalize_csr(csr.der()).await?;
        let chain = order.poll_certificate(&RetryPolicy::default()).await?;
        self.install(host, &chain, &key.serialize_pem())
            .context("installing issued certificate")
    }
}

/// Plain-HTTP listener: ACME challenges, otherwise a redirect to HTTPS.
pub async fn serve_http(
    listener: TcpListener,
    acme: Option<Arc<AcmeManager>>,
    shutdown: CancellationToken,
) {
    loop {
        let (tcp, _) = tokio::select! {
            _ = shutdown.cancelled() => return,
            r = listener.accept() => match r { Ok(x) => x, Err(_) => continue },
        };
        let acme = acme.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(10), async move {
                let mut c = BufConn::new(tcp, None);
                let Ok(Some(req)) = c.read_request(8 * 1024).await else { return };
                let path = req.path.clone();
                let resp = if let Some(body) = acme.as_ref().and_then(|a| a.challenge_response(&path)) {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .into_bytes()
                } else if let Some(host) = req.host().filter(|h| is_hostname(h)) {
                    let target = if path.starts_with('/') { path } else { "/".into() };
                    format!(
                        "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{host}{target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .into_bytes()
                } else {
                    simple_response(404, "Not Found", "not found\n", true)
                };
                let _ = c.inner.write_all(&resp).await;
                let _ = c.inner.shutdown().await;
            })
            .await;
        });
    }
}

fn is_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b':')
}

/// Extract `notAfter` (Unix seconds) from a DER X.509 certificate.
pub fn not_after_unix(der: &[u8]) -> Result<i64> {
    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version OPTIONAL,
    //   serialNumber, signature, issuer, validity SEQUENCE { notBefore, notAfter } ... } }
    let (tag, cert, _) = der_next(der)?;
    ensure_tag(tag, 0x30)?;
    let (tag, tbs, _) = der_next(cert)?;
    ensure_tag(tag, 0x30)?;
    let mut rest = tbs;
    let (tag, _, r) = der_next(rest)?;
    if tag == 0xa0 {
        rest = r;
    }
    for _ in 0..3 {
        // serialNumber, signature, issuer
        let (_, _, r) = der_next(rest)?;
        rest = r;
    }
    let (tag, validity, _) = der_next(rest)?;
    ensure_tag(tag, 0x30)?;
    let (_, _, r) = der_next(validity)?; // notBefore
    let (tag, t, _) = der_next(r)?;
    parse_time(tag, t)
}

fn ensure_tag(tag: u8, want: u8) -> Result<()> {
    if tag != want {
        bail!("unexpected DER tag {tag:#x}");
    }
    Ok(())
}

fn der_next(d: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    if d.len() < 2 {
        bail!("truncated DER");
    }
    let tag = d[0];
    let (len, hdr) = if d[1] & 0x80 == 0 {
        (d[1] as usize, 2)
    } else {
        let n = (d[1] & 0x7f) as usize;
        if n == 0 || n > 4 || d.len() < 2 + n {
            bail!("bad DER length");
        }
        let mut l = 0usize;
        for b in &d[2..2 + n] {
            l = (l << 8) | *b as usize;
        }
        (l, 2 + n)
    };
    if d.len() < hdr + len {
        bail!("truncated DER");
    }
    Ok((tag, &d[hdr..hdr + len], &d[hdr + len..]))
}

fn parse_time(tag: u8, t: &[u8]) -> Result<i64> {
    let s = std::str::from_utf8(t).context("time")?;
    let s = s.strip_suffix('Z').context("time must be UTC")?;
    let (year, rest) = match tag {
        0x17 => {
            let yy: i64 = s.get(0..2).context("time")?.parse()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..])
        }
        0x18 => (s.get(0..4).context("time")?.parse()?, &s[4..]),
        _ => bail!("unexpected time tag {tag:#x}"),
    };
    let num =
        |r: std::ops::Range<usize>| -> Result<i64> { Ok(rest.get(r).context("time")?.parse()?) };
    let (mo, d, h, mi, se) = (num(0..2)?, num(2..4)?, num(4..6)?, num(6..8)?, num(8..10)?);
    Ok(days_from_civil(year, mo, d) * 86_400 + h * 3600 + mi * 60 + se)
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_until(y: i32, m: u8, d: u8, host: &str) -> (String, String) {
        let mut p = rcgen::CertificateParams::new(vec![host.to_string()]).unwrap();
        p.not_after = rcgen::date_time_ymd(y, m, d);
        let k = rcgen::KeyPair::generate().unwrap();
        (p.self_signed(&k).unwrap().pem(), k.serialize_pem())
    }

    #[test]
    fn civil_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2031, 5, 17) * 86_400, 1_936_742_400);
    }

    #[test]
    fn expiry_parsing_and_renewal_policy() {
        let (c, _) = cert_until(2031, 5, 17, "a.example");
        let der = rustls::pki_types::CertificateDer::from_pem_slice(c.as_bytes()).unwrap();
        assert_eq!(not_after_unix(der.as_ref()).unwrap(), 1_936_742_400);
        // GeneralizedTime (year >= 2050)
        let (c, _) = cert_until(2060, 1, 2, "b.example");
        let der = rustls::pki_types::CertificateDer::from_pem_slice(c.as_bytes()).unwrap();
        assert_eq!(
            not_after_unix(der.as_ref()).unwrap(),
            days_from_civil(2060, 1, 2) * 86_400
        );
        let na = 2_000_000_000;
        assert!(!needs_renewal(na, na - 31 * 86_400));
        assert!(needs_renewal(na, na - 29 * 86_400));
        assert!(needs_renewal(na, na + 1));
        assert!(not_after_unix(b"\x30\x03\x02\x01").is_err());
    }

    use rustls::pki_types::pem::PemObject;

    #[tokio::test]
    async fn storage_resolver_and_challenges() {
        let t = tempfile::tempdir().unwrap();
        let resolver = Arc::new(CertResolver::new());
        let m = Arc::new(
            AcmeManager::new(
                "ops@example.com".into(),
                LETS_ENCRYPT.into(),
                t.path().join("certs"),
                resolver.clone(),
            )
            .unwrap(),
        );
        let (c, k) = cert_until(2099, 1, 1, "web.example");
        m.install("web.example", &c, &k).unwrap();
        assert!(resolver.has_host("web.example"));
        assert!(!m.wants("web.example", crate::now_secs()));
        assert!(m.wants("other.example", crate::now_secs()));
        assert!(fsutil::is_private(&t.path().join("certs/web.example.key")).unwrap());
        assert!(fsutil::is_private(&t.path().join("certs")).unwrap());
        // A fresh manager reloads from disk.
        let r2 = Arc::new(CertResolver::new());
        let m2 = AcmeManager::new(
            "x@y".into(),
            LETS_ENCRYPT.into(),
            t.path().join("certs"),
            r2.clone(),
        )
        .unwrap();
        m2.load_existing().unwrap();
        assert!(r2.has_host("web.example"));

        // Challenge responder over real HTTP.
        m.challenges
            .write()
            .unwrap()
            .insert("tok123".into(), "tok123.thumb".into());
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let stop = CancellationToken::new();
        tokio::spawn(serve_http(l, Some(m.clone()), stop.clone()));
        let get = |path: &'static str| async move {
            use tokio::io::AsyncReadExt;
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(format!("GET {path} HTTP/1.1\r\nHost: web.example\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).await.unwrap();
            out
        };
        let r = get("/.well-known/acme-challenge/tok123").await;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        assert!(r.ends_with("tok123.thumb"));
        let r = get("/.well-known/acme-challenge/unknown").await;
        assert!(r.starts_with("HTTP/1.1 301"));
        let r = get("/page?x=1").await;
        assert!(r.contains("Location: https://web.example/page?x=1"));
        stop.cancel();
    }
}
