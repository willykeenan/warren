//! TLS configuration for both ends: the node's client config (web PKI roots or
//! a pinned certificate hash) and the relay's certificate resolver.

use anyhow::{anyhow, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

/// The crypto provider used everywhere (ring).
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// SHA-256 of a DER certificate.
pub fn cert_sha256(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

/// Client configuration for connecting to the relay. With `pin`, the relay's
/// leaf certificate must hash to exactly that value (for self-signed relays);
/// otherwise the bundled web PKI roots are used.
pub fn client_config(pin: Option<[u8; 32]>) -> Result<Arc<ClientConfig>> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;
    let mut cfg = match pin {
        Some(pin) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier {
                pin,
                algs: provider.signature_verification_algorithms,
            }))
            .with_no_client_auth(),
        None => {
            let roots = RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Server name for a host string (DNS name or IP literal).
pub fn server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_string()).map_err(|_| anyhow!("invalid server name {host}"))
}

/// Accepts exactly one certificate, identified by its SHA-256. Handshake
/// signatures are still verified against that certificate's key.
#[derive(Debug)]
struct PinVerifier {
    pin: [u8; 32],
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if crate::crypto::ct_eq(&cert_sha256(end_entity.as_ref()), &self.pin) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "relay certificate does not match the pinned SHA-256".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Build a rustls certified key from PEM text.
pub fn certified_key_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<CertifiedKey>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .context("parsing certificate PEM")?;
    if certs.is_empty() {
        return Err(anyhow!("no certificate found in PEM"));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).context("parsing private key PEM")?;
    let signing = provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| anyhow!("unsupported private key: {e}"))?;
    Ok(Arc::new(CertifiedKey::new(certs, signing)))
}

/// Load a certificate chain and key from files.
pub fn load_cert_files(cert: &Path, key: &Path) -> Result<Arc<CertifiedKey>> {
    let c = std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?;
    let k =
        crate::fsutil::read_private(key).with_context(|| format!("reading {}", key.display()))?;
    certified_key_from_pem(&c, &k)
}

/// Generate a self-signed certificate. Returns (cert PEM, key PEM).
pub fn generate_self_signed(sans: &[String]) -> Result<(String, String)> {
    let mut params = rcgen::CertificateParams::new(sans.to_vec())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "warren relay (self-signed)");
    let key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// Load (or create once) a persistent self-signed certificate in `dir` so
/// that nodes' pins survive relay restarts.
pub fn persistent_self_signed(
    dir: &Path,
    sans: &[String],
) -> Result<(Arc<CertifiedKey>, [u8; 32])> {
    let tag = crate::crypto::sha256_hex(sans.join(",").as_bytes());
    let cert_path = dir.join(format!("self-signed-{}.crt", &tag[..12]));
    let key_path = dir.join(format!("self-signed-{}.key", &tag[..12]));
    if !(cert_path.exists() && key_path.exists()) {
        let (c, k) = generate_self_signed(sans)?;
        crate::fsutil::write_private(&key_path, k.as_bytes())?;
        crate::fsutil::write_private(&cert_path, c.as_bytes())?;
    }
    #[cfg(unix)]
    crate::fsutil::ensure_private_file(&key_path)?;
    let ck = load_cert_files(&cert_path, &key_path)?;
    let fp = cert_sha256(ck.cert[0].as_ref());
    Ok((ck, fp))
}

/// Picks the relay's certificate by SNI.
#[derive(Debug, Default)]
pub struct CertResolver {
    state: RwLock<ResolverState>,
}

#[derive(Debug, Default)]
struct ResolverState {
    default: Option<Arc<CertifiedKey>>,
    exact: HashMap<String, Arc<CertifiedKey>>,
    /// Keyed by the parent domain: `*.example.com` is stored under `example.com`.
    wildcard: HashMap<String, Arc<CertifiedKey>>,
}

impl CertResolver {
    pub fn new() -> CertResolver {
        CertResolver::default()
    }

    /// Certificate used when no other entry matches (and when there is no SNI).
    pub fn set_default(&self, ck: Arc<CertifiedKey>) {
        self.state.write().unwrap().default = Some(ck);
    }

    pub fn set_host(&self, host: &str, ck: Arc<CertifiedKey>) {
        self.state
            .write()
            .unwrap()
            .exact
            .insert(host.to_ascii_lowercase(), ck);
    }

    pub fn set_wildcard(&self, parent: &str, ck: Arc<CertifiedKey>) {
        self.state
            .write()
            .unwrap()
            .wildcard
            .insert(parent.to_ascii_lowercase(), ck);
    }

    pub fn has_host(&self, host: &str) -> bool {
        self.state
            .read()
            .unwrap()
            .exact
            .contains_key(&host.to_ascii_lowercase())
    }

    pub fn lookup(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let st = self.state.read().unwrap();
        if let Some(name) = sni {
            let name = name.to_ascii_lowercase();
            if let Some(ck) = st.exact.get(&name) {
                return Some(ck.clone());
            }
            if let Some((_, parent)) = name.split_once('.') {
                if let Some(ck) = st.wildcard.get(parent) {
                    return Some(ck.clone());
                }
            }
        }
        st.default.clone()
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.lookup(client_hello.server_name())
    }
}

/// Server configuration using a resolver.
pub fn server_config(resolver: Arc<CertResolver>) -> Result<Arc<ServerConfig>> {
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_roundtrip_and_resolver() {
        let t = tempfile::tempdir().unwrap();
        let sans = vec!["relay.test".to_string(), "*.pub.test".to_string()];
        let (ck, fp) = persistent_self_signed(t.path(), &sans).unwrap();
        let (ck2, fp2) = persistent_self_signed(t.path(), &sans).unwrap();
        assert_eq!(fp, fp2, "certificate must persist across restarts");
        assert_eq!(ck.cert[0], ck2.cert[0]);
        for e in std::fs::read_dir(t.path()).unwrap() {
            let p = e.unwrap().path();
            assert!(crate::fsutil::is_private(&p).unwrap());
        }
        let r = CertResolver::new();
        assert!(r.lookup(Some("x")).is_none());
        r.set_default(ck.clone());
        let (c2, k2) = generate_self_signed(&["custom.example".to_string()]).unwrap();
        let other = certified_key_from_pem(c2.as_bytes(), k2.as_bytes()).unwrap();
        r.set_host("Custom.Example", other.clone());
        r.set_wildcard("pub.test", ck.clone());
        assert!(Arc::ptr_eq(
            &r.lookup(Some("custom.example")).unwrap(),
            &other
        ));
        assert!(Arc::ptr_eq(&r.lookup(Some("app.pub.test")).unwrap(), &ck));
        assert!(Arc::ptr_eq(&r.lookup(None).unwrap(), &ck));
        assert!(r.has_host("custom.example"));
    }

    #[test]
    fn bad_pem_rejected() {
        assert!(certified_key_from_pem(b"nope", b"nope").is_err());
    }

    #[test]
    fn client_configs_build() {
        client_config(None).unwrap();
        client_config(Some([0u8; 32])).unwrap();
        assert!(server_name("127.0.0.1").is_ok());
        assert!(server_name("relay.example.com").is_ok());
    }
}
