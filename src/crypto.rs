//! Key material, authentication messages, fingerprints and enrollment codes.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, Rng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt;

/// Noise protocol name used for private streams.
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
/// Noise prologue binding handshakes to this protocol version.
pub const NOISE_PROLOGUE: &[u8] = b"warren-v1-private";

const AUTH_CONTEXT: &[u8] = b"warren-v1-auth";
const JOIN_CONTEXT: &[u8] = b"warren-v1-join";

/// Alphabet for enrollment codes: digits and upper-case letters without the
/// easily confused `0 O 1 I L`.
pub const CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
/// Length of an enrollment code.
pub const CODE_LEN: usize = 10;

/// A node's long-term keys. Secret parts never implement `Display` and are
/// redacted in `Debug`.
#[derive(Clone)]
pub struct Identity {
    pub sign: SigningKey,
    pub static_secret: [u8; 32],
    pub static_pub: [u8; 32],
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("sign_pub", &hex::encode(self.sign_pub()))
            .field("static_pub", &hex::encode(self.static_pub))
            .field("secrets", &"[redacted]")
            .finish()
    }
}

impl Identity {
    /// Generate fresh Ed25519 and X25519 keys from the OS RNG.
    pub fn generate() -> Identity {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let sign = SigningKey::from_bytes(&seed);
        let kp = snow::Builder::new(NOISE_PARAMS.parse().expect("noise params"))
            .generate_keypair()
            .expect("x25519 keypair");
        let mut static_secret = [0u8; 32];
        let mut static_pub = [0u8; 32];
        static_secret.copy_from_slice(&kp.private);
        static_pub.copy_from_slice(&kp.public);
        Identity {
            sign,
            static_secret,
            static_pub,
        }
    }

    pub fn from_parts(sign_secret: [u8; 32], static_secret: [u8; 32]) -> Identity {
        let sign = SigningKey::from_bytes(&sign_secret);
        let static_pub = x25519_public(&static_secret);
        Identity {
            sign,
            static_secret,
            static_pub,
        }
    }

    pub fn sign_pub(&self) -> [u8; 32] {
        self.sign.verifying_key().to_bytes()
    }

    pub fn sign_secret(&self) -> [u8; 32] {
        self.sign.to_bytes()
    }

    pub fn node_id(&self) -> String {
        node_id_for(&self.sign_pub())
    }

    pub fn sign_auth(&self, challenge: &[u8; 32], relay_host: &str) -> [u8; 64] {
        self.sign
            .sign(&auth_message(challenge, relay_host))
            .to_bytes()
    }

    pub fn sign_join(&self, challenge: &[u8; 32], relay_host: &str) -> [u8; 64] {
        self.sign
            .sign(&join_message(challenge, relay_host, &self.static_pub))
            .to_bytes()
    }
}

/// Compute an X25519 public key from a secret using the same X25519
/// implementation the Noise handshakes use.
pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    use snow::resolvers::{CryptoResolver, DefaultResolver};
    let resolver = DefaultResolver;
    let mut dh = resolver
        .resolve_dh(&snow::params::DHChoice::Curve25519)
        .expect("x25519");
    dh.set(secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(dh.pubkey());
    out
}

/// Message signed on every connection.
pub fn auth_message(challenge: &[u8; 32], relay_host: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(AUTH_CONTEXT.len() + 32 + relay_host.len());
    m.extend_from_slice(AUTH_CONTEXT);
    m.extend_from_slice(challenge);
    m.extend_from_slice(relay_host.as_bytes());
    m
}

/// Message signed when enrolling; binds the static key to the signing key.
pub fn join_message(challenge: &[u8; 32], relay_host: &str, static_pub: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(JOIN_CONTEXT.len() + 64 + relay_host.len());
    m.extend_from_slice(JOIN_CONTEXT);
    m.extend_from_slice(challenge);
    m.extend_from_slice(relay_host.as_bytes());
    m.extend_from_slice(static_pub);
    m
}

/// Strict Ed25519 verification.
pub fn verify(sign_pub: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(sign_pub) else {
        return false;
    };
    let Ok(sig) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    vk.verify_strict(msg, &Signature::from_bytes(&sig)).is_ok()
}

/// Stable node id derived from the signing key.
pub fn node_id_for(sign_pub: &[u8; 32]) -> String {
    let d = Sha256::digest(sign_pub);
    format!("n{}", hex::encode(&d[..10]))
}

/// Human-readable fingerprint of a public key: first 16 bytes of its SHA-256,
/// grouped for reading aloud.
pub fn fingerprint(key: &[u8]) -> String {
    let d = Sha256::digest(key);
    let h = hex::encode(&d[..16]);
    let groups: Vec<&str> = (0..h.len())
        .step_by(4)
        .map(|i| &h[i..(i + 4).min(h.len())])
        .collect();
    groups.join(":")
}

/// SHA-256 of arbitrary bytes, hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Parse 32 bytes from hex.
pub fn parse_key32(s: &str) -> Option<[u8; 32]> {
    let v = hex::decode(s.trim()).ok()?;
    <[u8; 32]>::try_from(v.as_slice()).ok()
}

/// 32 random bytes.
pub fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

/// Generate a new one-time enrollment code.
pub fn generate_code() -> String {
    let mut rng = OsRng;
    (0..CODE_LEN)
        .map(|_| CODE_ALPHABET[rng.gen_range(0..CODE_ALPHABET.len())] as char)
        .collect()
}

/// Normalize user input: upper-case, strip spaces and dashes. Returns `None`
/// if the result is not a well-formed code.
pub fn normalize_code(input: &str) -> Option<String> {
    let s: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if s.len() == CODE_LEN && s.bytes().all(|b| CODE_ALPHABET.contains(&b)) {
        Some(s)
    } else {
        None
    }
}

/// The only form in which codes are stored.
pub fn hash_code(code: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"warren-v1-invite");
    h.update(code.as_bytes());
    h.finalize().into()
}

/// Constant-time byte comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrip_and_public_derivation() {
        let id = Identity::generate();
        let back = Identity::from_parts(id.sign_secret(), id.static_secret);
        assert_eq!(back.sign_pub(), id.sign_pub());
        assert_eq!(back.static_pub, id.static_pub);
        assert!(id.node_id().starts_with('n'));
        assert!(!format!("{id:?}").contains(&hex::encode(id.static_secret)));
    }

    #[test]
    fn auth_signature_binds_challenge_and_host() {
        let id = Identity::generate();
        let ch = random32();
        let sig = id.sign_auth(&ch, "relay.example.com");
        let pk = id.sign_pub();
        assert!(verify(&pk, &auth_message(&ch, "relay.example.com"), &sig));
        assert!(!verify(
            &pk,
            &auth_message(&random32(), "relay.example.com"),
            &sig
        ));
        assert!(!verify(&pk, &auth_message(&ch, "evil.example.com"), &sig));
        let other = Identity::generate();
        assert!(!verify(
            &other.sign_pub(),
            &auth_message(&ch, "relay.example.com"),
            &sig
        ));
        assert!(!verify(
            &pk,
            &auth_message(&ch, "relay.example.com"),
            &sig[..63]
        ));
        let js = id.sign_join(&ch, "r");
        assert!(verify(&pk, &join_message(&ch, "r", &id.static_pub), &js));
        assert!(!verify(&pk, &join_message(&ch, "r", &[0u8; 32]), &js));
    }

    #[test]
    fn codes() {
        for _ in 0..200 {
            let c = generate_code();
            assert_eq!(c.len(), CODE_LEN);
            assert_eq!(normalize_code(&c).as_deref(), Some(c.as_str()));
            for bad in *b"0O1IL" {
                assert!(!c.as_bytes().contains(&bad));
            }
        }
        assert_eq!(normalize_code("abcde-fghjk").as_deref(), Some("ABCDEFGHJK"));
        assert_eq!(normalize_code("ABCDEFGHJ"), None);
        assert_eq!(normalize_code("ABCDEFGHJ0"), None);
        assert_ne!(hash_code("ABCDEFGHJK"), hash_code("ABCDEFGHJM"));
    }

    #[test]
    fn fingerprints() {
        let f = fingerprint(&[1u8; 32]);
        assert_eq!(f.len(), 32 + 7);
        assert_eq!(f.matches(':').count(), 7);
        assert_ne!(f, fingerprint(&[2u8; 32]));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert_eq!(parse_key32(&hex::encode([5u8; 32])), Some([5u8; 32]));
        assert_eq!(parse_key32("zz"), None);
    }
}
