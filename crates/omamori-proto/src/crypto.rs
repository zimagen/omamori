//! RustCrypto primitives and the exact v1 domain-separated constructions.
use crate::wire::{Entry, HostId, Mac, Nonce, RequestId};
use hkdf::Hkdf;
use hmac::{Hmac, Mac as _};
use p256::{PublicKey, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Owned shared key. Debug never prints secret bytes; storage callers must
/// protect any copy they explicitly obtain through `as_bytes`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; 32]);
impl Key {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidKey,
}

/// P-256 private scalars are zeroized on drop by RustCrypto's SecretKey.
pub struct KeyPair(SecretKey);
impl KeyPair {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(SecretKey::random(rng))
    }
    /// For fixed test vectors. The scalar must be nonzero and below the order.
    pub fn from_scalar(bytes: &[u8; 32]) -> Result<Self, Error> {
        SecretKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }
    pub fn public(&self) -> [u8; 65] {
        self.0
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .expect("uncompressed P-256")
    }
    pub fn derive_key(
        &self,
        peer: &[u8; 65],
        host_nonce: &Nonce,
        watch_nonce: &Nonce,
        host_id: &HostId,
    ) -> Result<Key, Error> {
        if peer[0] != 4 {
            return Err(Error::InvalidKey);
        }
        let peer = PublicKey::from_sec1_bytes(peer).map_err(|_| Error::InvalidKey)?;
        let shared = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), peer.as_affine());
        // SharedSecret also zeroizes on drop.
        Ok(derive_key(
            shared.raw_secret_bytes().as_ref(),
            host_nonce,
            watch_nonce,
            host_id,
        ))
    }
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

pub fn hmac_sha256(key: &Key, parts: &[&[u8]]) -> Mac {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC supports every key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    bool::from(left.ct_eq(right))
}

pub fn derive_key(z: &[u8; 32], host_nonce: &Nonce, watch_nonce: &Nonce, host_id: &HostId) -> Key {
    let mut salt = [0; 32];
    salt[..16].copy_from_slice(host_nonce);
    salt[16..].copy_from_slice(watch_nonce);
    let mut info = b"omamori/v1/key".to_vec();
    info.extend_from_slice(host_id);
    let mut bytes = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(&salt), z)
        .expand(&info, &mut *bytes)
        .expect("32-byte HKDF output");
    Key::new(*bytes)
}

pub fn commitment(watch_pub: &[u8; 65], watch_nonce: &Nonce) -> Mac {
    sha256(&[b"omamori/v1/commit", watch_pub, watch_nonce])
}

pub fn transcript(commit: &[u8], host: &[u8], reveal: &[u8]) -> Mac {
    sha256(&[commit, host, reveal])
}

/// Six digits, including leading zeros.
pub fn sas(key: &Key, transcript: &Mac) -> String {
    let mac = hmac_sha256(key, &[b"omamori/v1/sas", transcript]);
    let number = u32::from_be_bytes(mac[..4].try_into().expect("four bytes")) % 1_000_000;
    format!("{number:06}")
}

pub fn pending_mac(key: &Key, watch_nonce: &Nonce, message_before_mac: &[u8]) -> Mac {
    hmac_sha256(
        key,
        &[b"omamori/v1/pending", watch_nonce, message_before_mac],
    )
}

pub fn approve_mac(key: &Key, host_id: &HostId, watch_nonce: &Nonce, entry: &Entry) -> Mac {
    let title = crate::wire::truncate_str(&entry.title);
    let detail = crate::wire::truncate_str(&entry.detail);
    let contents = sha256(&[title.as_bytes(), &[0], detail.as_bytes()]);
    hmac_sha256(
        key,
        &[
            b"omamori/v1/approve",
            host_id,
            watch_nonce,
            &entry.req_id,
            &[entry.kind as u8],
            &contents,
        ],
    )
}

pub fn result_mac(key: &Key, watch_nonce: &Nonce, req_id: &RequestId, status: u8) -> Mac {
    hmac_sha256(key, &[b"omamori/v1/result", watch_nonce, req_id, &[status]])
}

pub fn watch_confirm_mac(key: &Key, transcript: &Mac) -> Mac {
    hmac_sha256(key, &[b"omamori/v1/pair-ok/watch", transcript])
}

pub fn host_confirm_mac(key: &Key, transcript: &Mac) -> Mac {
    hmac_sha256(key, &[b"omamori/v1/pair-ok/host", transcript])
}
