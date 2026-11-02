//! Password-encrypted local store.
//!
//! File format (JSON):
//! `{"version":1,"kdf":{"alg":"argon2id","m_kib":…,"t":…,"p":…,"salt":"…"},"nonce":"…","ciphertext":"…"}`
//!
//! key = Argon2id(password, salt); plaintext = JSON of the app's contents;
//! ciphertext = XChaCha20-Poly1305(key, random 24-byte nonce, AAD = header).
//! A wrong password and a tampered file both fail authentication the same way.

use std::fs;
use std::io::Write;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

pub const STORE_VERSION: u32 = 1;
/// Argon2id cost for the online app: 64 MiB, 3 passes (~0.3–1 s on a PC).
pub const DEFAULT_M_KIB: u32 = 64 * 1024;
pub const DEFAULT_T: u32 = 3;
pub const DEFAULT_P: u32 = 1;
/// Lower bounds accepted when opening a file, so a tampered header can't
/// downgrade the work factor.
const MIN_M_KIB: u32 = 19 * 1024;
const MIN_T: u32 = 2;
pub const MIN_PASSWORD_CHARS: usize = 12;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("wrong password, or the file was changed")]
    WrongPasswordOrTampered,
    #[error("the encrypted file is malformed or from an unknown version")]
    Malformed,
    #[error("key derivation failed")]
    Kdf,
    #[error("random number generator failed")]
    Random,
    #[error("file error: {0}")]
    Io(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    pub alg: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt: String,
}

impl KdfParams {
    pub fn new_random() -> Result<Self, StoreError> {
        Self::new_random_with(DEFAULT_M_KIB, DEFAULT_T, DEFAULT_P)
    }

    /// Custom cost (the offline signer uses a higher memory cost).
    pub fn new_random_with(m_kib: u32, t: u32, p: u32) -> Result<Self, StoreError> {
        let mut salt = [0u8; 16];
        crate::random_bytes(&mut salt).map_err(|_| StoreError::Random)?;
        let params = Self {
            alg: "argon2id".into(),
            m_kib,
            t,
            p,
            salt: B64.encode(salt),
        };
        params.validate()?;
        Ok(params)
    }

    /// Lowest cost accepted when opening a file (used by fast tests).
    pub const MIN_M_KIB: u32 = MIN_M_KIB;
    pub const MIN_T: u32 = MIN_T;

    fn validate(&self) -> Result<Vec<u8>, StoreError> {
        let salt = B64.decode(&self.salt).map_err(|_| StoreError::Malformed)?;
        if self.alg != "argon2id"
            || self.m_kib < MIN_M_KIB
            || self.m_kib > 4 * 1024 * 1024
            || self.t < MIN_T
            || self.t > 20
            || self.p == 0
            || self.p > 16
            || salt.len() < 16
        {
            return Err(StoreError::Malformed);
        }
        Ok(salt)
    }
}

/// Derive the 32-byte store key from the password.
pub fn derive_key(password: &str, params: &KdfParams) -> Result<Zeroizing<[u8; 32]>, StoreError> {
    let salt = params.validate()?;
    let p = Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| StoreError::Kdf)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(password.as_bytes(), &salt, key.as_mut())
        .map_err(|_| StoreError::Kdf)?;
    Ok(key)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileFormat {
    version: u32,
    kdf: KdfParams,
    nonce: String,
    ciphertext: String,
}

fn aad(kdf: &KdfParams) -> Result<Vec<u8>, StoreError> {
    // Binds the header (version + KDF settings) to the ciphertext.
    let mut a = format!("watch-wallet-store-v{STORE_VERSION}:").into_bytes();
    a.extend(serde_json::to_vec(kdf).map_err(|_| StoreError::Malformed)?);
    Ok(a)
}

/// Encrypt `contents` into the file format.
pub fn seal<T: Serialize>(
    key: &[u8; 32],
    kdf: &KdfParams,
    contents: &T,
) -> Result<Vec<u8>, StoreError> {
    let plain = Zeroizing::new(serde_json::to_vec(contents).map_err(|_| StoreError::Malformed)?);
    let mut nonce = [0u8; 24];
    crate::random_bytes(&mut nonce).map_err(|_| StoreError::Random)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let aad = aad(kdf)?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &aad,
            },
        )
        .map_err(|_| StoreError::Malformed)?;
    serde_json::to_vec_pretty(&FileFormat {
        version: STORE_VERSION,
        kdf: kdf.clone(),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ct),
    })
    .map_err(|_| StoreError::Malformed)
}

/// Read the KDF settings from a file (needed to derive the key).
pub fn read_kdf(bytes: &[u8]) -> Result<KdfParams, StoreError> {
    let f: FileFormat = serde_json::from_slice(bytes).map_err(|_| StoreError::Malformed)?;
    if f.version != STORE_VERSION {
        return Err(StoreError::Malformed);
    }
    f.kdf.validate()?;
    Ok(f.kdf)
}

/// Decrypt with an already-derived key.
pub fn open_with_key<T: DeserializeOwned>(bytes: &[u8], key: &[u8; 32]) -> Result<T, StoreError> {
    let f: FileFormat = serde_json::from_slice(bytes).map_err(|_| StoreError::Malformed)?;
    if f.version != STORE_VERSION {
        return Err(StoreError::Malformed);
    }
    f.kdf.validate()?;
    let nonce = B64.decode(&f.nonce).map_err(|_| StoreError::Malformed)?;
    if nonce.len() != 24 {
        return Err(StoreError::Malformed);
    }
    let ct = B64
        .decode(&f.ciphertext)
        .map_err(|_| StoreError::Malformed)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let aad = aad(&f.kdf)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: &aad,
                },
            )
            .map_err(|_| StoreError::WrongPasswordOrTampered)?,
    );
    serde_json::from_slice(&plain).map_err(|_| StoreError::Malformed)
}

/// Decrypt with a password. Returns the contents, the key and the KDF settings
/// (so later saves don't need the password again).
pub fn open<T: DeserializeOwned>(
    bytes: &[u8],
    password: &str,
) -> Result<(T, Zeroizing<[u8; 32]>, KdfParams), StoreError> {
    let kdf = read_kdf(bytes)?;
    let key = derive_key(password, &kdf)?;
    let contents = open_with_key(bytes, &key)?;
    Ok((contents, key, kdf))
}

/// Password rule for the online app.
pub fn check_password_rule(password: &str) -> Result<(), &'static str> {
    let n = password.chars().count();
    if n < MIN_PASSWORD_CHARS {
        return Err("Use at least 12 characters.");
    }
    if n > 256 {
        return Err("Use at most 256 characters.");
    }
    let first = password.chars().next();
    if password.chars().all(|c| Some(c) == first) {
        return Err("Don't repeat one character.");
    }
    Ok(())
}

/// Atomic write: temp file, flush to disk, rename.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let io = |e: std::io::Error| StoreError::Io(e.kind().to_string());
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(io)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp).map_err(io)?;
        f.write_all(bytes).map_err(io)?;
        f.sync_all().map_err(io)?;
    }
    fs::rename(&tmp, path).map_err(io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Demo {
        wallets: Vec<String>,
        n: u64,
    }

    /// Cheap KDF settings so tests are fast (still above the minimums).
    fn test_kdf() -> KdfParams {
        let mut k = KdfParams::new_random().expect("kdf");
        k.m_kib = MIN_M_KIB;
        k.t = MIN_T;
        k
    }

    #[test]
    fn round_trip_and_wrong_password() {
        let kdf = test_kdf();
        let key = derive_key("correct horse battery", &kdf).expect("key");
        let demo = Demo {
            wallets: vec!["savings-01".into()],
            n: 7,
        };
        let bytes = seal(&key, &kdf, &demo).expect("seal");
        let text = String::from_utf8(bytes.clone()).expect("utf8");
        assert!(
            !text.contains("savings-01"),
            "contents must not be readable"
        );
        let (back, _, _): (Demo, _, _) = open(&bytes, "correct horse battery").expect("open");
        assert_eq!(back, demo);
        assert_eq!(
            open::<Demo>(&bytes, "wrong password!!").map(|_| ()),
            Err(StoreError::WrongPasswordOrTampered)
        );
    }

    #[test]
    fn tampering_is_detected() {
        let kdf = test_kdf();
        let key = derive_key("correct horse battery", &kdf).expect("key");
        let bytes = seal(
            &key,
            &kdf,
            &Demo {
                wallets: vec![],
                n: 1,
            },
        )
        .expect("seal");
        let mut f: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        // Flip a ciphertext byte.
        let mut ct = B64
            .decode(f["ciphertext"].as_str().expect("ct"))
            .expect("b64");
        ct[0] ^= 1;
        f["ciphertext"] = B64.encode(ct).into();
        let tampered = serde_json::to_vec(&f).expect("json");
        assert_eq!(
            open_with_key::<Demo>(&tampered, &key).map(|_| ()),
            Err(StoreError::WrongPasswordOrTampered)
        );
        // Raising t in the header (bound by AAD) also fails authentication.
        let mut g: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        g["kdf"]["t"] = 4.into();
        let changed = serde_json::to_vec(&g).expect("json");
        assert_eq!(
            open_with_key::<Demo>(&changed, &key).map(|_| ()),
            Err(StoreError::WrongPasswordOrTampered)
        );
        // Downgrading the work factor below the minimum is refused outright.
        let mut h: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        h["kdf"]["m_kib"] = 8.into();
        let weak = serde_json::to_vec(&h).expect("json");
        assert_eq!(read_kdf(&weak).map(|_| ()), Err(StoreError::Malformed));
    }

    #[test]
    fn password_rule() {
        assert!(check_password_rule("short").is_err());
        assert!(check_password_rule("aaaaaaaaaaaaaaaa").is_err());
        assert!(check_password_rule("correct horse battery").is_ok());
    }
}
