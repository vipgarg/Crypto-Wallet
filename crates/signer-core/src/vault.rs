//! Encrypted vault file for a **stored** wallet on the signer (Spending,
//! Savings), ARCHITECTURE.md §6.4.
//!
//! - One file per wallet, each with its own password.
//! - Contains the BIP-39 entropy, never the passphrase. For wallets with a
//!   passphrase, the expected master fingerprint is stored so a mistyped
//!   passphrase is caught at unlock.
//! - Vault-tier wallets are **stateless**: no file at all; the seed is
//!   scanned from a SeedQR card at signing time (not in this module).
//! - Argon2id 256 MiB / 3 passes by default (higher than the PC app).

use auth::store::{self, KdfParams, StoreError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wallet_types::{Tier, WalletId};
use zeroize::Zeroizing;

use crate::accounts::{self, WalletPublic};
use crate::seed::SeedMaterial;

pub const SIGNER_M_KIB: u32 = 256 * 1024;
pub const SIGNER_T: u32 = 3;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultError {
    #[error("wrong vault password, or the vault file was changed")]
    WrongPassword,
    #[error("the passphrase doesn't match this wallet (fingerprint differs)")]
    WrongPassphrase,
    #[error("Vault-tier wallets are stateless and are never stored on the signer")]
    VaultTierNotStored,
    #[error("vault file error: {0}")]
    Store(String),
}

impl From<StoreError> for VaultError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::WrongPasswordOrTampered => VaultError::WrongPassword,
            other => VaultError::Store(other.to_string()),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultContents {
    version: u32,
    id: WalletId,
    label: String,
    tier: Tier,
    entropy_hex: String,
    uses_passphrase: bool,
    public: WalletPublic,
    /// A real-network wallet (made by a real-networks build). Absent in
    /// older vaults: test wallet.
    #[serde(default)]
    real: bool,
    /// Waiting period (minutes) a real wallet's policy starts with, chosen
    /// when the wallet was made. Absent: 24 hours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    real_wait_minutes: Option<u32>,
}

/// An unlocked stored wallet: kept only for one signing session, then dropped
/// (which wipes the entropy).
pub struct UnlockedWallet {
    pub id: WalletId,
    pub label: String,
    pub tier: Tier,
    pub public: WalletPublic,
    pub uses_passphrase: bool,
    pub seed: SeedMaterial,
    /// Real-network wallet (see `mode`).
    pub real: bool,
    /// The real-network waiting period its policy starts with (minutes).
    pub real_wait_minutes: Option<u32>,
}

/// What describes a stored wallet (everything except secrets).
pub struct WalletInfo {
    pub id: WalletId,
    pub label: String,
    pub tier: Tier,
    /// Derived with the passphrase the user chose (or "" for none).
    pub public: WalletPublic,
    pub uses_passphrase: bool,
    /// For a real wallet: the waiting period its policy starts with
    /// (10 to 1440 minutes; None = 24 hours). Ignored for test wallets.
    pub real_wait_minutes: Option<u32>,
}

/// Encrypt a new stored wallet with its own vault password.
pub fn create(
    info: &WalletInfo,
    seed: &SeedMaterial,
    vault_password: &str,
    kdf: KdfParams,
) -> Result<Vec<u8>, VaultError> {
    if info.tier == Tier::Vault {
        return Err(VaultError::VaultTierNotStored);
    }
    store::check_password_rule(vault_password).map_err(|e| VaultError::Store(e.into()))?;
    if info
        .real_wait_minutes
        .is_some_and(|m| !(10..=1440).contains(&m))
    {
        return Err(VaultError::Store(
            "the waiting period must be 10 to 1440 minutes".into(),
        ));
    }
    let real = crate::mode::Mode::of_this_build() == crate::mode::Mode::Real;
    let key = store::derive_key(vault_password, &kdf)?;
    let contents = Zeroizing::new(
        serde_json::to_vec(&VaultContents {
            version: 1,
            id: info.id.clone(),
            label: info.label.clone(),
            tier: info.tier,
            entropy_hex: hex::encode(seed.entropy()),
            uses_passphrase: info.uses_passphrase,
            public: info.public.clone(),
            real,
            real_wait_minutes: if real { info.real_wait_minutes } else { None },
        })
        .map_err(|e| VaultError::Store(e.to_string()))?,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&contents).map_err(|e| VaultError::Store(e.to_string()))?;
    Ok(store::seal(&key, &kdf, &value)?)
}

/// Default (strong) KDF settings for new vaults on the signer.
pub fn signer_kdf() -> Result<KdfParams, VaultError> {
    Ok(KdfParams::new_random_with(SIGNER_M_KIB, SIGNER_T, 1)?)
}

/// Unlock a stored wallet: vault password, then the passphrase (if the wallet
/// uses one), which must reproduce the recorded fingerprint.
pub fn unlock(
    bytes: &[u8],
    vault_password: &str,
    passphrase: &str,
) -> Result<UnlockedWallet, VaultError> {
    let (c, _key, _kdf): (VaultContents, _, _) = store::open(bytes, vault_password)?;
    let entropy = Zeroizing::new(
        hex::decode(&c.entropy_hex).map_err(|_| VaultError::Store("damaged".into()))?,
    );
    let seed =
        SeedMaterial::from_entropy_bytes(&entropy).map_err(|e| VaultError::Store(e.to_string()))?;
    let pass = if c.uses_passphrase { passphrase } else { "" };
    let derived =
        accounts::derive_public(&seed, pass).map_err(|e| VaultError::Store(e.to_string()))?;
    if derived.fingerprint != c.public.fingerprint {
        return Err(VaultError::WrongPassphrase);
    }
    if derived != c.public {
        return Err(VaultError::Store(
            "stored public data doesn't match the seed".into(),
        ));
    }
    Ok(UnlockedWallet {
        id: c.id,
        label: c.label,
        tier: c.tier,
        public: c.public,
        uses_passphrase: c.uses_passphrase,
        seed,
        real: c.real,
        real_wait_minutes: c.real_wait_minutes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_kdf() -> KdfParams {
        KdfParams::new_random_with(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1).expect("kdf")
    }

    #[test]
    fn create_and_unlock_with_passphrase() {
        let seed = SeedMaterial::from_entropy(&[11u8; 32]);
        let public = accounts::derive_public(&seed, "my secret phrase").expect("pub");
        let id: WalletId = "savings-01".parse().expect("id");
        let info = WalletInfo {
            id,
            label: "Savings".into(),
            tier: Tier::Savings,
            public: public.clone(),
            uses_passphrase: true,
            real_wait_minutes: None,
        };
        let file = create(&info, &seed, "vault password 123", fast_kdf()).expect("create");
        let text = String::from_utf8_lossy(&file);
        assert!(
            !text.contains(&public.eth),
            "nothing readable without the password"
        );

        let w = unlock(&file, "vault password 123", "my secret phrase").expect("unlock");
        assert_eq!(w.public, public);
        assert_eq!(w.seed.entropy(), seed.entropy());

        assert_eq!(
            unlock(&file, "wrong password!!", "my secret phrase").map(|_| ()),
            Err(VaultError::WrongPassword)
        );
        assert_eq!(
            unlock(&file, "vault password 123", "my secret phrasee").map(|_| ()),
            Err(VaultError::WrongPassphrase),
            "a mistyped passphrase is caught"
        );
    }

    #[test]
    fn vault_tier_is_never_stored() {
        let seed = SeedMaterial::from_entropy(&[12u8; 32]);
        let public = accounts::derive_public(&seed, "").expect("pub");
        let info = WalletInfo {
            id: "vault-01".parse().expect("id"),
            label: "Vault".into(),
            tier: Tier::Vault,
            public,
            uses_passphrase: true,
            real_wait_minutes: None,
        };
        let r = create(&info, &seed, "vault password 123", fast_kdf());
        assert_eq!(r.map(|_| ()), Err(VaultError::VaultTierNotStored));
    }

    #[test]
    fn default_kdf_is_strong() {
        let k = signer_kdf().expect("kdf");
        assert_eq!((k.m_kib, k.t), (SIGNER_M_KIB, SIGNER_T));
    }
}
