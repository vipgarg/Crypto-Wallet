//! Public data derived on the signer for each network, using the same
//! derivation code as the PC app (so "verify on signer" compares like with
//! like):
//! - Bitcoin: BIP-84 account key `m/84'/0'/0'`, exported as a zpub.
//! - Ethereum: `m/44'/60'/0'/0/0`.
//! - TRON: `m/44'/195'/0'/0/0`.

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use chain_btc::{AccountXpub, Chain};

use crate::seed::{SeedError, SeedMaterial};

pub const BTC_ACCOUNT_PATH: &str = "m/84'/0'/0'";
pub const ETH_ACCOUNT_PATH: &str = "m/44'/60'/0'";
pub const TRON_ACCOUNT_PATH: &str = "m/44'/195'/0'";

/// SLIP-132 version bytes for a mainnet P2WPKH account key ("zpub").
const ZPUB_VERSION: [u8; 4] = [0x04, 0xb2, 0x47, 0x46];

pub use watch_export::{validate, WalletPublic};

fn account_xpub(master: &Xpriv, path: &str) -> Result<Xpub, SeedError> {
    let secp = Secp256k1::new();
    let path: DerivationPath = path.parse().map_err(|_| SeedError::Derivation)?;
    let acct = master
        .derive_priv(&secp, &path)
        .map_err(|_| SeedError::Derivation)?;
    Ok(Xpub::from_priv(&secp, &acct))
}

/// Serialise an account xpub with zpub version bytes.
pub fn to_zpub(xpub: &Xpub) -> String {
    let mut data = xpub.encode();
    data[..4].copy_from_slice(&ZPUB_VERSION);
    bitcoin::base58::encode_check(&data)
}

pub fn derive_public(seed: &SeedMaterial, passphrase: &str) -> Result<WalletPublic, SeedError> {
    let master = seed.master(passphrase)?;
    let secp = Secp256k1::signing_only();
    let btc = account_xpub(&master, BTC_ACCOUNT_PATH)?;
    let eth = chain_eth::derive_address(&account_xpub(&master, ETH_ACCOUNT_PATH)?, 0)
        .map_err(|_| SeedError::Derivation)?;
    let tron = chain_tron::derive_address(&account_xpub(&master, TRON_ACCOUNT_PATH)?, 0)
        .map_err(|_| SeedError::Derivation)?;
    Ok(WalletPublic {
        fingerprint: master.fingerprint(&secp).to_string(),
        btc_zpub: to_zpub(&btc),
        eth: eth.to_checksum(),
        tron: tron.to_base58(),
    })
}

/// Bitcoin receive address #`index`, computed from the exported zpub with
/// the PC app's own code path (for "verify on signer").
pub fn btc_receive_address(public: &WalletPublic, index: u32) -> Result<String, SeedError> {
    let acct: AccountXpub = public.btc_zpub.parse().map_err(|_| SeedError::Derivation)?;
    acct.derive_address(Chain::Receive, index)
        .map(|a| a.to_string())
        .map_err(|_| SeedError::Derivation)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Public test phrase; only ever used in tests.
    const TEST_WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn matches_published_vectors_and_the_pc_app() {
        let seed = SeedMaterial::from_words(TEST_WORDS).expect("seed");
        let p = derive_public(&seed, "").expect("derive");
        // BIP-84 published account zpub for this phrase.
        assert_eq!(
            p.btc_zpub,
            "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
        );
        assert_eq!(
            btc_receive_address(&p, 0).expect("r0"),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        // Widely published first Ethereum address for this phrase.
        assert_eq!(p.eth, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        assert!(p.tron.starts_with('T') && p.tron.len() == 34);
        assert_eq!(p.fingerprint, "73c5da0a");
        assert!(validate(&p));
    }

    #[test]
    fn passphrase_gives_a_different_wallet() {
        let seed = SeedMaterial::from_words(TEST_WORDS).expect("seed");
        let a = derive_public(&seed, "").expect("a");
        let b = derive_public(&seed, "extra words").expect("b");
        assert_ne!(a.btc_zpub, b.btc_zpub);
        assert_ne!(a.eth, b.eth);
        assert_ne!(a.tron, b.tron);
        assert_ne!(a.fingerprint, b.fingerprint);
    }
}
