//! USDT on Ethereum signing on the tablet (ARCHITECTURE.md §8.3 pre-sign
//! validator).
//!
//! **Test network only in this build: Ethereum Sepolia.** The only token
//! signed is the pinned Sepolia test USDT, on chain id 11155111, so a
//! mainnet transaction can't be signed by mistake.
//!
//! The tablet works everything out from the unsigned EIP-1559 transaction:
//! one plain 68-byte `transfer(recipient, amount)` to the pinned contract,
//! no ETH sent along, no access list; gas limit at most 120,000 and a
//! worst-case fee (gas limit × max fee) of at most 0.05 test ETH. The sender
//! is whoever signs: this wallet's own key (`m/44'/60'/0'/0/0`).
//!
//! Unlike TRON, an Ethereum transaction has no expiry: a signed one stays
//! valid until its nonce is used. Sign only what you mean to send now.

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use chain_eth::EthAddress;
use eth_tx::{Erc20Transfer, TxError};
use thiserror::Error;

pub use eth_tx::{SEPOLIA_CHAIN_ID, SEPOLIA_USDT};
/// Highest gas limit accepted.
pub const MAX_GAS_LIMIT: u64 = 120_000;
/// Highest worst-case fee accepted (0.05 ETH, in wei).
pub const MAX_FEE_WEI: u128 = 50_000_000_000_000_000;
/// Ethereum key path, as for the watch-only export.
pub const ETH_KEY_PATH: &str = "m/44'/60'/0'/0/0";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EthSignError {
    #[error("{0}")]
    Tx(#[from] TxError),
    #[error("refused: {0}")]
    Refused(String),
    #[error("key derivation failed")]
    Derivation,
}

fn refuse<T>(why: impl Into<String>) -> Result<T, EthSignError> {
    Err(EthSignError::Refused(why.into()))
}

/// What the tablet shows before you approve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthReview {
    pub network: String,
    pub from: String,
    pub recipient: String,
    pub amount_usdt: String,
    pub amount_base: u128,
    /// Worst case (gas limit × max fee), in ETH.
    pub max_fee_eth: String,
    pub nonce: u64,
    /// Hex of the signing hash (the transaction hash is only known after
    /// signing).
    pub signing_hash: String,
}

fn key(master: &Xpriv) -> Result<(secp256k1::SecretKey, EthAddress), EthSignError> {
    let secp = Secp256k1::new();
    let path: DerivationPath = ETH_KEY_PATH.parse().map_err(|_| EthSignError::Derivation)?;
    let k = master
        .derive_priv(&secp, &path)
        .map_err(|_| EthSignError::Derivation)?;
    let addr = EthAddress::from_public_key(&k.private_key.public_key(&secp));
    let sk = secp256k1::SecretKey::from_slice(&k.private_key.secret_bytes())
        .map_err(|_| EthSignError::Derivation)?;
    Ok((sk, addr))
}

/// This wallet's Ethereum address.
pub fn wallet_address(master: &Xpriv) -> Result<EthAddress, EthSignError> {
    Ok(key(master)?.1)
}

fn decimal(v: u128, decimals: u32) -> String {
    let d = 10u128.pow(decimals);
    let (w, f) = (v / d, v % d);
    if f == 0 {
        w.to_string()
    } else {
        let f = format!("{f:0w$}", w = decimals as usize);
        format!("{w}.{}", f.trim_end_matches('0'))
    }
}

/// Check an unsigned transaction for signing.
pub fn review(unsigned: &[u8], master: &Xpriv) -> Result<EthReview, EthSignError> {
    let t = Erc20Transfer::decode_unsigned(unsigned)?;
    let (_, me) = key(master)?;
    if t.chain_id != SEPOLIA_CHAIN_ID {
        return refuse("this isn't the Ethereum Sepolia test network (this build only signs test-network USDT)");
    }
    let usdt: EthAddress = SEPOLIA_USDT.parse().map_err(|_| EthSignError::Derivation)?;
    if t.token != usdt {
        return refuse("this isn't the Sepolia test USDT contract");
    }
    if t.amount == 0 {
        return refuse("the amount is zero");
    }
    if t.recipient == me {
        return refuse("the recipient is this wallet itself");
    }
    if t.gas_limit == 0 || t.gas_limit > MAX_GAS_LIMIT {
        return refuse(format!(
            "the gas limit must be between 1 and {MAX_GAS_LIMIT}"
        ));
    }
    if t.max_priority_fee_per_gas > t.max_fee_per_gas {
        return refuse("the priority fee is higher than the max fee");
    }
    let worst = u128::from(t.gas_limit).saturating_mul(t.max_fee_per_gas);
    if worst > MAX_FEE_WEI {
        return refuse("the maximum network fee is over 0.05 test ETH");
    }
    Ok(EthReview {
        network: "Ethereum Sepolia (test network, coins have no value)".into(),
        from: me.to_checksum(),
        recipient: t.recipient.to_checksum(),
        amount_usdt: decimal(t.amount, 6),
        amount_base: t.amount,
        max_fee_eth: decimal(worst, 18),
        nonce: t.nonce,
        signing_hash: eth_tx::signing_hash(unsigned)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    })
}

/// Sign the reviewed transaction (checks run again). Returns r ‖ s ‖ y_parity.
pub fn sign(unsigned: &[u8], master: &Xpriv) -> Result<([u8; 65], EthReview), EthSignError> {
    let review = review(unsigned, master)?;
    let (sk, me) = key(master)?;
    let sig = eth_tx::sign(unsigned, &sk);
    if eth_tx::recover_signer(unsigned, &sig)? != me {
        return Err(EthSignError::Derivation);
    }
    Ok((sig, review))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::NetworkKind;

    fn master() -> Xpriv {
        Xpriv::new_master(NetworkKind::Main, &[9u8; 64]).expect("m")
    }

    fn tx() -> Erc20Transfer {
        Erc20Transfer {
            chain_id: SEPOLIA_CHAIN_ID,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 20_000_000_000,
            gas_limit: 65_000,
            token: SEPOLIA_USDT.parse().expect("usdt"),
            recipient: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
                .parse()
                .expect("to"),
            amount: 7_250_000,
        }
    }

    fn refused(r: Result<EthReview, EthSignError>, needle: &str) {
        match r {
            Err(EthSignError::Refused(m)) => assert!(m.contains(needle), "{m}"),
            other => panic!("expected refusal '{needle}', got {other:?}"),
        }
    }

    #[test]
    fn honest_transfer_reviews_and_signs() {
        let m = master();
        let raw = tx().encode_unsigned();
        let r = review(&raw, &m).expect("review");
        assert_eq!(r.amount_usdt, "7.25");
        assert_eq!(r.max_fee_eth, "0.0013");
        let (sig, _) = sign(&raw, &m).expect("sign");
        assert_eq!(
            eth_tx::recover_signer(&raw, &sig),
            Ok(wallet_address(&m).expect("me"))
        );
    }

    #[test]
    fn same_address_as_the_watch_only_export() {
        // Widely published first Ethereum address of the all-"abandon" test phrase.
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = crate::seed::SeedMaterial::from_words(words).expect("seed");
        let m = seed.master("").expect("master");
        assert_eq!(
            wallet_address(&m).expect("me").to_checksum(),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
    }

    #[test]
    fn refuses_mainnet_other_tokens_and_odd_values() {
        let m = master();
        let mut t = tx();
        t.chain_id = 1;
        refused(review(&t.encode_unsigned(), &m), "Sepolia");
        let mut t = tx();
        t.token = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
            .parse()
            .expect("mainnet usdt");
        refused(review(&t.encode_unsigned(), &m), "test USDT");
        let mut t = tx();
        t.amount = 0;
        refused(review(&t.encode_unsigned(), &m), "zero");
        let mut t = tx();
        t.recipient = wallet_address(&m).expect("me");
        refused(review(&t.encode_unsigned(), &m), "itself");
        let mut t = tx();
        t.gas_limit = 500_000;
        refused(review(&t.encode_unsigned(), &m), "gas limit");
        let mut t = tx();
        t.max_fee_per_gas = 1_000_000_000_000;
        refused(review(&t.encode_unsigned(), &m), "0.05");
        let mut t = tx();
        t.max_priority_fee_per_gas = t.max_fee_per_gas + 1;
        refused(review(&t.encode_unsigned(), &m), "priority");
    }
}
