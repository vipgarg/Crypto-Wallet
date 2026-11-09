//! TRON USDT signing on the tablet (ARCHITECTURE.md §8.3 pre-sign validator).
//!
//! **Test network only in this build: TRON Nile.** The only token this
//! build signs for is the pinned **Nile** test USDT contract, so a
//! transaction for mainnet USDT is refused (it can't be signed by mistake).
//!
//! The tablet works everything out from the raw transaction:
//! - exactly one `TriggerSmartContract` call, to the pinned test USDT
//!   contract, from this wallet's own TRON address (derived here);
//! - a plain 68-byte `transfer(recipient, amount)`, no TRX or other token
//!   sent along, no memo, owner permission only;
//! - fee limit at most 30 TRX;
//! - expiration at most 10 minutes after the transaction's timestamp, and
//!   not already long past by this tablet's clock.

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use chain_tron::TronAddress;
use serde::Serialize;
use thiserror::Error;
use tron_tx::{Trc20Transfer, TxError};

/// The only TRC-20 contract this build signs for: Nile test USDT.
pub use tron_tx::NILE_USDT;
/// Highest fee limit accepted (30 TRX, in sun).
pub const MAX_FEE_LIMIT_SUN: u64 = 30_000_000;
/// Longest validity accepted (expiration minus timestamp).
pub const MAX_VALIDITY_MS: u64 = 10 * 60 * 1000;
/// Tolerance for this tablet's clock when checking expiration.
pub const CLOCK_TOLERANCE_MS: u64 = 10 * 60 * 1000;
/// TRON address path (BIP-44 coin type 195), as for the watch-only export.
pub const TRON_KEY_PATH: &str = "m/44'/195'/0'/0/0";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TronSignError {
    #[error("{0}")]
    Tx(#[from] TxError),
    #[error("refused: {0}")]
    Refused(String),
    #[error("key derivation failed")]
    Derivation,
}

fn refuse<T>(why: impl Into<String>) -> Result<T, TronSignError> {
    Err(TronSignError::Refused(why.into()))
}

/// What the tablet shows before you approve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TronReview {
    pub network: String,
    pub from: String,
    pub recipient: String,
    /// Exact decimal USDT amount, e.g. "12.5".
    pub amount_usdt: String,
    pub fee_limit_trx: String,
    pub txid: String,
}

fn key(master: &Xpriv) -> Result<(bitcoin::secp256k1::SecretKey, TronAddress), TronSignError> {
    let secp = Secp256k1::new();
    let path: DerivationPath = TRON_KEY_PATH
        .parse()
        .map_err(|_| TronSignError::Derivation)?;
    let k = master
        .derive_priv(&secp, &path)
        .map_err(|_| TronSignError::Derivation)?;
    let sk = k.private_key;
    let pk = sk.public_key(&secp);
    // Same secp256k1 version as tron-tx: convert through bytes.
    let pk2 =
        secp256k1::PublicKey::from_slice(&pk.serialize()).map_err(|_| TronSignError::Derivation)?;
    Ok((sk, tron_tx::address_of(&pk2)))
}

/// This wallet's TRON address (derived from the seed).
pub fn wallet_address(master: &Xpriv) -> Result<TronAddress, TronSignError> {
    Ok(key(master)?.1)
}

fn usdt_text(v: u128) -> String {
    let whole = v / 1_000_000;
    let frac = v % 1_000_000;
    if frac == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{}", format!("{frac:06}").trim_end_matches('0'))
    }
}

/// Check a raw transaction for signing. `now_ms` is the tablet's clock.
pub fn review(raw: &[u8], master: &Xpriv, now_ms: u64) -> Result<TronReview, TronSignError> {
    let t = Trc20Transfer::decode_raw(raw)?;
    let (_, me) = key(master)?;
    let usdt: TronAddress = NILE_USDT.parse().map_err(|_| TronSignError::Derivation)?;
    if t.token != usdt {
        return refuse(
            "this isn't the TRON Nile test USDT contract (this build only signs test-network USDT)",
        );
    }
    if t.owner != me {
        return refuse("the transaction isn't from this wallet's TRON address");
    }
    if t.amount == 0 {
        return refuse("the amount is zero");
    }
    if t.recipient == me {
        return refuse("the recipient is this wallet itself");
    }
    if t.fee_limit_sun == 0 || t.fee_limit_sun > MAX_FEE_LIMIT_SUN {
        return refuse(format!(
            "the fee limit must be between 0 and {} TRX",
            MAX_FEE_LIMIT_SUN / 1_000_000
        ));
    }
    let validity = t.expiration_ms.checked_sub(t.timestamp_ms);
    if !validity.is_some_and(|v| (1..=MAX_VALIDITY_MS).contains(&v)) {
        return refuse("the transaction's validity period is unusual (more than 10 minutes)");
    }
    if t.expiration_ms + CLOCK_TOLERANCE_MS < now_ms {
        return refuse("the transaction has already expired; build it again on the PC");
    }
    if t.timestamp_ms > now_ms + CLOCK_TOLERANCE_MS {
        return refuse("the transaction is dated in the future by this tablet's clock; check the tablet's date and time");
    }
    Ok(TronReview {
        network: "TRON Nile (test network, coins have no value)".into(),
        from: me.to_base58(),
        recipient: t.recipient.to_base58(),
        amount_usdt: usdt_text(t.amount),
        fee_limit_trx: usdt_text(u128::from(t.fee_limit_sun)),
        txid: hex_lower(&tron_tx::txid(raw)),
    })
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Sign the reviewed transaction (checks run again). Returns the 65-byte
/// signature.
pub fn sign(
    raw: &[u8],
    master: &Xpriv,
    now_ms: u64,
) -> Result<([u8; 65], TronReview), TronSignError> {
    let review = review(raw, master, now_ms)?;
    let (sk, me) = key(master)?;
    let sk2 = secp256k1::SecretKey::from_slice(&sk.secret_bytes())
        .map_err(|_| TronSignError::Derivation)?;
    let sig = tron_tx::sign(raw, &sk2);
    if tron_tx::recover_signer(raw, &sig)? != me {
        return Err(TronSignError::Derivation);
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

    const NOW: u64 = 1_800_000_000_000;

    fn tx(me: TronAddress) -> Trc20Transfer {
        Trc20Transfer {
            ref_block_bytes: [1, 2],
            ref_block_hash: [3; 8],
            expiration_ms: NOW + 120_000,
            timestamp_ms: NOW,
            fee_limit_sun: 30_000_000,
            owner: me,
            token: NILE_USDT.parse().expect("usdt"),
            recipient: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".parse().expect("to"),
            amount: 12_500_000,
        }
    }

    fn refused(r: Result<TronReview, TronSignError>, needle: &str) {
        match r {
            Err(TronSignError::Refused(m)) => assert!(m.contains(needle), "{m}"),
            other => panic!("expected refusal '{needle}', got {other:?}"),
        }
    }

    #[test]
    fn honest_transfer_reviews_and_signs() {
        let m = master();
        let me = wallet_address(&m).expect("me");
        let raw = tx(me).encode_raw();
        let r = review(&raw, &m, NOW).expect("review");
        assert_eq!(r.amount_usdt, "12.5");
        assert_eq!(r.fee_limit_trx, "30");
        assert_eq!(r.recipient, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
        let (sig, _) = sign(&raw, &m, NOW).expect("sign");
        assert_eq!(tron_tx::recover_signer(&raw, &sig), Ok(me));
    }

    #[test]
    fn same_address_as_the_watch_only_export() {
        let m = master();
        let secp = Secp256k1::new();
        let acct = m
            .derive_priv(
                &secp,
                &"m/44'/195'/0'".parse::<DerivationPath>().expect("p"),
            )
            .expect("acct");
        let xpub = bitcoin::bip32::Xpub::from_priv(&secp, &acct);
        let exported = chain_tron::derive_address(&xpub, 0).expect("exported");
        assert_eq!(wallet_address(&m).expect("me"), exported);
    }

    #[test]
    fn refuses_mainnet_usdt_wrong_owner_and_odd_values() {
        let m = master();
        let me = wallet_address(&m).expect("me");
        let mut t = tx(me);
        t.token = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
            .parse()
            .expect("mainnet usdt");
        refused(review(&t.encode_raw(), &m, NOW), "test USDT");

        let mut t = tx(me);
        t.owner = "TUUSMd58eC3fKx3fn7whxJyr1FR56tgaP8".parse().expect("other");
        refused(review(&t.encode_raw(), &m, NOW), "isn't from this wallet");

        let mut t = tx(me);
        t.fee_limit_sun = 31_000_000;
        refused(review(&t.encode_raw(), &m, NOW), "fee limit");

        let mut t = tx(me);
        t.expiration_ms = t.timestamp_ms + 24 * 3600 * 1000;
        refused(review(&t.encode_raw(), &m, NOW), "validity");

        let t = tx(me);
        refused(review(&t.encode_raw(), &m, NOW + 3600 * 1000), "expired");

        let mut t = tx(me);
        t.amount = 0;
        refused(review(&t.encode_raw(), &m, NOW), "zero");

        let mut t = tx(me);
        t.recipient = me;
        refused(review(&t.encode_raw(), &m, NOW), "itself");
    }
}
