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
//!
//! Plain TRX transfers (`TransferContract`) are signed only as **top-ups
//! between your own wallets** (§8.3b): the recipient must be another wallet
//! on this tablet, at most 200 TRX each.

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use chain_tron::TronAddress;
use serde::Serialize;
use thiserror::Error;
use tron_tx::{TronTx, TxError};

/// The only TRC-20 contract this build signs for: Nile test USDT.
pub use tron_tx::NILE_USDT;
/// Real (mainnet) USDT on TRON, signed only by real wallets in a
/// real-networks build (the PC config pins the same value).
pub const MAINNET_USDT: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
use crate::mode::Mode;
/// Highest fee limit accepted (30 TRX, in sun).
pub const MAX_FEE_LIMIT_SUN: u64 = 30_000_000;
/// Longest validity accepted (expiration minus timestamp).
pub const MAX_VALIDITY_MS: u64 = 10 * 60 * 1000;
/// Tolerance for this tablet's clock when checking expiration.
pub const CLOCK_TOLERANCE_MS: u64 = 10 * 60 * 1000;
/// Largest TRX top-up between own wallets (200 TRX, in sun).
pub const MAX_TRX_TOPUP_SUN: u64 = 200_000_000;
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
    /// "usdt" or "trx".
    pub kind: String,
    pub from: String,
    pub recipient: String,
    /// Exact decimal amount, e.g. "12.5".
    pub amount: String,
    /// "USDT" or "TRX".
    pub unit: String,
    /// Fee limit in TRX ("0" for plain TRX transfers, which use bandwidth).
    pub fee_limit_trx: String,
    pub txid: String,
    /// Base units (for the tablet's limits).
    pub amount_base: u128,
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

/// Check a raw transaction for signing. `now_ms` is the tablet's clock;
/// `own` are this tablet's other wallets (the only TRX top-up recipients).
pub fn review(
    raw: &[u8],
    master: &Xpriv,
    now_ms: u64,
    own: &[TronAddress],
    mode: Mode,
) -> Result<TronReview, TronSignError> {
    if !mode.allowed() {
        return refuse("this is a real-money wallet, and this build signs only on test networks");
    }
    let tx = TronTx::decode_raw(raw)?;
    let (_, me) = key(master)?;
    if tx.owner() != me {
        return refuse("the transaction isn't from this wallet's TRON address");
    }
    if tx.recipient() == me {
        return refuse("the recipient is this wallet itself");
    }
    let (timestamp_ms, expiration_ms) = tx.times();
    let validity = expiration_ms.checked_sub(timestamp_ms);
    if !validity.is_some_and(|v| (1..=MAX_VALIDITY_MS).contains(&v)) {
        return refuse("the transaction's validity period is unusual (more than 10 minutes)");
    }
    if expiration_ms + CLOCK_TOLERANCE_MS < now_ms {
        return refuse("the transaction has already expired; build it again on the PC");
    }
    if timestamp_ms > now_ms + CLOCK_TOLERANCE_MS {
        return refuse("the transaction is dated in the future by this tablet's clock; check the tablet's date and time");
    }
    let (kind, unit, amount, fee) = match &tx {
        TronTx::Usdt(t) => {
            let pinned = match mode {
                Mode::Test => NILE_USDT,
                Mode::Real => MAINNET_USDT,
            };
            let usdt: TronAddress = pinned.parse().map_err(|_| TronSignError::Derivation)?;
            if t.token != usdt {
                return refuse(match mode {
                    Mode::Test => "this isn't the TRON Nile test USDT contract (this wallet only signs test-network USDT)",
                    Mode::Real => "this isn't the real USDT contract on TRON",
                });
            }
            if t.amount == 0 {
                return refuse("the amount is zero");
            }
            if t.fee_limit_sun == 0 || t.fee_limit_sun > MAX_FEE_LIMIT_SUN {
                return refuse(format!(
                    "the fee limit must be between 0 and {} TRX",
                    MAX_FEE_LIMIT_SUN / 1_000_000
                ));
            }
            ("usdt", "USDT", t.amount, t.fee_limit_sun)
        }
        TronTx::Trx(t) => {
            if !own.contains(&t.recipient) {
                return refuse(
                    "TRX can only be sent to your own wallets on this tablet (to top up their network fees)",
                );
            }
            if t.amount_sun > MAX_TRX_TOPUP_SUN {
                return refuse(format!(
                    "a TRX top-up is limited to {} TRX",
                    MAX_TRX_TOPUP_SUN / 1_000_000
                ));
            }
            ("trx", "TRX", u128::from(t.amount_sun), 0)
        }
    };
    Ok(TronReview {
        network: match mode {
            Mode::Test => "TRON Nile (test network, coins have no value)".into(),
            Mode::Real => "TRON mainnet: REAL MONEY".into(),
        },
        kind: kind.into(),
        from: me.to_base58(),
        recipient: tx.recipient().to_base58(),
        amount: usdt_text(amount),
        unit: unit.into(),
        fee_limit_trx: usdt_text(u128::from(fee)),
        txid: hex_lower(&tron_tx::txid(raw)),
        amount_base: amount,
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
    own: &[TronAddress],
    mode: Mode,
) -> Result<([u8; 65], TronReview), TronSignError> {
    let review = review(raw, master, now_ms, own, mode)?;
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

    fn tx(me: TronAddress) -> tron_tx::Trc20Transfer {
        tron_tx::Trc20Transfer {
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
        let r = review(&raw, &m, NOW, &[], Mode::Test).expect("review");
        assert_eq!((r.amount.as_str(), r.unit.as_str()), ("12.5", "USDT"));
        assert_eq!(r.fee_limit_trx, "30");
        assert_eq!(r.recipient, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
        let (sig, _) = sign(&raw, &m, NOW, &[], Mode::Test).expect("sign");
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
        refused(
            review(&t.encode_raw(), &m, NOW, &[], Mode::Test),
            "test USDT",
        );

        let mut t = tx(me);
        t.owner = "TUUSMd58eC3fKx3fn7whxJyr1FR56tgaP8".parse().expect("other");
        refused(
            review(&t.encode_raw(), &m, NOW, &[], Mode::Test),
            "isn't from this wallet",
        );

        let mut t = tx(me);
        t.fee_limit_sun = 31_000_000;
        refused(
            review(&t.encode_raw(), &m, NOW, &[], Mode::Test),
            "fee limit",
        );

        let mut t = tx(me);
        t.expiration_ms = t.timestamp_ms + 24 * 3600 * 1000;
        refused(
            review(&t.encode_raw(), &m, NOW, &[], Mode::Test),
            "validity",
        );

        let t = tx(me);
        refused(
            review(&t.encode_raw(), &m, NOW + 3600 * 1000, &[], Mode::Test),
            "expired",
        );

        let mut t = tx(me);
        t.amount = 0;
        refused(review(&t.encode_raw(), &m, NOW, &[], Mode::Test), "zero");

        let mut t = tx(me);
        t.recipient = me;
        refused(review(&t.encode_raw(), &m, NOW, &[], Mode::Test), "itself");
    }

    #[test]
    fn trx_only_to_own_wallets_and_capped() {
        let m = master();
        let me = wallet_address(&m).expect("me");
        let other_own: TronAddress = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".parse().expect("own");
        let t = tron_tx::TrxTransfer {
            ref_block_bytes: [1, 2],
            ref_block_hash: [3; 8],
            expiration_ms: NOW + 120_000,
            timestamp_ms: NOW,
            owner: me,
            recipient: other_own,
            amount_sun: 25_000_000,
        };
        let raw = t.encode_raw();
        refused(review(&raw, &m, NOW, &[], Mode::Test), "your own wallets");
        let r = review(&raw, &m, NOW, &[other_own], Mode::Test).expect("own");
        assert_eq!(
            (r.kind.as_str(), r.amount.as_str(), r.unit.as_str()),
            ("trx", "25", "TRX")
        );
        assert_eq!(r.fee_limit_trx, "0");
        let (sig, _) = sign(&raw, &m, NOW, &[other_own], Mode::Test).expect("sign");
        assert_eq!(tron_tx::recover_signer(&raw, &sig), Ok(me));
        let mut big = t.clone();
        big.amount_sun = MAX_TRX_TOPUP_SUN + 1;
        refused(
            review(&big.encode_raw(), &m, NOW, &[other_own], Mode::Test),
            "limited to 200",
        );
        let mut stale = t;
        stale.expiration_ms = NOW - 3_600_000;
        stale.timestamp_ms = NOW - 3_660_000;
        refused(
            review(&stale.encode_raw(), &m, NOW, &[other_own], Mode::Test),
            "expired",
        );
    }

    #[test]
    fn real_mode_only_in_a_real_build_and_only_real_usdt() {
        let m = master();
        let me = wallet_address(&m).expect("me");
        let mut t = tx(me);
        if cfg!(feature = "real-networks") {
            refused(
                review(&t.encode_raw(), &m, NOW, &[], Mode::Real),
                "real USDT",
            );
            t.token = MAINNET_USDT.parse().expect("usdt");
            let r = review(&t.encode_raw(), &m, NOW, &[], Mode::Real).expect("real");
            assert!(r.network.contains("REAL"));
            refused(
                review(&t.encode_raw(), &m, NOW, &[], Mode::Test),
                "test USDT",
            );
        } else {
            t.token = MAINNET_USDT.parse().expect("usdt");
            refused(
                review(&t.encode_raw(), &m, NOW, &[], Mode::Real),
                "test networks",
            );
        }
    }
}
