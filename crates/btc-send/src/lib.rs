//! PC side of a Bitcoin payment (ARCHITECTURE.md §7 ①–⑧, §8.1).
//!
//! 1. [`build`]: pick coins, add change, and produce an **unsigned PSBT**
//!    carrying everything the tablet needs to check it independently (the
//!    full previous transaction of every coin, key paths, the master
//!    fingerprint). No keys are involved.
//! 2. The tablet reviews, you approve there, and it returns the PSBT with
//!    signatures.
//! 3. [`finalize`]: take **only the signatures** from what came back, put
//!    them on the PSBT built in step 1, verify every signature, and produce
//!    the final transaction. If the tablet (or the QR channel) changed
//!    anything else, it is simply not used; a signature for a different
//!    transaction fails verification.
//!
//! **Test network only in this build:** signet. Mainnet sending comes after
//! the Phase 2 gates.

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    absolute, transaction, Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Witness,
};
use serde::Serialize;
use thiserror::Error;

/// The only network this build sends on.
pub const SEND_NETWORK: Network = Network::Signet;
/// Fee rate limits accepted when building (the tablet has its own limits).
pub const MIN_FEE_RATE: u64 = 1;
pub const MAX_FEE_RATE: u64 = 200;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SendError {
    #[error("{0}")]
    Invalid(String),
    #[error("not enough funds: {available} sats available, {needed} needed (amount + fee)")]
    Insufficient { available: u64, needed: u64 },
    #[error("the signed transaction from the tablet doesn't match: {0}")]
    BadSignature(String),
}

fn invalid<T>(why: impl Into<String>) -> Result<T, SendError> {
    Err(SendError::Invalid(why.into()))
}

/// The wallet's test-network account: `m/84'/1'/0'` public key and the
/// master fingerprint (both from the tablet's export).
#[derive(Debug, Clone)]
pub struct Account {
    pub xpub: Xpub,
    pub fingerprint: Fingerprint,
}

/// A coin (unspent output) of this wallet, with its full previous
/// transaction and where its key is.
#[derive(Debug, Clone)]
pub struct Coin {
    pub prev_tx: Transaction,
    pub vout: u32,
    /// 0 = receive, 1 = change.
    pub chain: u32,
    pub index: u32,
}

/// What [`build`] decided, shown on the PC before the QR code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub recipient: String,
    pub amount_sats: u64,
    pub change_sats: u64,
    pub change_index: Option<u32>,
    pub fee_sats: u64,
    pub fee_rate: u64,
    pub inputs: usize,
    pub txid: String,
}

fn account_path(chain: u32, index: u32) -> Result<DerivationPath, SendError> {
    let n = |i| ChildNumber::from_normal_idx(i).map_err(|_| SendError::Invalid("bad index".into()));
    let h =
        |i| ChildNumber::from_hardened_idx(i).map_err(|_| SendError::Invalid("bad index".into()));
    Ok(DerivationPath::from(vec![
        h(84)?,
        h(1)?,
        h(0)?,
        n(chain)?,
        n(index)?,
    ]))
}

fn derive(account: &Account, chain: u32, index: u32) -> Result<CompressedPublicKey, SendError> {
    let secp = Secp256k1::verification_only();
    let path = [
        ChildNumber::from_normal_idx(chain).map_err(|_| SendError::Invalid("bad chain".into()))?,
        ChildNumber::from_normal_idx(index).map_err(|_| SendError::Invalid("bad index".into()))?,
    ];
    Ok(account
        .xpub
        .derive_pub(&secp, &path)
        .map_err(|e| SendError::Invalid(e.to_string()))?
        .to_pub())
}

/// Address `chain/index` of the account on the send network.
pub fn address(account: &Account, chain: u32, index: u32) -> Result<Address, SendError> {
    Ok(Address::p2wpkh(
        &derive(account, chain, index)?,
        SEND_NETWORK,
    ))
}

/// Parse a recipient address for the send network.
pub fn parse_recipient(s: &str) -> Result<Address, SendError> {
    s.trim()
        .parse::<Address<bitcoin::address::NetworkUnchecked>>()
        .map_err(|e| SendError::Invalid(format!("not a Bitcoin address: {e}")))?
        .require_network(SEND_NETWORK)
        .map_err(|_| {
            SendError::Invalid("this address isn't for the Bitcoin test network (signet)".into())
        })
}

/// Estimated virtual size once signed (P2WPKH inputs).
fn vsize(tx: &Transaction) -> u64 {
    (tx.weight().to_wu() + 2 + 108 * tx.input.len() as u64).div_ceil(4)
}

/// Build the unsigned PSBT: largest coins first, change to `change_index`
/// on the change chain if it's above the dust limit (otherwise it goes to
/// the fee).
pub fn build(
    account: &Account,
    coins: &[Coin],
    recipient: &Address,
    amount_sats: u64,
    fee_rate: u64,
    change_index: u32,
) -> Result<(Psbt, Plan), SendError> {
    if !(MIN_FEE_RATE..=MAX_FEE_RATE).contains(&fee_rate) {
        return invalid(format!(
            "fee rate must be {MIN_FEE_RATE}-{MAX_FEE_RATE} sat/vB"
        ));
    }
    let to_script = recipient.script_pubkey();
    if Amount::from_sat(amount_sats) < to_script.minimal_non_dust() {
        return invalid("the amount is below the dust limit");
    }
    // Check every coin really is ours before using it.
    let mut usable = Vec::new();
    for c in coins {
        let Some(out) = c.prev_tx.output.get(c.vout as usize) else {
            return invalid("a coin points to a missing output");
        };
        let pk = derive(account, c.chain, c.index)?;
        if out.script_pubkey != ScriptBuf::new_p2wpkh(&pk.wpubkey_hash()) {
            return invalid("a coin doesn't belong to this wallet");
        }
        usable.push((c, out.clone(), pk));
    }
    usable.sort_by_key(|(_, out, _)| std::cmp::Reverse(out.value));

    let change_pk = derive(account, 1, change_index)?;
    let change_script = ScriptBuf::new_p2wpkh(&change_pk.wpubkey_hash());
    let make_tx = |n: usize, change: Option<u64>| {
        let mut output = vec![TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: to_script.clone(),
        }];
        if let Some(v) = change {
            output.push(TxOut {
                value: Amount::from_sat(v),
                script_pubkey: change_script.clone(),
            });
        }
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: usable[..n]
                .iter()
                .map(|(c, _, _)| TxIn {
                    previous_output: OutPoint {
                        txid: c.prev_tx.compute_txid(),
                        vout: c.vout,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output,
        }
    };
    let available: u64 = usable.iter().map(|(_, o, _)| o.value.to_sat()).sum();
    let mut chosen = None;
    for n in 1..=usable.len() {
        let total: u64 = usable[..n].iter().map(|(_, o, _)| o.value.to_sat()).sum();
        // Try with change first.
        let fee_with = vsize(&make_tx(n, Some(0))) * fee_rate;
        if let Some(change) = total.checked_sub(amount_sats + fee_with) {
            if Amount::from_sat(change) >= change_script.minimal_non_dust() {
                chosen = Some((n, Some(change), fee_with));
                break;
            }
        }
        let fee_without = vsize(&make_tx(n, None)) * fee_rate;
        if let Some(rest) = total.checked_sub(amount_sats + fee_without) {
            // Leftover below dust goes to the fee.
            chosen = Some((n, None, fee_without + rest));
            break;
        }
    }
    let Some((n, change, fee)) = chosen else {
        let needed = amount_sats + vsize(&make_tx(usable.len().max(1), None)) * fee_rate;
        return Err(SendError::Insufficient { available, needed });
    };
    let tx = make_tx(n, change);
    let txid = tx.compute_txid().to_string();
    let mut psbt =
        Psbt::from_unsigned_tx(tx.clone()).map_err(|e| SendError::Invalid(e.to_string()))?;
    for (i, (c, out, pk)) in usable[..n].iter().enumerate() {
        let inp = &mut psbt.inputs[i];
        inp.non_witness_utxo = Some(c.prev_tx.clone());
        inp.witness_utxo = Some(out.clone());
        inp.bip32_derivation
            .insert(pk.0, (account.fingerprint, account_path(c.chain, c.index)?));
    }
    if change.is_some() {
        psbt.outputs[1].bip32_derivation.insert(
            change_pk.0,
            (account.fingerprint, account_path(1, change_index)?),
        );
    }
    let plan = Plan {
        recipient: recipient.to_string(),
        amount_sats,
        change_sats: change.unwrap_or(0),
        change_index: change.map(|_| change_index),
        fee_sats: fee,
        fee_rate: fee.div_ceil(vsize(&tx)),
        inputs: n,
        txid,
    };
    Ok((psbt, plan))
}

/// Combine the tablet's signatures with the PSBT built on this PC, verify
/// each one, and produce the final transaction. Only signatures are taken
/// from `signed`; everything else comes from `built`.
pub fn finalize(built: &Psbt, signed: &Psbt) -> Result<Transaction, SendError> {
    let bad = |m: &str| SendError::BadSignature(m.to_owned());
    if signed.unsigned_tx != built.unsigned_tx {
        return Err(bad("it is for a different transaction"));
    }
    let secp = Secp256k1::verification_only();
    let tx = &built.unsigned_tx;
    let mut cache = SighashCache::new(tx);
    let mut out = built.clone();
    for (i, inp) in built.inputs.iter().enumerate() {
        let n = i + 1;
        let (pk, _) = inp
            .bip32_derivation
            .iter()
            .next()
            .ok_or_else(|| bad("an input has no key"))?;
        let prev = inp
            .witness_utxo
            .as_ref()
            .ok_or_else(|| bad("an input has no coin data"))?;
        let sigs = &signed.inputs[i].partial_sigs;
        let key = bitcoin::PublicKey::new(*pk);
        let (Some(sig), 1) = (sigs.get(&key), sigs.len()) else {
            return Err(SendError::BadSignature(format!(
                "input {n} doesn't have exactly one signature from the expected key"
            )));
        };
        if sig.sighash_type != EcdsaSighashType::All {
            return Err(SendError::BadSignature(format!(
                "input {n}: unexpected signature type"
            )));
        }
        let sighash = cache
            .p2wpkh_signature_hash(i, &prev.script_pubkey, prev.value, EcdsaSighashType::All)
            .map_err(|e| SendError::BadSignature(e.to_string()))?;
        secp.verify_ecdsa(&Message::from(sighash), &sig.signature, pk)
            .map_err(|_| SendError::BadSignature(format!("input {n}: signature is invalid")))?;
        let o = &mut out.inputs[i];
        o.final_script_witness = Some(Witness::p2wpkh(sig, pk));
        o.partial_sigs.clear();
        o.bip32_derivation.clear();
        o.non_witness_utxo = None;
    }
    out.extract_tx()
        .map_err(|e| SendError::BadSignature(e.to_string()))
}

/// Serialise / read a PSBT for the QR channel.
pub fn to_bytes(psbt: &Psbt) -> Vec<u8> {
    psbt.serialize()
}

pub fn from_bytes(b: &[u8]) -> Result<Psbt, SendError> {
    Psbt::deserialize(b).map_err(|e| SendError::Invalid(format!("not a valid PSBT: {e}")))
}
