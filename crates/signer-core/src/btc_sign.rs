//! Bitcoin signing on the tablet (ARCHITECTURE.md §7 ⑦b–⑦d, §8.1).
//!
//! **Test network only in this build:** the tablet signs Bitcoin **signet**
//! transactions (coins with no value). Mainnet signing is not compiled in;
//! it comes only after the Phase 2 gates pass.
//!
//! The PC sends a PSBT (BIP-174). The tablet trusts **nothing** the PC says
//! about it and works everything out itself:
//! - every input must be this wallet's own coin: its key is derived here
//!   from the seed at the stated path, and the coin's script and amount are
//!   checked against the full previous transaction (whose id must match);
//! - at most one output may be change, and only if it really is this
//!   wallet's change address (derived here); everything else is a recipient,
//!   and v1 allows exactly one recipient;
//! - the fee is computed from the checked amounts and must be within limits;
//! - anything unusual (extra fields, scripts, other sighash types, a lock
//!   time, unknown data) is refused, not ignored.
//!
//! The result of [`review`] is what the tablet shows; [`sign`] signs only
//! the transaction that was reviewed.

use std::collections::BTreeMap;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{absolute, transaction, Address, CompressedPublicKey, Network, ScriptBuf, Sequence};
use serde::Serialize;
use thiserror::Error;

/// The only network this build signs for.
pub const SIGN_NETWORK: Network = Network::Signet;
/// BIP-84 account on test networks (coin type 1).
pub const TEST_ACCOUNT_PATH: &str = "m/84'/1'/0'";
/// Largest fee accepted, in satoshis.
pub const MAX_FEE_SATS: u64 = 100_000;
/// Highest fee rate accepted, in sat/vB.
pub const MAX_FEE_RATE: u64 = 500;
/// Highest address index accepted in a derivation path.
pub const MAX_INDEX: u32 = 100_000;
/// Inputs accepted in one transaction (keeps the QR code small).
pub const MAX_INPUTS: usize = 20;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignError {
    #[error("this isn't a valid transaction request (PSBT): {0}")]
    Malformed(String),
    #[error("refused: {0}")]
    Refused(String),
    #[error("key derivation failed")]
    Derivation,
}

fn refuse<T>(why: impl Into<String>) -> Result<T, SignError> {
    Err(SignError::Refused(why.into()))
}

/// What the tablet shows before you approve. Every number here was worked
/// out on the tablet from the checked transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Review {
    pub network: String,
    pub recipient: String,
    pub amount_sats: u64,
    /// Change back to this wallet (0 if none).
    pub change_sats: u64,
    /// Change address index, if any (shown so it can be checked).
    pub change_index: Option<u32>,
    pub fee_sats: u64,
    /// Fee rate in sat/vB, rounded up.
    pub fee_rate: u64,
    pub inputs: usize,
    /// Transaction id (doesn't change when signed, for SegWit). Its first
    /// 8 characters are shown on both the PC and the tablet.
    pub txid: String,
}

/// The account key for test networks, from the master key.
pub fn test_account(master: &Xpriv) -> Result<Xpriv, SignError> {
    let secp = Secp256k1::new();
    let path: DerivationPath = TEST_ACCOUNT_PATH
        .parse()
        .map_err(|_| SignError::Derivation)?;
    master
        .derive_priv(&secp, &path)
        .map_err(|_| SignError::Derivation)
}

/// Public account key for test networks (exported to the PC as a tpub).
pub fn test_account_xpub(master: &Xpriv) -> Result<Xpub, SignError> {
    let secp = Secp256k1::new();
    Ok(Xpub::from_priv(&secp, &test_account(master)?))
}

/// `m/84'/1'/0'/chain/index` → (chain, index), or `None` if the path is
/// anything else.
fn parse_path(path: &DerivationPath) -> Option<(u32, u32)> {
    let p: Vec<ChildNumber> = path.into_iter().copied().collect();
    let expect = [
        ChildNumber::from_hardened_idx(84).ok()?,
        ChildNumber::from_hardened_idx(1).ok()?,
        ChildNumber::from_hardened_idx(0).ok()?,
    ];
    if p.len() != 5 || p[..3] != expect {
        return None;
    }
    match (p[3], p[4]) {
        (ChildNumber::Normal { index: c }, ChildNumber::Normal { index: i })
            if c <= 1 && i <= MAX_INDEX =>
        {
            Some((c, i))
        }
        _ => None,
    }
}

fn derive_pubkey(account: &Xpub, chain: u32, index: u32) -> Result<CompressedPublicKey, SignError> {
    let secp = Secp256k1::verification_only();
    let path = [
        ChildNumber::from_normal_idx(chain).map_err(|_| SignError::Derivation)?,
        ChildNumber::from_normal_idx(index).map_err(|_| SignError::Derivation)?,
    ];
    Ok(account
        .derive_pub(&secp, &path)
        .map_err(|_| SignError::Derivation)?
        .to_pub())
}

/// Checked facts about one input.
struct CheckedInput {
    chain: u32,
    index: u32,
    pubkey: CompressedPublicKey,
    value: u64,
    script: ScriptBuf,
}

/// Check one input and return what was verified.
fn check_input(
    psbt: &Psbt,
    i: usize,
    fingerprint: Fingerprint,
    account: &Xpub,
) -> Result<CheckedInput, SignError> {
    let inp = &psbt.inputs[i];
    let txin = &psbt.unsigned_tx.input[i];
    let n = i + 1;
    if !txin.script_sig.is_empty() || !txin.witness.is_empty() {
        return refuse(format!("input {n} already has signature data"));
    }
    if ![
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        Sequence::ENABLE_LOCKTIME_NO_RBF,
        Sequence::MAX,
    ]
    .contains(&txin.sequence)
    {
        return refuse(format!("input {n} has an unusual sequence number"));
    }
    let extra = inp.final_script_sig.is_some()
        || inp.final_script_witness.is_some()
        || !inp.partial_sigs.is_empty()
        || inp.redeem_script.is_some()
        || inp.witness_script.is_some()
        || !inp.ripemd160_preimages.is_empty()
        || !inp.sha256_preimages.is_empty()
        || !inp.hash160_preimages.is_empty()
        || !inp.hash256_preimages.is_empty()
        || inp.tap_key_sig.is_some()
        || !inp.tap_script_sigs.is_empty()
        || !inp.tap_scripts.is_empty()
        || !inp.tap_key_origins.is_empty()
        || inp.tap_internal_key.is_some()
        || inp.tap_merkle_root.is_some()
        || !inp.proprietary.is_empty()
        || !inp.unknown.is_empty();
    if extra {
        return refuse(format!(
            "input {n} contains data this signer doesn't accept"
        ));
    }
    if let Some(t) = inp.sighash_type {
        if t.ecdsa_hash_ty() != Ok(EcdsaSighashType::All) {
            return refuse(format!("input {n} asks for an unusual signature type"));
        }
    }
    // The full previous transaction proves the coin's amount and script.
    let Some(prev) = &inp.non_witness_utxo else {
        return refuse(format!("input {n} is missing its previous transaction"));
    };
    if prev.compute_txid() != txin.previous_output.txid {
        return refuse(format!("input {n}: previous transaction doesn't match"));
    }
    let Some(prev_out) = prev.output.get(txin.previous_output.vout as usize) else {
        return refuse(format!("input {n}: previous output doesn't exist"));
    };
    if inp.witness_utxo.as_ref() != Some(prev_out) {
        return refuse(format!("input {n}: coin data is inconsistent"));
    }
    // Exactly one key, ours, at a normal BIP-84 test path.
    if inp.bip32_derivation.len() != 1 {
        return refuse(format!("input {n} must name exactly one key"));
    }
    let Some((pk, (fp, path))) = inp.bip32_derivation.iter().next() else {
        return refuse(format!("input {n} must name exactly one key"));
    };
    if *fp != fingerprint {
        return refuse(format!(
            "input {n} belongs to another wallet (fingerprint {fp})"
        ));
    }
    let Some((chain, index)) = parse_path(path) else {
        return refuse(format!("input {n} uses an unexpected key path"));
    };
    let derived = derive_pubkey(account, chain, index)?;
    if derived.0 != *pk {
        return refuse(format!("input {n}: key doesn't match this wallet"));
    }
    let script = ScriptBuf::new_p2wpkh(&derived.wpubkey_hash());
    if prev_out.script_pubkey != script {
        return refuse(format!("input {n} isn't one of this wallet's coins"));
    }
    Ok(CheckedInput {
        chain,
        index,
        pubkey: derived,
        value: prev_out.value.to_sat(),
        script,
    })
}

/// Check the whole request and work out what it does.
pub fn review(psbt: &Psbt, master: &Xpriv) -> Result<Review, SignError> {
    review_inner(psbt, master).map(|(r, _)| r)
}

fn review_inner(psbt: &Psbt, master: &Xpriv) -> Result<(Review, Vec<CheckedInput>), SignError> {
    let secp = Secp256k1::new();
    let fingerprint = master.fingerprint(&secp);
    let account = test_account_xpub(master)?;
    let tx = &psbt.unsigned_tx;

    if psbt.version != 0
        || !psbt.xpub.is_empty()
        || !psbt.proprietary.is_empty()
        || !psbt.unknown.is_empty()
    {
        return refuse("the request contains data this signer doesn't accept");
    }
    if tx.version != transaction::Version::TWO && tx.version != transaction::Version::ONE {
        return refuse("unusual transaction version");
    }
    if tx.lock_time != absolute::LockTime::ZERO {
        return refuse("the transaction has a lock time");
    }
    if tx.input.is_empty() || tx.input.len() > MAX_INPUTS {
        return refuse(format!("between 1 and {MAX_INPUTS} inputs are accepted"));
    }
    if tx.output.is_empty() || tx.output.len() > 2 {
        return refuse("only one recipient (plus change) is accepted");
    }
    let mut seen = std::collections::BTreeSet::new();
    for txin in &tx.input {
        if !seen.insert(txin.previous_output) {
            return refuse("the same coin is spent twice");
        }
    }

    let inputs: Vec<CheckedInput> = (0..tx.input.len())
        .map(|i| check_input(psbt, i, fingerprint, &account))
        .collect::<Result<_, _>>()?;
    let total_in: u64 = inputs
        .iter()
        .map(|c| c.value)
        .try_fold(0u64, u64::checked_add)
        .ok_or_else(|| SignError::Refused("input amounts overflow".into()))?;

    let mut recipient: Option<(String, u64)> = None;
    let mut change: Option<(u32, u64)> = None;
    let mut total_out: u64 = 0;
    for (i, (txout, out)) in tx.output.iter().zip(&psbt.outputs).enumerate() {
        let n = i + 1;
        let value = txout.value.to_sat();
        total_out = total_out
            .checked_add(value)
            .ok_or_else(|| SignError::Refused("output amounts overflow".into()))?;
        if out.redeem_script.is_some()
            || out.witness_script.is_some()
            || out.tap_internal_key.is_some()
            || out.tap_tree.is_some()
            || !out.tap_key_origins.is_empty()
            || !out.proprietary.is_empty()
            || !out.unknown.is_empty()
        {
            return refuse(format!(
                "output {n} contains data this signer doesn't accept"
            ));
        }
        if txout.value < txout.script_pubkey.minimal_non_dust() {
            return refuse(format!("output {n} is below the dust limit"));
        }
        if out.bip32_derivation.is_empty() {
            let Ok(addr) = Address::from_script(&txout.script_pubkey, SIGN_NETWORK) else {
                return refuse(format!("output {n} isn't a standard address"));
            };
            if recipient.is_some() {
                return refuse("only one recipient is accepted");
            }
            recipient = Some((addr.to_string(), value));
            continue;
        }
        // Claimed change: must really be this wallet's change address.
        let mut entries = out.bip32_derivation.iter();
        let (Some((pk, (fp, path))), None) = (entries.next(), entries.next()) else {
            return refuse(format!("output {n} names more than one key"));
        };
        if *fp != fingerprint {
            return refuse(format!(
                "output {n} claims to be change but belongs to another wallet"
            ));
        }
        let Some((1, index)) = parse_path(path) else {
            return refuse(format!(
                "output {n} claims to be change at an unexpected path"
            ));
        };
        let derived = derive_pubkey(&account, 1, index)?;
        if derived.0 != *pk || txout.script_pubkey != ScriptBuf::new_p2wpkh(&derived.wpubkey_hash())
        {
            return refuse(format!(
                "output {n} claims to be change but isn't this wallet's address"
            ));
        }
        if change.is_some() {
            return refuse("only one change output is accepted");
        }
        change = Some((index, value));
    }
    let Some((recipient, amount)) = recipient else {
        return refuse("there is no recipient (sending only to your own change isn't accepted)");
    };
    let fee = total_in
        .checked_sub(total_out)
        .ok_or_else(|| SignError::Refused("outputs are larger than inputs".into()))?;
    // Size once signed: each P2WPKH input adds about 108 weight units of witness.
    let weight = tx.weight().to_wu() + 2 + 108 * inputs.len() as u64;
    let vsize = weight.div_ceil(4);
    let fee_rate = fee.div_ceil(vsize.max(1));
    if fee > MAX_FEE_SATS || fee_rate > MAX_FEE_RATE {
        return refuse(format!(
            "the fee ({fee} sats, about {fee_rate} sat/vB) is above the limit ({MAX_FEE_SATS} sats or {MAX_FEE_RATE} sat/vB)"
        ));
    }
    if fee == 0 {
        return refuse("the fee is zero, so the transaction would never confirm");
    }
    Ok((
        Review {
            network: "Bitcoin signet (test network, coins have no value)".into(),
            recipient,
            amount_sats: amount,
            change_sats: change.map_or(0, |c| c.1),
            change_index: change.map(|c| c.0),
            fee_sats: fee,
            fee_rate,
            inputs: inputs.len(),
            txid: tx.compute_txid().to_string(),
        },
        inputs,
    ))
}

/// Sign the reviewed request. The checks are run again here, so nothing
/// else can be signed. Returns the PSBT with a signature on every input.
pub fn sign(mut psbt: Psbt, master: &Xpriv) -> Result<(Psbt, Review), SignError> {
    let (rev, inputs) = review_inner(&psbt, master)?;
    let secp = Secp256k1::new();
    let account = test_account(master)?;
    let tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&tx);
    for (i, c) in inputs.iter().enumerate() {
        let path = [
            ChildNumber::from_normal_idx(c.chain).map_err(|_| SignError::Derivation)?,
            ChildNumber::from_normal_idx(c.index).map_err(|_| SignError::Derivation)?,
        ];
        let key = account
            .derive_priv(&secp, &path)
            .map_err(|_| SignError::Derivation)?;
        let sk = key.private_key;
        if sk.public_key(&secp) != c.pubkey.0 {
            return Err(SignError::Derivation);
        }
        let sighash = cache
            .p2wpkh_signature_hash(
                i,
                &c.script,
                bitcoin::Amount::from_sat(c.value),
                EcdsaSighashType::All,
            )
            .map_err(|e| SignError::Malformed(e.to_string()))?;
        let msg = Message::from(sighash);
        let sig = secp.sign_ecdsa_low_r(&msg, &sk);
        let mut sigs = BTreeMap::new();
        sigs.insert(
            bitcoin::PublicKey::new(c.pubkey.0),
            bitcoin::ecdsa::Signature {
                signature: sig,
                sighash_type: EcdsaSighashType::All,
            },
        );
        psbt.inputs[i].partial_sigs = sigs;
    }
    Ok((psbt, rev))
}

/// Read a PSBT from bytes.
pub fn parse(bytes: &[u8]) -> Result<Psbt, SignError> {
    Psbt::deserialize(bytes).map_err(|e| SignError::Malformed(e.to_string()))
}
