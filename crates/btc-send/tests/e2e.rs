//! End to end: PC builds → tablet reviews and signs → PC finalises.
//! Plus the recipient/amount/fee substitution tests (ARCHITECTURE.md §7.3).

use bitcoin::bip32::Xpriv;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{
    absolute, transaction, Amount, NetworkKind, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Witness,
};
use btc_send::{address, build, finalize, parse_recipient, Account, Coin, SendError};
use signer_core::btc_sign::{self, SignError};

fn master(seed_byte: u8) -> Xpriv {
    Xpriv::new_master(NetworkKind::Test, &[seed_byte; 64]).expect("master")
}

fn account(m: &Xpriv) -> Account {
    let secp = Secp256k1::new();
    Account {
        xpub: btc_sign::test_account_xpub(m).expect("xpub"),
        fingerprint: m.fingerprint(&secp),
    }
}

/// A previous transaction paying `sats` to this account's address chain/index.
fn funding(acct: &Account, chain: u32, index: u32, sats: u64, salt: u8) -> Coin {
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(
                    [salt; 32],
                )),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_op_return([salt]),
            },
            TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: address(acct, chain, index).expect("addr").script_pubkey(),
            },
        ],
    };
    Coin {
        prev_tx: tx,
        vout: 1,
        chain,
        index,
    }
}

struct Setup {
    m: Xpriv,
    acct: Account,
    coins: Vec<Coin>,
    recipient: bitcoin::Address,
}

fn setup() -> Setup {
    let m = master(1);
    let acct = account(&m);
    let coins = vec![
        funding(&acct, 0, 0, 30_000, 1),
        funding(&acct, 0, 3, 80_000, 2),
        funding(&acct, 1, 0, 5_000, 3),
    ];
    let other = account(&master(2));
    let recipient = address(&other, 0, 0).expect("recipient");
    Setup {
        m,
        acct,
        coins,
        recipient,
    }
}

fn refused(r: Result<btc_sign::Review, SignError>, needle: &str) {
    match r {
        Err(SignError::Refused(m)) => {
            assert!(m.contains(needle), "'{m}' should mention '{needle}'")
        }
        other => panic!("expected refusal mentioning '{needle}', got {other:?}"),
    }
}

#[test]
fn honest_payment_round_trip() {
    let s = setup();
    let (psbt, plan) = build(&s.acct, &s.coins, &s.recipient, 50_000, 2, 1).expect("build");
    assert_eq!(plan.inputs, 1, "largest coin (80,000) is enough");
    assert_eq!(plan.change_index, Some(1));
    assert_eq!(plan.amount_sats + plan.change_sats + plan.fee_sats, 80_000);

    // The QR channel carries bytes.
    let bytes = btc_send::to_bytes(&psbt);
    let on_tablet = btc_sign::parse(&bytes).expect("parse");
    let review = btc_sign::review(&on_tablet, &s.m).expect("review");
    // The tablet works out the same facts independently.
    assert_eq!(review.recipient, plan.recipient);
    assert_eq!(review.amount_sats, plan.amount_sats);
    assert_eq!(review.change_sats, plan.change_sats);
    assert_eq!(review.fee_sats, plan.fee_sats);
    assert_eq!(review.txid, plan.txid);
    assert!(review.recipient.starts_with("tb1q"));

    let (signed, _) = btc_sign::sign(on_tablet, &s.m).expect("sign");
    let back = btc_send::from_bytes(&btc_send::to_bytes(&signed)).expect("back");
    let tx = finalize(&psbt, &back).expect("finalize");
    assert_eq!(
        tx.compute_txid().to_string(),
        plan.txid,
        "SegWit txid unchanged by signing"
    );
    assert!(tx.input.iter().all(|i| i.witness.len() == 2));
    assert_eq!(tx.output[0].value.to_sat(), 50_000);
    assert_eq!(tx.output[0].script_pubkey, s.recipient.script_pubkey());
}

#[test]
fn several_coins_and_no_change_when_leftover_is_dust() {
    let s = setup();
    let (psbt, plan) = build(&s.acct, &s.coins, &s.recipient, 109_500, 2, 4).expect("build");
    assert_eq!(plan.inputs, 2);
    assert_eq!(plan.change_sats, 0, "leftover below dust goes to the fee");
    assert_eq!(plan.amount_sats + plan.fee_sats, 110_000);
    let (signed, rev) = btc_sign::sign(psbt.clone(), &s.m).expect("sign");
    assert_eq!(rev.change_index, None);
    finalize(&psbt, &signed).expect("finalize");

    assert!(matches!(
        build(&s.acct, &s.coins, &s.recipient, 500_000, 2, 1),
        Err(SendError::Insufficient {
            available: 115_000,
            ..
        })
    ));
}

#[test]
fn recipient_swapped_in_the_qr_channel_is_visible_and_not_broadcastable() {
    let s = setup();
    let (psbt, plan) = build(&s.acct, &s.coins, &s.recipient, 50_000, 2, 1).expect("build");
    let mut evil = psbt.clone();
    let attacker = address(&account(&master(9)), 0, 0).expect("attacker");
    evil.unsigned_tx.output[0].script_pubkey = attacker.script_pubkey();
    // The tablet shows the attacker's address: you'd see it differs from paper.
    let review = btc_sign::review(&evil, &s.m).expect("review");
    assert_ne!(review.recipient, plan.recipient);
    assert_eq!(review.recipient, attacker.to_string());
    assert_ne!(review.txid, plan.txid, "the transaction id differs too");
    // Even if approved, the PC refuses to use signatures for another transaction.
    let (signed, _) = btc_sign::sign(evil, &s.m).expect("sign");
    assert!(matches!(
        finalize(&psbt, &signed),
        Err(SendError::BadSignature(_))
    ));
}

#[test]
fn amount_or_fee_changed_on_the_return_path_is_refused() {
    let s = setup();
    let (psbt, _) = build(&s.acct, &s.coins, &s.recipient, 50_000, 2, 1).expect("build");
    let (mut signed, _) = btc_sign::sign(psbt.clone(), &s.m).expect("sign");
    signed.unsigned_tx.output[0].value = Amount::from_sat(60_000);
    assert!(matches!(
        finalize(&psbt, &signed),
        Err(SendError::BadSignature(_))
    ));
}

#[test]
fn signature_from_another_key_or_transaction_is_refused() {
    let s = setup();
    let (psbt, _) = build(&s.acct, &s.coins, &s.recipient, 50_000, 2, 1).expect("build");
    let (other_psbt, _) = build(&s.acct, &s.coins, &s.recipient, 40_000, 2, 1).expect("build2");
    let (other_signed, _) = btc_sign::sign(other_psbt, &s.m).expect("sign other");
    // Graft the other transaction's signatures onto ours.
    let mut grafted = psbt.clone();
    grafted.inputs[0].partial_sigs = other_signed.inputs[0].partial_sigs.clone();
    assert!(
        matches!(finalize(&psbt, &grafted), Err(SendError::BadSignature(m)) if m.contains("invalid"))
    );
    // No signature at all.
    assert!(matches!(
        finalize(&psbt, &psbt),
        Err(SendError::BadSignature(_))
    ));
}

#[test]
fn tablet_refuses_lies_about_coins() {
    let s = setup();
    let (psbt, _) = build(&s.acct, &s.coins, &s.recipient, 50_000, 2, 1).expect("build");

    // Claimed coin amount differs from the previous transaction (fee lie).
    let mut p = psbt.clone();
    if let Some(w) = p.inputs[0].witness_utxo.as_mut() {
        w.value = Amount::from_sat(1_000_000);
    }
    refused(btc_sign::review(&p, &s.m), "inconsistent");

    // Previous transaction swapped for another one.
    let mut p = psbt.clone();
    p.inputs[0].non_witness_utxo = Some(s.coins[0].prev_tx.clone());
    refused(btc_sign::review(&p, &s.m), "previous transaction");

    // Previous transaction missing.
    let mut p = psbt.clone();
    p.inputs[0].non_witness_utxo = None;
    refused(
        btc_sign::review(&p, &s.m),
        "missing its previous transaction",
    );

    // A coin of another wallet.
    let other = account(&master(5));
    let foreign = vec![funding(&other, 0, 0, 90_000, 7)];
    let (p, _) = build(&other, &foreign, &s.recipient, 50_000, 2, 1).expect("build foreign");
    refused(btc_sign::review(&p, &s.m), "another wallet");

    // Our fingerprint and path, but the key/script isn't ours.
    let mut p = psbt.clone();
    let (pk, src) = p.inputs[0].bip32_derivation.pop_first().expect("deriv");
    let mut src2 = src.clone();
    src2.1 = "m/84'/1'/0'/0/7".parse().expect("path");
    p.inputs[0].bip32_derivation.insert(pk, src2);
    refused(btc_sign::review(&p, &s.m), "doesn't match");
    let _ = src;
}

#[test]
fn tablet_refuses_fake_change_and_odd_transactions() {
    let s = setup();
    let (psbt, _) = build(&s.acct, &s.coins, &s.recipient, 50_000, 2, 1).expect("build");

    // "Change" that actually pays the attacker.
    let mut p = psbt.clone();
    let attacker = address(&account(&master(9)), 1, 1).expect("attacker");
    p.unsigned_tx.output[1].script_pubkey = attacker.script_pubkey();
    refused(btc_sign::review(&p, &s.m), "isn't this wallet's address");

    // Change marked as change on the receive chain.
    let mut p = psbt.clone();
    let (pk, mut src) = p.outputs[1].bip32_derivation.pop_first().expect("deriv");
    src.1 = "m/84'/1'/0'/0/1".parse().expect("path");
    p.outputs[1].bip32_derivation.insert(pk, src);
    refused(btc_sign::review(&p, &s.m), "unexpected path");

    // Change output turned into a second recipient.
    let mut p = psbt.clone();
    p.outputs[1].bip32_derivation.clear();
    p.unsigned_tx.output[1].script_pubkey = attacker.script_pubkey();
    refused(btc_sign::review(&p, &s.m), "only one recipient");

    // Huge fee: change shrunk so most of a large coin goes to the miners.
    let big = vec![funding(&s.acct, 0, 5, 1_000_000, 8)];
    let (p, _) = build(&s.acct, &big, &s.recipient, 50_000, 2, 1).expect("build");
    let mut p2 = p.clone();
    p2.unsigned_tx.output[1].value = Amount::from_sat(1_000);
    refused(btc_sign::review(&p2, &s.m), "above the limit");

    // Lock time.
    let mut p = psbt.clone();
    p.unsigned_tx.lock_time = absolute::LockTime::from_height(900_000).expect("lt");
    refused(btc_sign::review(&p, &s.m), "lock time");

    // Unknown extra data.
    let mut p = psbt.clone();
    p.unknown.insert(
        bitcoin::psbt::raw::Key {
            type_value: 0xfc,
            key: vec![1],
        },
        vec![2],
    );
    refused(btc_sign::review(&p, &s.m), "doesn't accept");

    // Already signed input / unusual sighash.
    let mut p = psbt.clone();
    p.inputs[0].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from(
        bitcoin::sighash::EcdsaSighashType::None,
    ));
    refused(btc_sign::review(&p, &s.m), "signature type");
}

#[test]
fn only_test_network_addresses_are_accepted() {
    assert!(parse_recipient("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu").is_err());
    let a = address(&account(&master(3)), 0, 0).expect("a").to_string();
    assert!(parse_recipient(&a).is_ok());
}

fn _unused(_: Psbt) {}
