//! Bitcoin **signet** test wallets and test payments (Phase 2 testing).
//! Coins on signet have no value. The UI→core commands live in
//! `commands.rs` (so the command review guard sees them); this file holds
//! the logic.

use std::collections::BTreeMap;

use btc_send::bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use btc_send::bitcoin::psbt::Psbt;
use btc_send::bitcoin::{Transaction, Txid};
use btc_send::{Account, Coin, Plan};
use data_sources::fetch::ConfirmedBtcFacts;
use data_sources::signet::Signet;
use data_sources::{CrossChecked, HttpClient, NetworkConfig};
use serde::{Deserialize, Serialize};
use watch_export::TestExport;

/// Unused addresses in a row before the scan stops (BIP-44 gap limit).
const GAP: u32 = 20;
/// Safety bound on addresses scanned per chain.
const MAX_INDEX: u32 = 300;

/// A test wallet as stored (public data only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestWallet {
    pub id: String,
    pub label: String,
    pub fingerprint: String,
    pub tpub: String,
}

impl From<TestExport> for TestWallet {
    fn from(e: TestExport) -> Self {
        Self {
            id: e.id.to_string(),
            label: e.label,
            fingerprint: e.fingerprint,
            tpub: e.tpub,
        }
    }
}

impl TestWallet {
    pub fn account(&self) -> Result<Account, String> {
        Ok(Account {
            xpub: self
                .tpub
                .parse()
                .map_err(|_| "stored test key is invalid".to_owned())?,
            fingerprint: self
                .fingerprint
                .parse()
                .map_err(|_| "stored fingerprint is invalid".to_owned())?,
        })
    }
}

/// One used address found by the scan.
#[derive(Debug, Clone, Serialize)]
pub struct UsedAddress {
    pub chain: u32,
    pub index: u32,
    pub address: String,
    pub confirmed_sats: u64,
}

/// Scan result for one test wallet.
#[derive(Debug, Clone, Serialize)]
pub struct TestWalletView {
    pub id: String,
    pub label: String,
    pub fingerprint: String,
    /// "verified" (both providers agree), "unverified" or "unavailable".
    pub status: &'static str,
    pub confirmed_sats: u64,
    pub used: Vec<UsedAddress>,
    /// Fresh receive address (first never-used) and its index.
    pub receive_address: String,
    pub receive_index: u32,
    /// First never-used change index (for the next payment's change).
    pub change_index: u32,
    pub problems: Vec<String>,
}

/// Scan receive and change addresses until 20 unused in a row.
pub async fn scan<H: HttpClient>(
    http: &H,
    config: &NetworkConfig,
    w: &TestWallet,
) -> Result<TestWalletView, String> {
    let acct = w.account()?;
    let signet = Signet::new(http, config);
    let mut used = Vec::new();
    let mut total = 0u64;
    let mut status = "verified";
    let mut problems = Vec::new();
    let mut first_unused = [None::<u32>; 2];
    for chain in [0u32, 1] {
        let mut unused_run = 0;
        let mut index = 0;
        while unused_run < GAP && index < MAX_INDEX {
            let addr = btc_send::address(&acct, chain, index).map_err(|e| e.to_string())?;
            let a = addr.to_string();
            let (facts, verified) = match signet.address_facts(&a).await {
                CrossChecked::Verified { value, .. } => (value, true),
                CrossChecked::Unverified { value, failed, .. } => {
                    if problems.is_empty() {
                        problems.extend(failed.into_iter().map(|(id, e)| format!("{id}: {e}")));
                    }
                    (value, false)
                }
                CrossChecked::Disagreement { answers } => {
                    return Err(format!(
                        "signet providers disagree about {a}: {}",
                        answers
                            .iter()
                            .map(|(id, v)| format!("{id} {} sats", v.confirmed_sats))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                }
                CrossChecked::Unavailable { failed } => {
                    return Err(format!(
                        "signet providers didn't answer: {}",
                        failed
                            .iter()
                            .map(|(id, e)| format!("{id}: {e}"))
                            .collect::<Vec<_>>()
                            .join("; ")
                    ))
                }
            };
            if !verified {
                status = "unverified";
            }
            let ConfirmedBtcFacts {
                confirmed_sats,
                tx_count,
            } = facts;
            if tx_count > 0 {
                unused_run = 0;
                total += confirmed_sats;
                used.push(UsedAddress {
                    chain,
                    index,
                    address: a,
                    confirmed_sats,
                });
            } else {
                unused_run += 1;
                first_unused[chain as usize].get_or_insert(index);
            }
            index += 1;
        }
    }
    let receive_index = first_unused[0].unwrap_or(0);
    Ok(TestWalletView {
        id: w.id.clone(),
        label: w.label.clone(),
        fingerprint: w.fingerprint.clone(),
        status,
        confirmed_sats: total,
        used,
        receive_address: btc_send::address(&acct, 0, receive_index)
            .map_err(|e| e.to_string())?
            .to_string(),
        receive_index,
        change_index: first_unused[1].unwrap_or(0),
        problems,
    })
}

/// Collect this wallet's confirmed coins, each with its full previous
/// transaction (checked to hash to the coin's txid).
pub async fn coins<H: HttpClient>(
    http: &H,
    config: &NetworkConfig,
    used: &[UsedAddress],
) -> Result<Vec<Coin>, String> {
    let signet = Signet::new(http, config);
    let mut prev: BTreeMap<String, Transaction> = BTreeMap::new();
    let mut out = Vec::new();
    for u in used.iter().filter(|u| u.confirmed_sats > 0) {
        let utxos = signet.utxos(&u.address).await?.value;
        for c in utxos.into_iter().filter(|c| c.confirmed) {
            if !prev.contains_key(&c.txid) {
                let hex = signet.tx_hex(&c.txid).await?.value;
                let tx: Transaction = deserialize_hex(&hex)
                    .map_err(|_| "a provider sent an unreadable transaction".to_owned())?;
                let want: Txid = c.txid.parse().map_err(|_| "bad txid".to_owned())?;
                if tx.compute_txid() != want {
                    return Err("a provider sent the wrong previous transaction".into());
                }
                prev.insert(c.txid.clone(), tx);
            }
            if let Some(tx) = prev.get(&c.txid) {
                out.push(Coin {
                    prev_tx: tx.clone(),
                    vout: c.vout,
                    chain: u.chain,
                    index: u.index,
                });
            }
        }
    }
    Ok(out)
}

/// A payment built on this PC and waiting for the tablet's signature.
pub struct PendingSend {
    pub wallet_id: String,
    pub psbt: Psbt,
    pub plan: Plan,
}

/// Result of broadcasting.
#[derive(Debug, Clone, Serialize)]
pub struct SentView {
    pub txid: String,
    pub accepted_by: Vec<String>,
    pub errors: Vec<String>,
    pub explorer_url: String,
}

pub async fn broadcast<H: HttpClient>(
    http: &H,
    config: &NetworkConfig,
    tx: &Transaction,
) -> Result<SentView, String> {
    let txid = tx.compute_txid().to_string();
    let raw = serialize_hex(tx);
    let answers = Signet::new(http, config).broadcast(&raw).await;
    let mut accepted_by = Vec::new();
    let mut errors = Vec::new();
    for (id, r) in answers {
        match r {
            Ok(t) if t == txid => accepted_by.push(id),
            Ok(t) => errors.push(format!("{id}: answered with a different id {t}")),
            Err(e) => errors.push(format!("{id}: {e}")),
        }
    }
    if accepted_by.is_empty() {
        return Err(format!(
            "No provider accepted the transaction: {}",
            errors.join("; ")
        ));
    }
    Ok(SentView {
        explorer_url: format!("https://mempool.space/signet/tx/{txid}"),
        txid,
        accepted_by,
        errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_send::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
    use btc_send::bitcoin::secp256k1::Secp256k1;
    use btc_send::bitcoin::{
        absolute, transaction, Amount, NetworkKind, OutPoint, ScriptBuf, Sequence, TxIn, TxOut,
        Witness,
    };
    use data_sources::fetch::mock::MockHttp;

    fn wallet() -> (TestWallet, Account) {
        let secp = Secp256k1::new();
        let m = Xpriv::new_master(NetworkKind::Test, &[4u8; 64]).expect("m");
        let path: DerivationPath = "m/84'/1'/0'".parse().expect("p");
        let x = Xpub::from_priv(&secp, &m.derive_priv(&secp, &path).expect("a"));
        let w = TestWallet {
            id: "test-01".into(),
            label: "Test".into(),
            fingerprint: m.fingerprint(&secp).to_string(),
            tpub: x.to_string(),
        };
        let a = w.account().expect("acct");
        (w, a)
    }

    fn stats(sats: u64, txs: u64) -> String {
        format!(
            r#"{{"chain_stats":{{"funded_txo_sum":{sats},"spent_txo_sum":0,"tx_count":{txs}}},"mempool_stats":{{"funded_txo_sum":0,"spent_txo_sum":0,"tx_count":0}}}}"#
        )
    }

    #[tokio::test]
    async fn scan_collect_coins_and_broadcast() {
        let config = NetworkConfig::embedded().expect("config");
        let (w, acct) = wallet();
        let r0 = btc_send::address(&acct, 0, 0).expect("r0");
        let prev = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(70_000),
                script_pubkey: r0.script_pubkey(),
            }],
        };
        let txid = prev.compute_txid().to_string();
        let mut http = MockHttp::default();
        for p in &config.signet_providers {
            for chain in [0u32, 1] {
                for i in 0..25 {
                    let a = btc_send::address(&acct, chain, i).expect("a").to_string();
                    let body = if chain == 0 && i == 0 {
                        stats(70_000, 1)
                    } else {
                        stats(0, 0)
                    };
                    http.on_get(&format!("{}/address/{a}", p.base_url), &body);
                }
            }
        }
        let p0 = &config.signet_providers[0].base_url;
        http.on_get(
            &format!("{p0}/address/{r0}/utxo"),
            &format!(
                r#"[{{"txid":"{txid}","vout":0,"value":70000,"status":{{"confirmed":true}}}}]"#
            ),
        );
        http.on_get(&format!("{p0}/tx/{txid}/hex"), &serialize_hex(&prev));

        let v = scan(&http, &config, &w).await.expect("scan");
        assert_eq!(v.status, "verified");
        assert_eq!(v.confirmed_sats, 70_000);
        assert_eq!((v.receive_index, v.change_index), (1, 0));
        assert!(v.receive_address.starts_with("tb1q"));

        let coins = coins(&http, &config, &v.used).await.expect("coins");
        assert_eq!(coins.len(), 1);
        assert_eq!(coins[0].prev_tx.compute_txid().to_string(), txid);

        // A provider sending the wrong previous transaction is caught.
        let mut bad = MockHttp::default();
        bad.on_get(
            &format!("{p0}/address/{r0}/utxo"),
            &format!(
                r#"[{{"txid":"{}","vout":0,"value":70000,"status":{{"confirmed":true}}}}]"#,
                "ab".repeat(32)
            ),
        );
        bad.on_get(
            &format!("{p0}/tx/{}/hex", "ab".repeat(32)),
            &serialize_hex(&prev),
        );
        assert!(coins_err(&bad, &config, &v.used)
            .await
            .contains("wrong previous transaction"));

        // Broadcast: accepted by one provider is enough; the other's error is reported.
        let raw = serialize_hex(&prev);
        let mut b = MockHttp::default();
        b.on_post_text(&format!("{p0}/tx"), &raw, Ok(txid.clone()));
        let sent = broadcast(&b, &config, &prev).await.expect("sent");
        assert_eq!(sent.accepted_by.len(), 1);
        assert_eq!(sent.errors.len(), 1);
        assert!(broadcast(&MockHttp::default(), &config, &prev)
            .await
            .is_err());
    }

    async fn coins_err(h: &MockHttp, c: &NetworkConfig, used: &[UsedAddress]) -> String {
        coins(h, c, used).await.err().unwrap_or_default()
    }
}
