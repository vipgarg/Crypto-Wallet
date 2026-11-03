//! Bitcoin history with poisoning and dust warnings.
//!
//! For an account key (zpub), the addresses in use are found the same way as
//! for the balance (receive and change chains, stopping after 20 unused in a
//! row), and each used address's transactions are loaded. A transaction's
//! direction and amount come from how much of its inputs and outputs belong
//! to this wallet.
//!
//! Flags:
//! - **Dust** received (< 1,000 sats) is hidden. It can be a tracking
//!   ("dust") attack: spending it together with your other coins links them.
//! - A counterparty that looks like one of your addresses or a real
//!   counterparty (same 3 characters after "bc1q"/"bc1p" or the first
//!   character, or the same last 3) is flagged.
//!
//! History comes from one provider at a time and isn't cross-checked.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use chain_btc::esplora::BtcTx;
use chain_btc::{Chain, GapScanner, GAP_LIMIT};
use data_sources::fetch::Sources;
use data_sources::HttpClient;
use wallet_types::{Amount, Asset};

use crate::activity::{looks_alike, ActivityEntry, Direction, Flag, Known};
use crate::registry::BtcWatch;

/// Received amounts below this are treated as dust.
pub const DUST_SATS: u64 = 1_000;
/// Pages (25 confirmed transactions each) loaded per address.
pub const MAX_PAGES_PER_ADDRESS: usize = 4;
/// Upper bound on addresses scanned per chain (safety net).
pub const MAX_INDEX: u32 = 500;

/// Characters to skip before comparing two addresses (the fixed prefix).
pub fn btc_prefix_len(a: &str) -> usize {
    if a.starts_with("bc1") {
        4
    } else {
        1
    }
}

/// Everything loaded for one wallet.
#[derive(Debug, Clone, Default)]
pub struct BtcHistory {
    /// Providers that answered (one per address; usually the same one).
    pub providers: BTreeSet<String>,
    pub txs: Vec<BtcTx>,
    /// Every address of this wallet that was looked at.
    pub mine: HashSet<String>,
    /// Used receive addresses (for the look-alike check).
    pub used_receive: Vec<String>,
    pub unreadable: usize,
    /// Addresses whose oldest transactions were left out (too many).
    pub truncated: usize,
    /// Set if the scan stopped early; the history is then incomplete.
    pub incomplete: Option<String>,
}

/// Load the transactions of every used address of `watch`.
pub async fn load_btc_history<H: HttpClient>(
    src: &Sources<'_, H>,
    watch: &BtcWatch,
) -> Result<BtcHistory, String> {
    let mut h = BtcHistory::default();
    let mut by_id: BTreeMap<String, BtcTx> = BTreeMap::new();
    match watch {
        BtcWatch::Address(addr) => {
            h.mine.insert(addr.to_string());
            let r = src.btc_address_txs(addr, MAX_PAGES_PER_ADDRESS).await?;
            h.providers.insert(r.provider);
            let (txs, bad, more) = r.value;
            h.unreadable += bad;
            h.truncated += usize::from(more);
            h.used_receive.push(addr.to_string());
            for t in txs {
                by_id.insert(t.txid.clone(), t);
            }
        }
        BtcWatch::AccountXpub(x) => {
            'chains: for chain in [Chain::Receive, Chain::Change] {
                let mut gap = GapScanner::new(GAP_LIMIT);
                while let Some(index) = gap.next() {
                    if index >= MAX_INDEX {
                        break;
                    }
                    let addr =
                        x.0.derive_address(chain, index)
                            .map_err(|e| e.to_string())?;
                    h.mine.insert(addr.to_string());
                    match src.btc_address_txs(&addr, MAX_PAGES_PER_ADDRESS).await {
                        Ok(r) => {
                            h.providers.insert(r.provider);
                            let (txs, bad, more) = r.value;
                            h.unreadable += bad;
                            h.truncated += usize::from(more);
                            let used = !txs.is_empty();
                            if used && chain == Chain::Receive {
                                h.used_receive.push(addr.to_string());
                            }
                            for t in txs {
                                by_id.insert(t.txid.clone(), t);
                            }
                            gap.record(used);
                        }
                        Err(e) if by_id.is_empty() && h.providers.is_empty() => return Err(e),
                        Err(e) => {
                            h.incomplete = Some(format!(
                                "Stopped at {} address #{index}: {e}",
                                if chain == Chain::Receive {
                                    "receive"
                                } else {
                                    "change"
                                }
                            ));
                            break 'chains;
                        }
                    }
                }
            }
        }
    }
    h.txs = by_id.into_values().collect();
    Ok(h)
}

fn sats_text(s: u64) -> String {
    Amount::new(Asset::Btc, u128::from(s)).to_decimal_string()
}

/// Your other wallets' addresses, this wallet's used receive addresses, and
/// the counterparties of real (non-dust) transactions.
pub fn known_counterparties_btc(h: &BtcHistory, own_other: &[Known]) -> Vec<Known> {
    let mut known: Vec<Known> = own_other.to_vec();
    known.extend(h.used_receive.iter().map(|a| {
        (
            a.clone(),
            "one of this wallet's receive addresses".to_owned(),
        )
    }));
    let mut seen = BTreeSet::new();
    for t in &h.txs {
        let (my_in, my_out, _) = sums(t, &h.mine);
        let received = my_out.saturating_sub(my_in);
        if my_in == 0 && received < DUST_SATS {
            continue; // dust can't make an address "known"
        }
        let others: Vec<&String> = if my_in > 0 {
            t.outputs
                .iter()
                .filter_map(|o| o.address.as_ref())
                .collect()
        } else {
            t.inputs.iter().filter_map(|i| i.address.as_ref()).collect()
        };
        for a in others {
            if !h.mine.contains(a) && seen.insert(a.clone()) {
                known.push((a.clone(), "someone you transacted with".into()));
            }
        }
    }
    known
}

/// (sats in from my addresses, sats out to my addresses, sats out to others)
fn sums(t: &BtcTx, mine: &HashSet<String>) -> (u64, u64, u64) {
    let is_mine = |a: &Option<String>| a.as_ref().is_some_and(|a| mine.contains(a));
    let my_in = t
        .inputs
        .iter()
        .filter(|i| is_mine(&i.address))
        .map(|i| i.sats)
        .fold(0u64, u64::saturating_add);
    let (mut my_out, mut ext_out) = (0u64, 0u64);
    for o in &t.outputs {
        if is_mine(&o.address) {
            my_out = my_out.saturating_add(o.sats);
        } else {
            ext_out = ext_out.saturating_add(o.sats);
        }
    }
    (my_in, my_out, ext_out)
}

fn lookalike(known: &[Known], cp: &str) -> Option<Flag> {
    known
        .iter()
        .find(|(k, _)| {
            btc_prefix_len(k) == btc_prefix_len(cp) && looks_alike(k, cp, btc_prefix_len(cp))
        })
        .map(|(addr, label)| Flag::LookAlike {
            similar_to: addr.clone(),
            similar_to_label: label.clone(),
        })
}

/// One entry per transaction, newest first (unconfirmed at the top).
pub fn classify_btc(h: &BtcHistory, known: &[Known]) -> Vec<ActivityEntry> {
    let mut out: Vec<(u64, ActivityEntry)> = h
        .txs
        .iter()
        .filter_map(|t| {
            let (my_in, my_out, ext_out) = sums(t, &h.mine);
            if my_in == 0 && my_out == 0 {
                return None;
            }
            let mut flags = Vec::new();
            let mut hidden = false;
            let (direction, amount, cp) = if my_in == 0 {
                let cp = t
                    .inputs
                    .iter()
                    .find_map(|i| i.address.clone().filter(|a| !h.mine.contains(a)));
                if my_out < DUST_SATS {
                    flags.push(Flag::BtcDust {
                        below: "1,000 sats".into(),
                    });
                    hidden = true;
                }
                (Direction::In, my_out, cp)
            } else if ext_out == 0 {
                // Between this wallet's own addresses; the amount is the fee.
                (Direction::SelfTransfer, my_in.saturating_sub(my_out), None)
            } else {
                let cp = t
                    .outputs
                    .iter()
                    .find_map(|o| o.address.clone().filter(|a| !h.mine.contains(a)));
                (Direction::Out, my_in.saturating_sub(my_out), cp)
            };
            if t.block_time.is_none() {
                flags.push(Flag::Unconfirmed);
            }
            if let Some(c) = &cp {
                flags.extend(lookalike(known, c));
            }
            // Unconfirmed sort first.
            let sort_key = t.block_time.unwrap_or(u64::MAX);
            Some((
                sort_key,
                ActivityEntry {
                    txid: t.txid.clone(),
                    time_ms: t.block_time.map_or(0, |s| s.saturating_mul(1000)),
                    direction,
                    is_approval: false,
                    token_label: Asset::Btc.label().to_owned(),
                    genuine_usdt: false,
                    amount: Some(sats_text(amount)),
                    counterparty: cp.unwrap_or_else(|| "(your own addresses)".to_owned()),
                    flags,
                    hidden,
                },
            ))
        })
        .collect();
    out.sort_by_key(|e| std::cmp::Reverse(e.0));
    out.into_iter().map(|(_, e)| e).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_btc::esplora::TxIo;

    fn io(a: &str, sats: u64) -> TxIo {
        TxIo {
            address: Some(a.to_owned()),
            sats,
        }
    }
    fn tx(n: u8, time: Option<u64>, inputs: Vec<TxIo>, outputs: Vec<TxIo>) -> BtcTx {
        BtcTx {
            txid: format!("{n:064x}"),
            block_time: time,
            inputs,
            outputs,
            fee_sats: 0,
        }
    }

    const ME_R0: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    const ME_C0: &str = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el";
    const FRIEND: &str = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
    // Same "xy2" after bc1q and same last 3 "wlh" as FRIEND.
    const FAKE: &str = "bc1qxy2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawlh";

    fn history(txs: Vec<BtcTx>) -> BtcHistory {
        BtcHistory {
            txs,
            mine: [ME_R0, ME_C0].iter().map(|s| (*s).to_owned()).collect(),
            used_receive: vec![ME_R0.to_owned()],
            ..BtcHistory::default()
        }
    }

    #[test]
    fn directions_amounts_and_dust() {
        let h = history(vec![
            // Received 0.001 BTC from a friend.
            tx(
                1,
                Some(100),
                vec![io(FRIEND, 200_000)],
                vec![io(ME_R0, 100_000), io(FRIEND, 99_000)],
            ),
            // Sent 50,000 sats to the friend, change back to me, 1,000 fee.
            tx(
                2,
                Some(200),
                vec![io(ME_R0, 100_000)],
                vec![io(FRIEND, 50_000), io(ME_C0, 49_000)],
            ),
            // Dust from a look-alike of the friend.
            tx(
                3,
                Some(300),
                vec![io(FAKE, 5_000)],
                vec![io(ME_R0, 546), io(FAKE, 4_000)],
            ),
            // Unconfirmed self-transfer (fee 500).
            tx(4, None, vec![io(ME_C0, 49_000)], vec![io(ME_R0, 48_500)]),
        ]);
        let known = known_counterparties_btc(&h, &[]);
        let e = classify_btc(&h, &known);
        assert_eq!(e.len(), 4);
        // Newest first, unconfirmed on top.
        assert_eq!(e[0].direction, Direction::SelfTransfer);
        assert!(e[0].flags.contains(&Flag::Unconfirmed));
        assert_eq!(e[0].amount.as_deref(), Some("0.000005"));

        assert_eq!(e[1].direction, Direction::In);
        assert!(e[1].hidden);
        assert!(e[1].flags.iter().any(|f| matches!(f, Flag::BtcDust { .. })));
        assert!(
            e[1].flags
                .iter()
                .any(|f| matches!(f, Flag::LookAlike { similar_to, .. } if similar_to == FRIEND)),
            "{:?}",
            e[1].flags
        );

        assert_eq!(e[2].direction, Direction::Out);
        assert_eq!(
            e[2].amount.as_deref(),
            Some("0.00051"),
            "amount includes the fee"
        );
        assert_eq!(e[2].counterparty, FRIEND);
        assert!(!e[2].hidden && e[2].flags.is_empty(), "{:?}", e[2].flags);

        assert_eq!(e[3].direction, Direction::In);
        assert_eq!(e[3].amount.as_deref(), Some("0.001"));
        assert!(!e[3].hidden);
    }

    #[test]
    fn dust_never_makes_an_address_known() {
        let h = history(vec![tx(
            1,
            Some(1),
            vec![io(FAKE, 5_000)],
            vec![io(ME_R0, 546)],
        )]);
        let known = known_counterparties_btc(&h, &[]);
        assert!(known.iter().all(|(a, _)| a != FAKE));
    }

    #[tokio::test(start_paused = true)]
    async fn loads_used_addresses_of_an_account() {
        use crate::registry::AccountXpubSer;
        use chain_btc::esplora::txs_path;
        use chain_btc::AccountXpub;
        use data_sources::config::FEATURE_ADDRESS_HISTORY;
        use data_sources::fetch::mock::MockHttp;
        use data_sources::NetworkConfig;
        use wallet_types::Network;

        const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
        let acct: AccountXpub = ZPUB.parse().expect("zpub");
        let config = NetworkConfig::embedded().expect("config");
        let p = config
            .with_feature(Network::Bitcoin, FEATURE_ADDRESS_HISTORY)
            .next()
            .expect("provider");
        let r0 = acct
            .derive_address(Chain::Receive, 0)
            .expect("r0")
            .to_string();
        let r3 = acct
            .derive_address(Chain::Receive, 3)
            .expect("r3")
            .to_string();
        let mut http = MockHttp::default();
        for chain in [Chain::Receive, Chain::Change] {
            for i in 0..40 {
                let a = acct.derive_address(chain, i).expect("a").to_string();
                let body = if a == r0 || a == r3 {
                    format!(
                        r#"[{{"txid":"{:064x}","vin":[{{"prevout":{{"scriptpubkey_address":"{FRIEND}","value":90000}}}}],"vout":[{{"scriptpubkey_address":"{a}","value":80000}}],"fee":10000,"status":{{"confirmed":true,"block_time":{}}}}}]"#,
                        i + 1,
                        1_700_000_000 + i
                    )
                } else {
                    "[]".to_owned()
                };
                http.on_get(&format!("{}{}", p.base_url, txs_path(&a)), &body);
            }
        }
        let src = Sources::new(&http, &config);
        let h = load_btc_history(&src, &BtcWatch::AccountXpub(AccountXpubSer(acct)))
            .await
            .expect("history");
        assert!(h.incomplete.is_none(), "{:?}", h.incomplete);
        assert_eq!(h.txs.len(), 2);
        assert_eq!(h.used_receive, vec![r0, r3]);
        // Receive scanned to #3 + 20 unused; change to 20 unused.
        assert_eq!(h.mine.len(), 24 + 20);
        assert_eq!(h.providers.len(), 1);
        let e = classify_btc(&h, &known_counterparties_btc(&h, &[]));
        assert!(e.iter().all(|x| x.direction == Direction::In && !x.hidden));
    }

    #[test]
    fn prefix_lengths() {
        assert_eq!(btc_prefix_len("bc1qabc"), 4);
        assert_eq!(btc_prefix_len("bc1pabc"), 4);
        assert_eq!(btc_prefix_len("1BoatSLRHtKNngkdXEeobR76b53LETtpyT"), 1);
    }
}
