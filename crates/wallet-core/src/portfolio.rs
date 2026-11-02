//! Cross-checked portfolio view (§5.5). Every number states how it was
//! verified. Totals only include verified balances and say when they're
//! incomplete.

use chain_btc::{Chain, GapScanner, GAP_LIMIT};
use data_sources::fetch::Sources;
use data_sources::{CrossChecked, HttpClient, NetworkConfig};
use serde::Serialize;
use wallet_types::{short_address, Amount, Asset, Tier, WalletId};

use crate::registry::{BtcWatch, Registry, WatchWallet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BalanceStatus {
    /// ≥2 independent providers gave the identical answer.
    Verified,
    /// Only one provider answered.
    Unverified,
    /// Providers gave different answers; no value is shown.
    Disagreement,
    /// No provider answered.
    Unavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetBalance {
    pub asset: Asset,
    pub label: &'static str,
    pub status: BalanceStatus,
    pub amount: Option<Amount>,
    /// Exact decimal string, e.g. "12.5". Integer-formatted, never a float.
    pub display: Option<String>,
    pub sources: Vec<String>,
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WalletPortfolio {
    pub id: WalletId,
    pub label: String,
    pub tier: Tier,
    pub tier_name: &'static str,
    pub balances: Vec<AssetBalance>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetTotal {
    pub asset: Asset,
    pub label: &'static str,
    pub verified_total: Amount,
    /// `None` when no balance of this asset could be verified, so the UI never
    /// shows a misleading "0".
    pub display: Option<String>,
    pub verified_wallets: usize,
    /// False if any wallet's balance for this asset wasn't verified, so the
    /// total may be missing something.
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Portfolio {
    pub wallets: Vec<WalletPortfolio>,
    pub totals: Vec<AssetTotal>,
    pub config_sha256: String,
    pub warnings: Vec<String>,
}

fn from_checked(asset: Asset, c: CrossChecked<u128>) -> AssetBalance {
    let fmt = |v: u128| Amount::new(asset, v).to_decimal_string();
    let (status, value, sources, problems) = match c {
        CrossChecked::Verified { value, sources } => {
            (BalanceStatus::Verified, Some(value), sources, vec![])
        }
        CrossChecked::Unverified {
            value,
            source,
            failed,
        } => (
            BalanceStatus::Unverified,
            Some(value),
            vec![source],
            failed
                .into_iter()
                .map(|(id, e)| format!("{id}: {e}"))
                .collect(),
        ),
        CrossChecked::Disagreement { answers } => (
            BalanceStatus::Disagreement,
            None,
            vec![],
            answers
                .into_iter()
                .map(|(id, v)| format!("{id} says {} {}", fmt(v), asset.symbol()))
                .collect(),
        ),
        CrossChecked::Unavailable { failed } => (
            BalanceStatus::Unavailable,
            None,
            vec![],
            failed
                .into_iter()
                .map(|(id, e)| format!("{id}: {e}"))
                .collect(),
        ),
    };
    AssetBalance {
        asset,
        label: asset.label(),
        status,
        amount: value.map(|v| Amount::new(asset, v)),
        display: value.map(fmt),
        sources,
        problems,
    }
}

/// Scan a BIP-84 account (receive + change chains, gap limit 20), summing
/// confirmed balances. Stops at the first disagreement or outage: a partial
/// scan is never reported as a verified total.
async fn scan_btc_account<H: HttpClient>(
    src: &Sources<'_, H>,
    acct: &chain_btc::AccountXpub,
) -> AssetBalance {
    let mut total: u128 = 0;
    let mut status = BalanceStatus::Verified;
    let mut problems = Vec::new();
    let mut sources = Vec::new();
    for chain in [Chain::Receive, Chain::Change] {
        let mut gap = GapScanner::new(GAP_LIMIT);
        while let Some(index) = gap.next() {
            let addr = match acct.derive_address(chain, index) {
                Ok(a) => a,
                Err(e) => {
                    return failed(Asset::Btc, BalanceStatus::Unavailable, vec![e.to_string()])
                }
            };
            let where_ = format!(
                "{} ({:?} #{index})",
                short_address(&addr.to_string()),
                chain
            );
            match src.btc_address(&addr).await {
                CrossChecked::Verified { value, sources: s } => {
                    sources = s;
                    total = total.saturating_add(u128::from(value.confirmed_sats));
                    gap.record(value.tx_count > 0);
                }
                CrossChecked::Unverified {
                    value,
                    source,
                    failed: f,
                } => {
                    status = BalanceStatus::Unverified;
                    sources = vec![source];
                    if problems.is_empty() {
                        problems.extend(f.into_iter().map(|(id, e)| format!("{id}: {e}")));
                    }
                    total = total.saturating_add(u128::from(value.confirmed_sats));
                    gap.record(value.tx_count > 0);
                }
                CrossChecked::Disagreement { answers } => {
                    let detail = answers
                        .iter()
                        .map(|(id, v)| {
                            format!("{id} says {} sats / {} txs", v.confirmed_sats, v.tx_count)
                        })
                        .collect::<Vec<_>>()
                        .join("; ");
                    return failed(
                        Asset::Btc,
                        BalanceStatus::Disagreement,
                        vec![format!("{where_}: {detail}")],
                    );
                }
                CrossChecked::Unavailable { failed: f } => {
                    let mut p = vec![format!("scan stopped at {where_}")];
                    p.extend(f.into_iter().map(|(id, e)| format!("{id}: {e}")));
                    return failed(Asset::Btc, BalanceStatus::Unavailable, p);
                }
            }
        }
    }
    let amount = Amount::new(Asset::Btc, total);
    AssetBalance {
        asset: Asset::Btc,
        label: Asset::Btc.label(),
        status,
        amount: Some(amount),
        display: Some(amount.to_decimal_string()),
        sources,
        problems,
    }
}

fn failed(asset: Asset, status: BalanceStatus, problems: Vec<String>) -> AssetBalance {
    AssetBalance {
        asset,
        label: asset.label(),
        status,
        amount: None,
        display: None,
        sources: vec![],
        problems,
    }
}

async fn wallet_portfolio<H: HttpClient>(src: &Sources<'_, H>, w: &WatchWallet) -> WalletPortfolio {
    let mut balances = Vec::new();
    match &w.btc {
        Some(BtcWatch::AccountXpub(x)) => balances.push(scan_btc_account(src, &x.0).await),
        Some(BtcWatch::Address(a)) => {
            let c = src.btc_address(a).await;
            let mapped = match c {
                CrossChecked::Verified { value, sources } => CrossChecked::Verified {
                    value: u128::from(value.confirmed_sats),
                    sources,
                },
                CrossChecked::Unverified {
                    value,
                    source,
                    failed,
                } => CrossChecked::Unverified {
                    value: u128::from(value.confirmed_sats),
                    source,
                    failed,
                },
                CrossChecked::Disagreement { answers } => CrossChecked::Disagreement {
                    answers: answers
                        .into_iter()
                        .map(|(id, v)| (id, u128::from(v.confirmed_sats)))
                        .collect(),
                },
                CrossChecked::Unavailable { failed } => CrossChecked::Unavailable { failed },
            };
            balances.push(from_checked(Asset::Btc, mapped));
        }
        None => {}
    }
    if let Some(eth) = &w.eth {
        balances.push(from_checked(Asset::UsdtErc20, src.usdt_erc20(eth).await));
        balances.push(from_checked(Asset::Eth, src.eth(eth).await));
    }
    if let Some(tron) = &w.tron {
        balances.push(from_checked(Asset::UsdtTrc20, src.usdt_trc20(tron).await));
        balances.push(from_checked(Asset::Trx, src.trx(tron).await));
    }
    WalletPortfolio {
        id: w.id.clone(),
        label: w.label.clone(),
        tier: w.tier,
        tier_name: w.tier.display_name(),
        balances,
    }
}

pub async fn build_portfolio<H: HttpClient>(
    http: &H,
    config: &NetworkConfig,
    registry: &Registry,
) -> Portfolio {
    let src = Sources { http, config };
    let mut wallets = Vec::new();
    for w in &registry.wallets {
        wallets.push(wallet_portfolio(&src, w).await);
    }

    let mut totals = Vec::new();
    for asset in Asset::ALL {
        let mut sum = Amount::zero(asset);
        let mut complete = true;
        let mut present = false;
        let mut verified_wallets = 0usize;
        for b in wallets
            .iter()
            .flat_map(|w| &w.balances)
            .filter(|b| b.asset == asset)
        {
            present = true;
            match (b.status, b.amount) {
                (BalanceStatus::Verified, Some(a)) => match sum.checked_add(a) {
                    Ok(s) => {
                        sum = s;
                        verified_wallets += 1;
                    }
                    Err(_) => complete = false,
                },
                _ => complete = false,
            }
        }
        if present {
            totals.push(AssetTotal {
                asset,
                label: asset.label(),
                verified_total: sum,
                display: (verified_wallets > 0).then(|| sum.to_decimal_string()),
                verified_wallets,
                complete,
            });
        }
    }

    let mut warnings = Vec::new();
    for n in config.networks_lacking_independence() {
        warnings.push(format!(
            "{} has fewer than 2 independent data providers configured; its balances can't be verified",
            n.display_name()
        ));
    }
    if totals.iter().any(|t| !t.complete) {
        warnings.push(
            "Some balances aren't verified by 2 providers; totals include verified balances only"
                .into(),
        );
    }

    Portfolio {
        wallets,
        totals,
        config_sha256: config.sha256.clone(),
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::NewWalletInput;
    use chain_btc::AccountXpub;
    use chain_eth::rpc;
    use chain_tron::api;
    use data_sources::fetch::mock::MockHttp;
    use serde_json::json;
    use wallet_types::Network;

    const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    fn esplora(sats: u64, txs: u64) -> String {
        format!(
            r#"{{"chain_stats":{{"funded_txo_sum":{sats},"spent_txo_sum":0,"tx_count":{txs}}},"mempool_stats":{{"funded_txo_sum":0,"spent_txo_sum":0,"tx_count":0}}}}"#
        )
    }

    fn word(n: u128) -> String {
        format!("{n:064x}")
    }

    /// Every provider answers every BTC address of the account; receive #0 and
    /// change #0 hold funds, everything else is unused.
    fn mock_btc(http: &mut MockHttp, config: &NetworkConfig, disagree_at_receive_0: bool) {
        let acct: AccountXpub = ZPUB.parse().expect("zpub");
        for (pi, p) in config.providers_for(Network::Bitcoin).enumerate() {
            for chain in [Chain::Receive, Chain::Change] {
                for i in 0..=GAP_LIMIT + 1 {
                    let a = acct.derive_address(chain, i).expect("derive");
                    let body = match (chain, i) {
                        (Chain::Receive, 0) if disagree_at_receive_0 && pi == 1 => esplora(1, 1),
                        (Chain::Receive, 0) => esplora(150_000, 2),
                        (Chain::Change, 0) => esplora(50_000, 1),
                        _ => esplora(0, 0),
                    };
                    http.on_get(&format!("{}/address/{}", p.base_url, a), &body);
                }
            }
        }
    }

    fn registry() -> Registry {
        let mut r = Registry::empty();
        let w = NewWalletInput {
            id: "savings-01".into(),
            label: "Savings".into(),
            tier: Tier::Savings,
            btc: Some(ZPUB.into()),
            eth: Some("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".into()),
            tron: Some("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".into()),
        };
        r.add(w.validate().expect("valid")).expect("add");
        r
    }

    fn mock_eth_tron(
        http: &mut MockHttp,
        config: &NetworkConfig,
        reg: &Registry,
        usdt_trc20_second: u128,
    ) {
        let w = &reg.wallets[0];
        let eth = w.eth.expect("eth");
        let tron = w.tron.expect("tron");
        for p in config.providers_for(Network::Ethereum) {
            http.on_post(
                &p.base_url,
                &rpc::erc20_balance_of(&config.usdt_erc20, &eth),
                json!({"result": format!("0x{}", word(2_000_000))}),
            );
            http.on_post(
                &p.base_url,
                &rpc::eth_get_balance(&eth),
                json!({"result": "0x2386f26fc10000"}),
            );
        }
        for (i, p) in config.providers_for(Network::Tron).enumerate() {
            let v = if i == 0 {
                30_000_000
            } else {
                usdt_trc20_second
            };
            http.on_post(
                &format!("{}{}", p.base_url, api::TRIGGER_CONSTANT_PATH),
                &api::trc20_balance_of(&config.usdt_trc20, &tron),
                json!({"result": {"result": true}, "constant_result": [word(v)]}),
            );
            http.on_post(
                &format!("{}{}", p.base_url, api::GET_ACCOUNT_PATH),
                &api::get_account(&tron),
                json!({"balance": 5_000_000}),
            );
        }
    }

    #[tokio::test]
    async fn all_verified() {
        let config = NetworkConfig::embedded().expect("config");
        let reg = registry();
        let mut http = MockHttp::default();
        mock_btc(&mut http, &config, false);
        mock_eth_tron(&mut http, &config, &reg, 30_000_000);
        let p = build_portfolio(&http, &config, &reg).await;
        let b = &p.wallets[0].balances;
        let get = |a: Asset| b.iter().find(|x| x.asset == a).expect("asset");
        assert_eq!(get(Asset::Btc).status, BalanceStatus::Verified);
        assert_eq!(get(Asset::Btc).display.as_deref(), Some("0.002"));
        assert_eq!(get(Asset::UsdtErc20).display.as_deref(), Some("2"));
        assert_eq!(get(Asset::Eth).display.as_deref(), Some("0.01"));
        assert_eq!(get(Asset::UsdtTrc20).display.as_deref(), Some("30"));
        assert_eq!(get(Asset::Trx).display.as_deref(), Some("5"));
        assert!(p.totals.iter().all(|t| t.complete));
        assert!(p.warnings.is_empty());
        // Privacy: only single addresses were requested from providers.
        assert!(http
            .requested()
            .iter()
            .all(|r| !r.contains("zpub") && !r.contains("xpub")));
    }

    #[tokio::test]
    async fn disagreement_hides_value_and_marks_total_incomplete() {
        let config = NetworkConfig::embedded().expect("config");
        let reg = registry();
        let mut http = MockHttp::default();
        mock_btc(&mut http, &config, true);
        mock_eth_tron(&mut http, &config, &reg, 29_000_000);
        let p = build_portfolio(&http, &config, &reg).await;
        let b = &p.wallets[0].balances;
        let btc = b.iter().find(|x| x.asset == Asset::Btc).expect("btc");
        assert_eq!(btc.status, BalanceStatus::Disagreement);
        assert!(btc.amount.is_none());
        let usdt = b
            .iter()
            .find(|x| x.asset == Asset::UsdtTrc20)
            .expect("usdt");
        assert_eq!(usdt.status, BalanceStatus::Disagreement);
        assert!(usdt.problems.iter().any(|m| m.contains("29")));
        let total = p
            .totals
            .iter()
            .find(|t| t.asset == Asset::UsdtTrc20)
            .expect("t");
        assert!(!total.complete);
        assert_eq!(total.display, None, "nothing verified must not show as 0");
        let eth_total = p.totals.iter().find(|t| t.asset == Asset::Eth).expect("t");
        assert_eq!(eth_total.display.as_deref(), Some("0.01"));
        assert!(!p.warnings.is_empty());
    }

    #[tokio::test]
    async fn outage_stops_btc_scan() {
        let config = NetworkConfig::embedded().expect("config");
        let reg = registry();
        let http = MockHttp::default(); // nothing answers
        let p = build_portfolio(&http, &config, &reg).await;
        let btc = p.wallets[0]
            .balances
            .iter()
            .find(|x| x.asset == Asset::Btc)
            .expect("btc");
        assert_eq!(btc.status, BalanceStatus::Unavailable);
        // Stopped at the first address instead of hammering all 40.
        let btc_requests = http
            .requested()
            .iter()
            .filter(|r| r.contains("/address/"))
            .count();
        assert_eq!(btc_requests, 2);
    }
}
