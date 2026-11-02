//! Receive addresses (ARCHITECTURE.md §7.2).
//!
//! - Ethereum and TRON reuse the account address.
//! - Bitcoin uses a fresh (never-used) receive address each time: the first
//!   unused address of the account's receive chain, confirmed unused by the
//!   providers. `skip` moves to later unused addresses ("new address").
//!
//! The PC can be compromised, so the address shown here must be compared with
//! the signer's own screen before it is given to anyone (§7.2 step 2).

use chain_btc::{AccountXpub, BtcAddress, Chain, GAP_LIMIT};
use data_sources::fetch::Sources;
use data_sources::{CrossChecked, HttpClient};
use serde::Serialize;

/// "New address" can move at most this far past the first unused address
/// (so a restored wallet still finds the funds within the gap limit).
pub const MAX_SKIP: u32 = GAP_LIMIT - 1;
/// Stop scanning for an unused address after this many indexes.
const MAX_SCAN: u32 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnusedCheck {
    /// Two or more providers agree the address has never been used.
    Verified,
    /// Only one provider answered.
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BtcReceive {
    pub address: String,
    pub index: u32,
    pub first_unused_index: u32,
    pub check: UnusedCheck,
}

/// Find a fresh receive address: the first never-used one, or `skip` unused
/// addresses later. Fails closed: any disagreement or outage is an error,
/// because handing out a used address (or a wrong one) is worse than waiting.
pub async fn fresh_btc_address<H: HttpClient>(
    src: &Sources<'_, H>,
    acct: &AccountXpub,
    skip: u32,
) -> Result<BtcReceive, String> {
    if skip > MAX_SKIP {
        return Err(format!("You can move at most {MAX_SKIP} addresses ahead."));
    }
    let mut first_unused = None;
    let mut seen_unused = 0u32;
    let mut weakest = UnusedCheck::Verified;
    for index in 0..MAX_SCAN {
        let addr: BtcAddress = acct
            .derive_address(Chain::Receive, index)
            .map_err(|e| e.to_string())?;
        let (used, check) = match src.btc_address(&addr).await {
            CrossChecked::Verified { value, .. } => (value.tx_count > 0, UnusedCheck::Verified),
            CrossChecked::Unverified { value, .. } => (value.tx_count > 0, UnusedCheck::Unverified),
            CrossChecked::Disagreement { .. } => {
                return Err(format!(
                    "The providers disagree about receive address #{index}. Try again later."
                ))
            }
            CrossChecked::Unavailable { failed } => {
                let why = failed
                    .first()
                    .map(|(id, e)| format!(" ({id}: {e})"))
                    .unwrap_or_default();
                return Err(format!(
                    "Couldn't check which Bitcoin address is unused{why}. Try again later."
                ));
            }
        };
        if used {
            continue;
        }
        if check == UnusedCheck::Unverified {
            weakest = UnusedCheck::Unverified;
        }
        let first = *first_unused.get_or_insert(index);
        if seen_unused == skip {
            return Ok(BtcReceive {
                address: addr.to_string(),
                index,
                first_unused_index: first,
                check: weakest,
            });
        }
        seen_unused += 1;
    }
    Err("No unused Bitcoin address found in the first 1000.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_sources::fetch::mock::MockHttp;
    use data_sources::NetworkConfig;
    use wallet_types::Network;

    const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    fn esplora(txs: u64) -> String {
        format!(
            r#"{{"chain_stats":{{"funded_txo_sum":0,"spent_txo_sum":0,"tx_count":{txs}}},"mempool_stats":{{"funded_txo_sum":0,"spent_txo_sum":0,"tx_count":0}}}}"#
        )
    }

    /// Receive addresses #0 and #1 used, #2 unused, #3 used, #4+ unused.
    fn mock(config: &NetworkConfig, only_first_provider: bool) -> MockHttp {
        let acct: AccountXpub = ZPUB.parse().expect("zpub");
        let mut http = MockHttp::default();
        for (pi, p) in config.providers_for(Network::Bitcoin).enumerate() {
            if only_first_provider && pi > 0 {
                continue;
            }
            for i in 0..10 {
                let a = acct.derive_address(Chain::Receive, i).expect("derive");
                let used = matches!(i, 0 | 1 | 3);
                http.on_get(
                    &format!("{}/address/{}", p.base_url, a),
                    &esplora(u64::from(used)),
                );
            }
        }
        http
    }

    #[tokio::test(start_paused = true)]
    async fn first_unused_and_skip() {
        let config = NetworkConfig::embedded().expect("config");
        let http = mock(&config, false);
        let src = Sources::new(&http, &config);
        let acct: AccountXpub = ZPUB.parse().expect("zpub");
        let r = fresh_btc_address(&src, &acct, 0).await.expect("fresh");
        assert_eq!(
            (r.index, r.first_unused_index, r.check),
            (2, 2, UnusedCheck::Verified)
        );
        assert_eq!(
            r.address,
            acct.derive_address(Chain::Receive, 2)
                .expect("a")
                .to_string()
        );
        // "New address" skips the used #3.
        let r = fresh_btc_address(&src, &acct, 1).await.expect("skip 1");
        assert_eq!(r.index, 4);
        assert!(fresh_btc_address(&src, &acct, MAX_SKIP + 1).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn single_provider_is_marked_and_outage_fails_closed() {
        let config = NetworkConfig::embedded().expect("config");
        let acct: AccountXpub = ZPUB.parse().expect("zpub");
        let http = mock(&config, true);
        let src = Sources::new(&http, &config);
        let r = fresh_btc_address(&src, &acct, 0).await.expect("fresh");
        assert_eq!(r.check, UnusedCheck::Unverified);

        let empty = MockHttp::default();
        let src = Sources::new(&empty, &config);
        let err = fresh_btc_address(&src, &acct, 0).await.expect_err("outage");
        assert!(err.contains("Couldn't check"));
    }
}
