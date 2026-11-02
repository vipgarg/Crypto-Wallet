//! Per-fact queries, asked of every provider for the network and cross-checked.

use chain_btc::esplora::{self, AddressStats};
use chain_btc::BtcAddress;
use chain_eth::{rpc, EthAddress};
use chain_tron::{api, TronAddress};
use thiserror::Error;
use wallet_types::Network;

use crate::config::{NetworkConfig, ProviderConfig};
use crate::cross_check::{cross_check, CrossChecked};
use crate::http::{HttpClient, HttpError};

#[derive(Debug, Error)]
pub enum FetchError {
    #[error(transparent)]
    Http(#[from] HttpError),
    #[error("could not parse provider answer: {0}")]
    Parse(String),
}

fn parse_err(e: impl std::fmt::Display) -> FetchError {
    FetchError::Parse(e.to_string())
}

pub async fn btc_address_stats<H: HttpClient>(
    http: &H,
    p: &ProviderConfig,
    addr: &BtcAddress,
) -> Result<AddressStats, FetchError> {
    let body = http
        .get_text(&format!("{}/address/{}", p.base_url, addr))
        .await?;
    esplora::parse_address(&body).map_err(parse_err)
}

pub async fn eth_balance<H: HttpClient>(
    http: &H,
    p: &ProviderConfig,
    addr: &EthAddress,
) -> Result<u128, FetchError> {
    let resp = http
        .post_json(&p.base_url, &rpc::eth_get_balance(addr))
        .await?;
    rpc::parse_quantity(&resp).map_err(parse_err)
}

pub async fn erc20_balance<H: HttpClient>(
    http: &H,
    p: &ProviderConfig,
    token: &EthAddress,
    holder: &EthAddress,
) -> Result<u128, FetchError> {
    let resp = http
        .post_json(&p.base_url, &rpc::erc20_balance_of(token, holder))
        .await?;
    rpc::parse_uint256_word(&resp).map_err(parse_err)
}

pub async fn trx_balance<H: HttpClient>(
    http: &H,
    p: &ProviderConfig,
    addr: &TronAddress,
) -> Result<u128, FetchError> {
    let url = format!("{}{}", p.base_url, api::GET_ACCOUNT_PATH);
    let resp = http.post_json(&url, &api::get_account(addr)).await?;
    api::parse_trx_balance(&resp).map_err(parse_err)
}

pub async fn trc20_balance<H: HttpClient>(
    http: &H,
    p: &ProviderConfig,
    token: &TronAddress,
    holder: &TronAddress,
) -> Result<u128, FetchError> {
    let url = format!("{}{}", p.base_url, api::TRIGGER_CONSTANT_PATH);
    let resp = http
        .post_json(&url, &api::trc20_balance_of(token, holder))
        .await?;
    api::parse_trc20_balance(&resp).map_err(parse_err)
}

/// The facts compared between providers for one Bitcoin address. Mempool
/// numbers differ legitimately between nodes, so they aren't compared (and
/// unconfirmed funds are never counted in a balance).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedBtcFacts {
    pub confirmed_sats: u64,
    pub tx_count: u64,
}

impl From<AddressStats> for ConfirmedBtcFacts {
    fn from(s: AddressStats) -> Self {
        Self {
            confirmed_sats: s.confirmed_sats,
            tx_count: s.tx_count,
        }
    }
}

/// Cross-checked queries across every provider of the relevant network.
pub struct Sources<'a, H: HttpClient> {
    pub http: &'a H,
    pub config: &'a NetworkConfig,
}

impl<H: HttpClient> Sources<'_, H> {
    pub async fn btc_address(&self, addr: &BtcAddress) -> CrossChecked<ConfirmedBtcFacts> {
        let mut results = Vec::new();
        for p in self.config.providers_for(Network::Bitcoin) {
            let r = btc_address_stats(self.http, p, addr)
                .await
                .map(ConfirmedBtcFacts::from);
            results.push((p.id.clone(), r));
        }
        cross_check(results)
    }

    pub async fn eth(&self, addr: &EthAddress) -> CrossChecked<u128> {
        let mut results = Vec::new();
        for p in self.config.providers_for(Network::Ethereum) {
            results.push((p.id.clone(), eth_balance(self.http, p, addr).await));
        }
        cross_check(results)
    }

    pub async fn usdt_erc20(&self, holder: &EthAddress) -> CrossChecked<u128> {
        let mut results = Vec::new();
        for p in self.config.providers_for(Network::Ethereum) {
            results.push((
                p.id.clone(),
                erc20_balance(self.http, p, &self.config.usdt_erc20, holder).await,
            ));
        }
        cross_check(results)
    }

    pub async fn trx(&self, addr: &TronAddress) -> CrossChecked<u128> {
        let mut results = Vec::new();
        for p in self.config.providers_for(Network::Tron) {
            results.push((p.id.clone(), trx_balance(self.http, p, addr).await));
        }
        cross_check(results)
    }

    pub async fn usdt_trc20(&self, holder: &TronAddress) -> CrossChecked<u128> {
        let mut results = Vec::new();
        for p in self.config.providers_for(Network::Tron) {
            results.push((
                p.id.clone(),
                trc20_balance(self.http, p, &self.config.usdt_trc20, holder).await,
            ));
        }
        cross_check(results)
    }
}

/// Recorded-response HTTP client for tests in this and other crates.
/// Not compiled into release builds.
#[cfg(any(test, feature = "mock"))]
pub mod mock {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use serde_json::Value;

    use crate::http::{HttpClient, HttpError};

    /// Answers by URL (GET) or by URL + request body (POST). Unknown requests
    /// fail with a network error, like an unreachable provider.
    #[derive(Default)]
    pub struct MockHttp {
        pub get: HashMap<String, Result<String, HttpError>>,
        pub post: HashMap<(String, String), Result<Value, HttpError>>,
        pub log: Mutex<Vec<String>>,
    }

    impl MockHttp {
        pub fn on_get(&mut self, url: &str, body: &str) {
            self.get.insert(url.to_owned(), Ok(body.to_owned()));
        }
        pub fn on_post(&mut self, url: &str, req: &Value, resp: Value) {
            self.post
                .insert((url.to_owned(), req.to_string()), Ok(resp));
        }
        pub fn requested(&self) -> Vec<String> {
            self.log.lock().map(|l| l.clone()).unwrap_or_default()
        }
    }

    impl HttpClient for MockHttp {
        async fn get_text(&self, url: &str) -> Result<String, HttpError> {
            if let Ok(mut l) = self.log.lock() {
                l.push(format!("GET {url}"));
            }
            self.get
                .get(url)
                .cloned()
                .unwrap_or(Err(HttpError::Network("unreachable".into())))
        }
        async fn post_json(&self, url: &str, body: &Value) -> Result<Value, HttpError> {
            if let Ok(mut l) = self.log.lock() {
                l.push(format!("POST {url} {body}"));
            }
            self.post
                .get(&(url.to_owned(), body.to_string()))
                .cloned()
                .unwrap_or(Err(HttpError::Network("unreachable".into())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockHttp;
    use super::*;
    use serde_json::json;

    fn word(n: u128) -> String {
        format!("{:064x}", n)
    }

    #[tokio::test]
    async fn usdt_trc20_two_providers_agree() {
        let config = NetworkConfig::embedded().expect("config");
        let holder: TronAddress = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".parse().expect("addr");
        let mut http = MockHttp::default();
        let req = api::trc20_balance_of(&config.usdt_trc20, &holder);
        for p in config.providers_for(Network::Tron) {
            http.on_post(
                &format!("{}{}", p.base_url, api::TRIGGER_CONSTANT_PATH),
                &req,
                json!({"result": {"result": true}, "constant_result": [word(25_000_000)]}),
            );
        }
        let s = Sources {
            http: &http,
            config: &config,
        };
        assert_eq!(s.usdt_trc20(&holder).await.value(), Some(&25_000_000));
        assert!(s.usdt_trc20(&holder).await.is_verified());
    }

    #[tokio::test]
    async fn usdt_erc20_providers_disagree() {
        let config = NetworkConfig::embedded().expect("config");
        let holder: EthAddress = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
            .parse()
            .expect("addr");
        let mut http = MockHttp::default();
        let req = rpc::erc20_balance_of(&config.usdt_erc20, &holder);
        for (n, p) in (1u128..).zip(config.providers_for(Network::Ethereum)) {
            http.on_post(
                &p.base_url,
                &req,
                json!({"jsonrpc": "2.0", "id": 1, "result": format!("0x{}", word(n))}),
            );
        }
        let s = Sources {
            http: &http,
            config: &config,
        };
        assert!(matches!(
            s.usdt_erc20(&holder).await,
            CrossChecked::Disagreement { .. }
        ));
    }

    #[tokio::test]
    async fn btc_ignores_mempool_differences_but_not_confirmed() {
        let config = NetworkConfig::embedded().expect("config");
        let addr: BtcAddress = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
            .parse()
            .expect("addr");
        let body = |mempool_tx: u32| {
            format!(
                r#"{{"chain_stats":{{"funded_txo_sum":5000,"spent_txo_sum":0,"tx_count":1}},"mempool_stats":{{"funded_txo_sum":0,"spent_txo_sum":0,"tx_count":{mempool_tx}}}}}"#
            )
        };
        let mut http = MockHttp::default();
        let ps: Vec<_> = config.providers_for(Network::Bitcoin).collect();
        http.on_get(&format!("{}/address/{}", ps[0].base_url, addr), &body(0));
        http.on_get(&format!("{}/address/{}", ps[1].base_url, addr), &body(1));
        let s = Sources {
            http: &http,
            config: &config,
        };
        let r = s.btc_address(&addr).await;
        assert!(r.is_verified(), "{r:?}");
        assert_eq!(r.value().map(|f| f.confirmed_sats), Some(5000));
        // Only individual addresses are requested, never an xpub.
        assert!(http.requested().iter().all(|u| !u.contains("pub")));
    }

    #[tokio::test]
    async fn one_provider_down_is_unverified() {
        let config = NetworkConfig::embedded().expect("config");
        let addr: TronAddress = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".parse().expect("addr");
        let mut http = MockHttp::default();
        let first = config.providers_for(Network::Tron).next().expect("p");
        http.on_post(
            &format!("{}{}", first.base_url, api::GET_ACCOUNT_PATH),
            &api::get_account(&addr),
            json!({"balance": 7}),
        );
        let s = Sources {
            http: &http,
            config: &config,
        };
        assert!(matches!(
            s.trx(&addr).await,
            CrossChecked::Unverified { value: 7, .. }
        ));
    }
}
