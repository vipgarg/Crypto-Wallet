//! Bitcoin **signet** (test network) data for Phase 2 testing: balances,
//! coins, previous transactions and broadcasting. Same Esplora API as
//! mainnet, on separate providers from the config's `signet_providers`.
//!
//! Balances are cross-checked like on mainnet. Coin lists and previous
//! transactions come from the first provider that answers; that's safe
//! because the tablet checks every coin against its full previous
//! transaction (whose id is its hash), and a wrong coin list can only make
//! the payment fail, not redirect it.

use chain_btc::esplora::{self, AddressStats};
use futures_util::future::join_all;
use serde::{Deserialize, Serialize};

use crate::config::{NetworkConfig, SignetProvider};
use crate::cross_check::{cross_check, CrossChecked};
use crate::fetch::{ConfirmedBtcFacts, FetchError, FromOne};
use crate::http::HttpClient;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignetUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub confirmed: bool,
}

#[derive(Deserialize)]
struct RawUtxo {
    txid: String,
    vout: u32,
    value: u64,
    status: RawStatus,
}

#[derive(Deserialize)]
struct RawStatus {
    confirmed: bool,
}

fn parse_err(e: impl std::fmt::Display) -> FetchError {
    FetchError::Parse(e.to_string())
}

fn hex_txid(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub struct Signet<'a, H: HttpClient> {
    http: &'a H,
    providers: &'a [SignetProvider],
}

impl<'a, H: HttpClient> Signet<'a, H> {
    pub fn new(http: &'a H, config: &'a NetworkConfig) -> Self {
        Self {
            http,
            providers: &config.signet_providers,
        }
    }

    async fn stats_from(&self, p: &SignetProvider, addr: &str) -> Result<AddressStats, FetchError> {
        let body = self
            .http
            .get_text(&format!("{}/address/{addr}", p.base_url))
            .await?;
        esplora::parse_address(&body).map_err(parse_err)
    }

    /// Confirmed balance and transaction count of one address, asked of
    /// every signet provider and cross-checked.
    pub async fn address_facts(&self, addr: &str) -> CrossChecked<ConfirmedBtcFacts> {
        let answers = join_all(self.providers.iter().map(|p| async move {
            (
                p.id.clone(),
                self.stats_from(p, addr).await.map(ConfirmedBtcFacts::from),
            )
        }))
        .await;
        cross_check(answers)
    }

    async fn first<T, F, Fut>(&self, ask: F) -> Result<FromOne<T>, String>
    where
        F: Fn(&'a SignetProvider) -> Fut,
        Fut: std::future::Future<Output = Result<T, FetchError>>,
    {
        let mut errors = Vec::new();
        for p in self.providers {
            match ask(p).await {
                Ok(value) => {
                    return Ok(FromOne {
                        provider: p.id.clone(),
                        value,
                    })
                }
                Err(e) => errors.push(format!("{}: {e}", p.id)),
            }
        }
        if errors.is_empty() {
            errors.push("no signet provider is configured".into());
        }
        Err(errors.join("; "))
    }

    /// Unspent coins of one address.
    pub async fn utxos(&self, addr: &str) -> Result<FromOne<Vec<SignetUtxo>>, String> {
        self.first(|p| async move {
            let body = self
                .http
                .get_text(&format!("{}/address/{addr}/utxo", p.base_url))
                .await?;
            let raw: Vec<RawUtxo> = serde_json::from_str(&body).map_err(parse_err)?;
            raw.into_iter()
                .map(|u| {
                    if hex_txid(&u.txid) {
                        Ok(SignetUtxo {
                            txid: u.txid.to_lowercase(),
                            vout: u.vout,
                            value: u.value,
                            confirmed: u.status.confirmed,
                        })
                    } else {
                        Err(FetchError::Parse("bad txid in coin list".into()))
                    }
                })
                .collect()
        })
        .await
    }

    /// Raw transaction (hex). The caller must check that it hashes to `txid`.
    pub async fn tx_hex(&self, txid: &str) -> Result<FromOne<String>, String> {
        if !hex_txid(txid) {
            return Err("invalid transaction id".into());
        }
        self.first(|p| async move {
            let body = self
                .http
                .get_text(&format!("{}/tx/{txid}/hex", p.base_url))
                .await?;
            let hex = body.trim().to_owned();
            if hex.is_empty() || hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(FetchError::Parse("not a raw transaction".into()));
            }
            Ok(hex)
        })
        .await
    }

    /// Send a signed transaction to **every** signet provider. Returns each
    /// provider's answer (the txid on success).
    pub async fn broadcast(&self, raw_hex: &str) -> Vec<(String, Result<String, String>)> {
        join_all(self.providers.iter().map(|p| async move {
            let r = self
                .http
                .post_text(&format!("{}/tx", p.base_url), raw_hex)
                .await
                .map_err(|e| e.to_string())
                .and_then(|t| {
                    let t = t.trim().to_lowercase();
                    if hex_txid(&t) {
                        Ok(t)
                    } else {
                        Err(format!(
                            "unexpected answer: {}",
                            t.chars().take(120).collect::<String>()
                        ))
                    }
                });
            (p.id.clone(), r)
        }))
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::mock::MockHttp;

    #[tokio::test]
    async fn signet_calls() {
        let config = NetworkConfig::embedded().expect("config");
        let ps = &config.signet_providers;
        let addr = "tb1qexample";
        let txid = "ab".repeat(32);
        let mut http = MockHttp::default();
        http.on_get(
            &format!("{}/address/{addr}/utxo", ps[1].base_url),
            &format!(
                r#"[{{"txid":"{txid}","vout":1,"value":5000,"status":{{"confirmed":true}}}}]"#
            ),
        );
        http.on_get(&format!("{}/tx/{txid}/hex", ps[0].base_url), "0200\n");
        for p in ps {
            http.on_get(
                &format!("{}/address/{addr}", p.base_url),
                r#"{"chain_stats":{"funded_txo_sum":5000,"spent_txo_sum":0,"tx_count":1},"mempool_stats":{"funded_txo_sum":0,"spent_txo_sum":0,"tx_count":0}}"#,
            );
        }
        http.on_post_text(
            &format!("{}/tx", ps[0].base_url),
            "0200",
            Ok(format!("{txid}\n")),
        );
        let s = Signet::new(&http, &config);

        let u = s.utxos(addr).await.expect("utxos");
        assert_eq!(u.provider, ps[1].id, "falls back to the second provider");
        assert_eq!(u.value[0].value, 5000);
        assert_eq!(s.tx_hex(&txid).await.expect("hex").value, "0200");
        assert!(s.tx_hex("nope").await.is_err());
        assert!(s.address_facts(addr).await.is_verified());

        let b = s.broadcast("0200").await;
        assert_eq!(b.len(), ps.len());
        assert_eq!(b[0].1.as_deref(), Ok(txid.as_str()));
        assert!(b[1].1.is_err());
    }
}
