//! Per-fact queries, asked of every provider for the network and cross-checked.

use chain_btc::esplora::{self, AddressStats};
use chain_btc::BtcAddress;
use chain_eth::{rpc, EthAddress};
use chain_tron::{api, TronAddress};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use serde::Serialize;
use thiserror::Error;
use wallet_types::Network;

use crate::config::{NetworkConfig, ProviderConfig, ProviderKind};
use crate::cross_check::{cross_check, CrossChecked};
use crate::http::{HttpClient, HttpError};

#[derive(Debug, Error)]
pub enum FetchError {
    #[error(transparent)]
    Http(#[from] HttpError),
    #[error("could not parse provider answer: {0}")]
    Parse(String),
    #[error("skipped: failed {0} times in a row during this refresh")]
    Skipped(u32),
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

/// How long one provider took for one question, and whether it answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderTiming {
    pub provider: String,
    pub millis: u64,
    pub ok: bool,
    /// Not asked at all, because it kept failing during this refresh.
    pub skipped: bool,
    /// How many times the provider said "too many requests" before answering.
    pub rate_limited: u8,
}

/// A cross-checked answer plus per-provider timings (shown in the UI's
/// progress log so a slow or failing provider is visible).
#[derive(Debug, Clone)]
pub struct Timed<T> {
    pub result: CrossChecked<T>,
    pub timings: Vec<ProviderTiming>,
}

/// After this many failures in a row, a provider is skipped for the rest of
/// the refresh, so one dead provider can't make every check wait for a timeout.
pub const BREAKER_THRESHOLD: u32 = 3;

/// Per-refresh failure counter for each provider.
#[derive(Default)]
struct Breaker(Mutex<HashMap<String, u32>>);

impl Breaker {
    fn is_open(&self, id: &str) -> bool {
        self.0
            .lock()
            .map(|m| m.get(id).copied().unwrap_or(0) >= BREAKER_THRESHOLD)
            .unwrap_or(false)
    }

    fn record(&self, id: &str, ok: bool) {
        if let Ok(mut m) = self.0.lock() {
            let n = m.entry(id.to_owned()).or_insert(0);
            *n = if ok { 0 } else { n.saturating_add(1) };
        }
    }
}

/// Retries after HTTP 429 before giving up on that request.
pub const MAX_RATE_LIMIT_RETRIES: u8 = 3;
const DEFAULT_RATE_LIMIT_WAIT: Duration = Duration::from_secs(2);
const MAX_RATE_LIMIT_WAIT: Duration = Duration::from_secs(20);
const MAX_INTERVAL: Duration = Duration::from_secs(2);

/// Minimum gap between two requests to the same provider. Bitcoin scans send
/// many requests to Esplora providers, so they get the larger gap.
fn base_interval(kind: ProviderKind) -> Duration {
    match kind {
        ProviderKind::Esplora => Duration::from_millis(100),
        ProviderKind::EthJsonRpc | ProviderKind::TronHttp => Duration::from_millis(50),
    }
}

struct PaceState {
    interval: Duration,
    next: tokio::time::Instant,
}

/// Spaces out requests to each provider, and slows down for the rest of the
/// refresh when a provider rate-limits us.
#[derive(Default)]
struct Pacer(Mutex<HashMap<String, PaceState>>);

impl Pacer {
    async fn wait(&self, p: &ProviderConfig) {
        let now = tokio::time::Instant::now();
        let at = match self.0.lock() {
            Ok(mut m) => {
                let s = m.entry(p.id.clone()).or_insert(PaceState {
                    interval: base_interval(p.kind),
                    next: now,
                });
                let at = s.next.max(now);
                s.next = at + s.interval;
                at
            }
            Err(_) => now,
        };
        tokio::time::sleep_until(at).await;
    }

    fn slow_down(&self, id: &str, wait: Duration) {
        if let Ok(mut m) = self.0.lock() {
            if let Some(s) = m.get_mut(id) {
                s.interval = (s.interval * 2).min(MAX_INTERVAL);
                let resume = tokio::time::Instant::now() + wait;
                s.next = s.next.max(resume);
            }
        }
    }
}

/// Cross-checked queries across every provider of the relevant network.
/// Create one per refresh: the failure counters start empty each time.
pub struct Sources<'a, H: HttpClient> {
    pub http: &'a H,
    pub config: &'a NetworkConfig,
    breaker: Breaker,
    pacer: Pacer,
}

impl<'a, H: HttpClient> Sources<'a, H> {
    pub fn new(http: &'a H, config: &'a NetworkConfig) -> Self {
        Self {
            http,
            config,
            breaker: Breaker::default(),
            pacer: Pacer::default(),
        }
    }

    /// Ask every provider of `network` **at the same time** and cross-check
    /// the answers. Requests to one provider are spaced out (pacing); a
    /// rate-limited request waits and is retried. Providers that keep failing
    /// are skipped (and counted as failed, so the result can't become
    /// "verified" without them).
    async fn ask_all<'s, T, F, Fut>(&'s self, network: Network, ask: F) -> Timed<T>
    where
        T: PartialEq + Clone,
        F: Fn(&'s ProviderConfig) -> Fut,
        Fut: Future<Output = Result<T, FetchError>>,
    {
        let ask = &ask;
        let futures = self.config.providers_for(network).map(|p| {
            async move {
                let start = Instant::now();
                let mut rate_limited = 0u8;
                let mut skipped = false;
                let r = loop {
                    // Checked before waiting (a skipped provider must not slow
                    // the refresh down) and again after waiting our turn (so
                    // queued requests aren't sent once it has been skipped).
                    if !self.breaker.is_open(&p.id) {
                        self.pacer.wait(p).await;
                    }
                    if self.breaker.is_open(&p.id) {
                        skipped = true;
                        break Err(FetchError::Skipped(BREAKER_THRESHOLD));
                    }
                    {
                        let r = ask(p).await;
                        match &r {
                            Err(FetchError::Http(HttpError::RateLimited { retry_after_secs }))
                                if rate_limited < MAX_RATE_LIMIT_RETRIES =>
                            {
                                rate_limited += 1;
                                let wait = retry_after_secs
                                    .map(Duration::from_secs)
                                    .unwrap_or(DEFAULT_RATE_LIMIT_WAIT)
                                    .min(MAX_RATE_LIMIT_WAIT);
                                self.pacer.slow_down(&p.id, wait);
                            }
                            _ => break r,
                        }
                    }
                };
                if !skipped {
                    self.breaker.record(&p.id, r.is_ok());
                }
                (p.id.clone(), start.elapsed(), r, skipped, rate_limited)
            }
        });
        let answers = join_all(futures).await;
        let timings = answers
            .iter()
            .map(|(id, elapsed, r, skipped, rate_limited)| ProviderTiming {
                provider: id.clone(),
                millis: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                ok: r.is_ok(),
                skipped: *skipped,
                rate_limited: *rate_limited,
            })
            .collect();
        let result = cross_check(
            answers
                .into_iter()
                .map(|(id, _, r, _, _)| (id, r))
                .collect(),
        );
        Timed { result, timings }
    }

    pub async fn btc_address_timed(&self, addr: &BtcAddress) -> Timed<ConfirmedBtcFacts> {
        self.ask_all(Network::Bitcoin, |p| async move {
            btc_address_stats(self.http, p, addr)
                .await
                .map(ConfirmedBtcFacts::from)
        })
        .await
    }

    pub async fn eth_timed(&self, addr: &EthAddress) -> Timed<u128> {
        self.ask_all(Network::Ethereum, |p| eth_balance(self.http, p, addr))
            .await
    }

    pub async fn usdt_erc20_timed(&self, holder: &EthAddress) -> Timed<u128> {
        let token = &self.config.usdt_erc20;
        self.ask_all(Network::Ethereum, |p| {
            erc20_balance(self.http, p, token, holder)
        })
        .await
    }

    pub async fn trx_timed(&self, addr: &TronAddress) -> Timed<u128> {
        self.ask_all(Network::Tron, |p| trx_balance(self.http, p, addr))
            .await
    }

    pub async fn usdt_trc20_timed(&self, holder: &TronAddress) -> Timed<u128> {
        let token = &self.config.usdt_trc20;
        self.ask_all(Network::Tron, |p| {
            trc20_balance(self.http, p, token, holder)
        })
        .await
    }

    pub async fn btc_address(&self, addr: &BtcAddress) -> CrossChecked<ConfirmedBtcFacts> {
        self.btc_address_timed(addr).await.result
    }

    pub async fn eth(&self, addr: &EthAddress) -> CrossChecked<u128> {
        self.eth_timed(addr).await.result
    }

    pub async fn usdt_erc20(&self, holder: &EthAddress) -> CrossChecked<u128> {
        self.usdt_erc20_timed(holder).await.result
    }

    pub async fn trx(&self, addr: &TronAddress) -> CrossChecked<u128> {
        self.trx_timed(addr).await.result
    }

    pub async fn usdt_trc20(&self, holder: &TronAddress) -> CrossChecked<u128> {
        self.usdt_trc20_timed(holder).await.result
    }
}

/// Recorded-response HTTP client for tests in this and other crates.
/// Not compiled into release builds.
#[cfg(any(test, feature = "mock"))]
pub mod mock {
    use std::collections::{HashMap, VecDeque};
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
        /// Answers returned in order for a GET URL, before falling back to `get`.
        pub get_seq: Mutex<HashMap<String, VecDeque<Result<String, HttpError>>>>,
    }

    impl MockHttp {
        pub fn on_get(&mut self, url: &str, body: &str) {
            self.get.insert(url.to_owned(), Ok(body.to_owned()));
        }
        pub fn on_post(&mut self, url: &str, req: &Value, resp: Value) {
            self.post
                .insert((url.to_owned(), req.to_string()), Ok(resp));
        }
        pub fn on_get_seq(&mut self, url: &str, answers: Vec<Result<String, HttpError>>) {
            if let Ok(mut m) = self.get_seq.lock() {
                m.insert(url.to_owned(), answers.into());
            }
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
            if let Ok(mut m) = self.get_seq.lock() {
                if let Some(next) = m.get_mut(url).and_then(VecDeque::pop_front) {
                    return next;
                }
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

    #[tokio::test(start_paused = true)]
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
        let s = Sources::new(&http, &config);
        assert_eq!(s.usdt_trc20(&holder).await.value(), Some(&25_000_000));
        assert!(s.usdt_trc20(&holder).await.is_verified());
    }

    #[tokio::test(start_paused = true)]
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
        let s = Sources::new(&http, &config);
        assert!(matches!(
            s.usdt_erc20(&holder).await,
            CrossChecked::Disagreement { .. }
        ));
    }

    #[tokio::test(start_paused = true)]
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
        let s = Sources::new(&http, &config);
        let r = s.btc_address(&addr).await;
        assert!(r.is_verified(), "{r:?}");
        assert_eq!(r.value().map(|f| f.confirmed_sats), Some(5000));
        // Only individual addresses are requested, never an xpub.
        assert!(http.requested().iter().all(|u| !u.contains("pub")));
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limit_is_waited_out_and_retried() {
        let config = NetworkConfig::embedded().expect("config");
        let addr: BtcAddress = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
            .parse()
            .expect("addr");
        let ok = r#"{"chain_stats":{"funded_txo_sum":7,"spent_txo_sum":0,"tx_count":1},"mempool_stats":{"funded_txo_sum":0,"spent_txo_sum":0,"tx_count":0}}"#;
        let mut http = MockHttp::default();
        let ps: Vec<_> = config.providers_for(Network::Bitcoin).collect();
        let limited = || {
            Err(HttpError::RateLimited {
                retry_after_secs: Some(3),
            })
        };
        http.on_get_seq(
            &format!("{}/address/{}", ps[0].base_url, addr),
            vec![limited(), limited()],
        );
        http.on_get(&format!("{}/address/{}", ps[0].base_url, addr), ok);
        http.on_get(&format!("{}/address/{}", ps[1].base_url, addr), ok);
        let s = Sources::new(&http, &config);
        let started = tokio::time::Instant::now();
        let t = s.btc_address_timed(&addr).await;
        assert!(t.result.is_verified(), "{:?}", t.result);
        let first = t
            .timings
            .iter()
            .find(|x| x.provider == ps[0].id)
            .expect("timing");
        assert_eq!(first.rate_limited, 2);
        // It honoured Retry-After (3 s, twice) instead of hammering the provider.
        assert!(started.elapsed() >= Duration::from_secs(6));
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limit_gives_up_after_max_retries() {
        let config = NetworkConfig::embedded().expect("config");
        let addr: BtcAddress = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
            .parse()
            .expect("addr");
        let mut http = MockHttp::default();
        let ps: Vec<_> = config.providers_for(Network::Bitcoin).collect();
        let limited: Vec<_> = (0..10)
            .map(|_| {
                Err(HttpError::RateLimited {
                    retry_after_secs: None,
                })
            })
            .collect();
        http.on_get_seq(&format!("{}/address/{}", ps[0].base_url, addr), limited);
        let s = Sources::new(&http, &config);
        let t = s.btc_address_timed(&addr).await;
        let first = t
            .timings
            .iter()
            .find(|x| x.provider == ps[0].id)
            .expect("timing");
        assert_eq!(first.rate_limited, MAX_RATE_LIMIT_RETRIES);
        assert!(!first.ok);
    }

    #[tokio::test(start_paused = true)]
    async fn failing_provider_is_skipped_but_never_counted_as_agreeing() {
        let config = NetworkConfig::embedded().expect("config");
        let addr: TronAddress = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".parse().expect("addr");
        let mut http = MockHttp::default();
        let ps: Vec<_> = config.providers_for(Network::Tron).collect();
        // Only the first provider answers; the second always fails.
        http.on_post(
            &format!("{}{}", ps[0].base_url, api::GET_ACCOUNT_PATH),
            &api::get_account(&addr),
            json!({"balance": 7}),
        );
        let s = Sources::new(&http, &config);
        for _ in 0..BREAKER_THRESHOLD {
            let t = s.trx_timed(&addr).await;
            assert!(t.timings.iter().all(|x| !x.skipped));
        }
        let before = http.requested().len();
        let started = tokio::time::Instant::now();
        let t = s.trx_timed(&addr).await;
        // A skipped provider costs no waiting time.
        assert!(started.elapsed() < Duration::from_millis(100));
        // The dead provider wasn't asked again...
        assert_eq!(http.requested().len(), before + 1);
        assert!(t
            .timings
            .iter()
            .any(|x| x.skipped && x.provider == ps[1].id));
        // ...and the answer is still only "unverified", never "verified".
        assert!(matches!(t.result, CrossChecked::Unverified { .. }));
        // A new refresh (new Sources) tries it again.
        let fresh = Sources::new(&http, &config);
        assert!(fresh
            .trx_timed(&addr)
            .await
            .timings
            .iter()
            .all(|x| !x.skipped));
    }

    #[tokio::test(start_paused = true)]
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
        let s = Sources::new(&http, &config);
        assert!(matches!(
            s.trx(&addr).await,
            CrossChecked::Unverified { value: 7, .. }
        ));
    }
}
