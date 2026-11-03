//! The ONLY entry points from the UI into Rust (ARCHITECTURE.md §9.1).
//!
//! Rules:
//! - Every argument is parsed into strong types here; the UI is treated as
//!   hostile (it runs in a WebView).
//! - Errors returned to the UI are fixed, safe text.
//! - This app has no secrets and no signing commands. Adding a command means
//!   adding it to `build.rs`, `capabilities/main.json` and the isolation
//!   script, and the test at the bottom of this file enforces the first.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use audit_log::{Entry, Event};
use chain_btc::{BtcAddress, Chain};
use data_sources::fetch::Sources;
use data_sources::{NetworkConfig, ReqwestClient};
use serde::Serialize;
use std::collections::HashSet;
use tauri::State;

use chain_eth::history::EthTx;
use wallet_core::activity::{
    classify_tron_transactions, classify_tron_with_known, known_counterparties, summarize,
    summarize_for, transactions_view, Known, KnownAddress, WalletActivity,
};
use wallet_core::address_book::{
    network_time, usable, AddressBook, NewBookEntry, OwnAddress, Revoked, Usable, WAITING_SECS,
};
use wallet_core::btc_activity::{
    classify_btc, known_counterparties_btc, load_btc_history, MAX_PAGES_PER_ADDRESS,
};
use wallet_core::eth_activity::{
    classify_eth_transactions, classify_eth_transfers, known_counterparties_eth, KnownEth,
};
use wallet_core::{
    build_portfolio, from_signer_export, BtcWatch, NewWalletInput, Portfolio, ProgressLevel,
    ProgressSink, Registry, WatchWallet,
};
use wallet_types::{Network, Tier};
use zeroize::Zeroizing;

use crate::session::{AuthStatus, SessionState, SetupInfo};

pub struct AppState {
    /// Login state and the encrypted wallet list (session.rs).
    pub session: Arc<SessionState>,
    pub config: NetworkConfig,
    pub http: ReqwestClient,
    pub progress: ProgressState,
    /// Last check problems written to the audit log (to avoid repeats).
    pub last_check_problems: Mutex<Option<String>>,
}

/// A whole refresh is stopped after this long; whatever hasn't answered by
/// then is reported as a timeout instead of the app waiting forever.
pub const REFRESH_TIME_LIMIT: Duration = Duration::from_secs(120);
/// Progress lines kept for the UI (oldest dropped first).
const MAX_PROGRESS_LINES: usize = 400;

#[derive(Clone, Serialize)]
pub struct ProgressLine {
    at_ms: u64,
    level: ProgressLevel,
    text: String,
}

#[derive(Default)]
struct ProgressData {
    running: bool,
    started: Option<Instant>,
    finished_ms: Option<u64>,
    checks: u32,
    lines: VecDeque<ProgressLine>,
}

/// Live log of the current (or last) portfolio refresh.
#[derive(Default)]
pub struct ProgressState(Mutex<ProgressData>);

fn elapsed_ms(started: Option<Instant>) -> u64 {
    started
        .map(|s| u64::try_from(s.elapsed().as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

impl ProgressSink for ProgressState {
    fn step(&self, level: ProgressLevel, text: String) {
        if let Ok(mut d) = self.0.lock() {
            if level != ProgressLevel::Info {
                d.checks += 1;
            }
            let at_ms = elapsed_ms(d.started);
            d.lines.push_back(ProgressLine { at_ms, level, text });
            while d.lines.len() > MAX_PROGRESS_LINES {
                d.lines.pop_front();
            }
        }
    }
}

impl ProgressState {
    /// Start a new refresh; fails if one is already running.
    fn begin(&self) -> Result<(), String> {
        let mut d = self.0.lock().map_err(|_| LOCK_ERR.to_owned())?;
        if d.running {
            return Err("A refresh is already running. Wait for it to finish.".into());
        }
        *d = ProgressData {
            running: true,
            started: Some(Instant::now()),
            ..ProgressData::default()
        };
        Ok(())
    }

    fn end(&self) {
        if let Ok(mut d) = self.0.lock() {
            d.running = false;
            d.finished_ms = Some(elapsed_ms(d.started));
        }
    }
}

#[derive(Serialize)]
pub struct ProgressView {
    running: bool,
    elapsed_ms: u64,
    checks: u32,
    lines: Vec<ProgressLine>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BtcView {
    /// The xpub itself isn't sent to the UI (privacy, §8.1); only its fingerprint.
    AccountXpub {
        fingerprint: String,
    },
    Address {
        address: String,
    },
}

#[derive(Serialize)]
pub struct WalletView {
    id: String,
    label: String,
    tier: Tier,
    tier_name: &'static str,
    btc: Option<BtcView>,
    eth: Option<String>,
    tron: Option<String>,
    /// Set when the wallet was imported from the signer tablet.
    signer_fingerprint: Option<String>,
}

impl From<&WatchWallet> for WalletView {
    fn from(w: &WatchWallet) -> Self {
        Self {
            id: w.id.to_string(),
            label: w.label.clone(),
            tier: w.tier,
            tier_name: w.tier.display_name(),
            btc: w.btc.as_ref().map(|b| match b {
                BtcWatch::AccountXpub(x) => BtcView::AccountXpub {
                    fingerprint: x.0.fingerprint(),
                },
                BtcWatch::Address(a) => BtcView::Address {
                    address: BtcAddress::to_string(a),
                },
            }),
            eth: w.eth.map(|a| a.to_checksum()),
            tron: w.tron.map(|a| a.to_base58()),
            signer_fingerprint: w.signer_fingerprint.clone(),
        }
    }
}

const LOCK_ERR: &str = "Internal error. Restart the app.";

fn views(r: &Registry) -> Vec<WalletView> {
    r.wallets.iter().map(WalletView::from).collect()
}

/// Read the wallet list (requires login; counts as activity).
fn read_registry(state: &AppState) -> Result<Registry, String> {
    state.session.with_registry(true, false, |r| Ok(r.clone()))
}

#[tauri::command]
pub fn list_wallets(state: State<'_, AppState>) -> Result<Vec<WalletView>, String> {
    state.session.with_registry(true, false, |r| Ok(views(r)))
}

#[tauri::command]
pub fn add_wallet(
    state: State<'_, AppState>,
    input: NewWalletInput,
) -> Result<Vec<WalletView>, String> {
    let wallet = input.validate().map_err(|e| e.to_string())?;
    let id = wallet.id.to_string();
    let out = state.session.with_registry(true, true, |r| {
        r.add(wallet).map_err(|e| e.to_string())?;
        Ok(views(r))
    })?;
    state
        .session
        .audit()
        .record(Event::WalletAdded, &format!("{id} (typed by hand)"));
    Ok(out)
}

/// What the PC read from the tablet's export QR, shown for the user to
/// compare with the tablet screen before adding.
#[derive(Debug, Serialize)]
pub struct SignerWalletPreview {
    id: String,
    label: String,
    tier_name: &'static str,
    fingerprint: String,
    /// Bitcoin receive address #0, derived on this PC from the account key.
    btc_first_address: String,
    eth: String,
    tron: String,
    /// Why it can't be added (e.g. already watched), if anything.
    problem: Option<String>,
}

fn preview_of(w: &WatchWallet, problem: Option<String>) -> Result<SignerWalletPreview, String> {
    let first = match &w.btc {
        Some(BtcWatch::AccountXpub(x)) => {
            x.0.derive_address(Chain::Receive, 0)
                .map(|a| a.to_string())
                .map_err(|e| e.to_string())?
        }
        _ => return Err("The export has no Bitcoin account key.".into()),
    };
    Ok(SignerWalletPreview {
        id: w.id.to_string(),
        label: w.label.clone(),
        tier_name: w.tier.display_name(),
        fingerprint: w.signer_fingerprint.clone().unwrap_or_default(),
        btc_first_address: first,
        eth: w.eth.map(|a| a.to_checksum()).unwrap_or_default(),
        tron: w.tron.map(|a| a.to_base58()).unwrap_or_default(),
        problem,
    })
}

/// Step 1 of "Add from tablet": check the scanned (or pasted) export and
/// show what it contains. Nothing is saved.
#[tauri::command]
pub fn preview_signer_wallet(
    state: State<'_, AppState>,
    text: String,
) -> Result<SignerWalletPreview, String> {
    let wallet = from_signer_export(&text).map_err(|e| e.to_string())?;
    let problem = state.session.with_registry(true, false, |r| {
        let mut trial = r.clone();
        Ok(trial.add(wallet.clone()).err().map(|e| e.to_string()))
    })?;
    preview_of(&wallet, problem)
}

/// Step 2: the user compared the preview with the tablet and confirmed. The
/// export is checked again from scratch (nothing is trusted from step 1).
#[tauri::command]
pub fn add_signer_wallet(
    state: State<'_, AppState>,
    text: String,
) -> Result<Vec<WalletView>, String> {
    let wallet = from_signer_export(&text).map_err(|e| e.to_string())?;
    let detail = format!(
        "{} (from the signer tablet, fingerprint {})",
        wallet.id,
        wallet.signer_fingerprint.as_deref().unwrap_or("?")
    );
    let out = state.session.with_registry(true, true, |r| {
        r.add(wallet).map_err(|e| e.to_string())?;
        Ok(views(r))
    })?;
    state.session.audit().record(Event::WalletAdded, &detail);
    Ok(out)
}

#[tauri::command]
pub fn remove_wallet(state: State<'_, AppState>, id: String) -> Result<Vec<WalletView>, String> {
    if id.len() > 32 {
        return Err("Unknown wallet.".into());
    }
    let out = state.session.with_registry(true, true, |r| {
        r.remove(&id).map_err(|e| e.to_string())?;
        Ok(views(r))
    })?;
    state.session.audit().record(Event::WalletRemoved, &id);
    Ok(out)
}

#[tauri::command]
pub async fn get_portfolio(state: State<'_, AppState>) -> Result<Portfolio, String> {
    let registry = read_registry(&state)?;
    state.progress.begin()?;
    let result = tokio::time::timeout(
        REFRESH_TIME_LIMIT,
        build_portfolio(&state.http, &state.config, &registry, &state.progress),
    )
    .await;
    match &result {
        Ok(_) => state.progress.step(ProgressLevel::Info, "Refresh finished.".into()),
        Err(_) => state.progress.step(
            ProgressLevel::Error,
            format!(
                "Stopped after {} seconds: some providers didn't answer in time. See the lines above for which one.",
                REFRESH_TIME_LIMIT.as_secs()
            ),
        ),
    }
    state.progress.end();
    result.map_err(|_| {
        format!(
            "The refresh took longer than {} seconds and was stopped. The progress log shows which provider was slow.",
            REFRESH_TIME_LIMIT.as_secs()
        )
    })
}

/// History requests are a single call; give up after this long.
const ACTIVITY_TIME_LIMIT: Duration = Duration::from_secs(30);

/// Bitcoin history scans every used address one by one, so it gets longer.
const BTC_ACTIVITY_TIME_LIMIT: Duration = Duration::from_secs(150);

#[tauri::command]
pub async fn get_activity(
    state: State<'_, AppState>,
    id: String,
    network: Network,
) -> Result<WalletActivity, String> {
    if id.len() > 32 {
        return Err("Unknown wallet.".into());
    }
    let registry = read_registry(&state)?;
    let wallet = registry
        .wallets
        .iter()
        .find(|w| w.id.as_str() == id)
        .ok_or_else(|| "Unknown wallet.".to_owned())?;
    match network {
        Network::Tron => tron_activity(&state, &registry, wallet).await,
        Network::Ethereum => eth_activity(&state, &registry, wallet).await,
        Network::Bitcoin => btc_activity(&state, &registry, wallet).await,
    }
}

/// Address book entries of `network`, for the look-alike check in history.
fn book_known(state: &AppState, network: Network) -> Vec<Known> {
    state
        .session
        .with_book(false, |_, b| {
            Ok(b.entries
                .iter()
                .filter(|e| e.network == network)
                .map(|e| {
                    (
                        e.address.clone(),
                        format!("address book entry \"{}\"", e.label),
                    )
                })
                .collect())
        })
        .unwrap_or_default()
}

fn timeout_msg() -> String {
    "The history provider didn't answer in time.".to_owned()
}

async fn tron_activity(
    state: &AppState,
    registry: &Registry,
    wallet: &WatchWallet,
) -> Result<WalletActivity, String> {
    let me = wallet
        .tron
        .ok_or_else(|| "This wallet has no TRON address.".to_owned())?;
    // Every other TRON address you watch, for the look-alike check.
    let own: Vec<KnownAddress> = registry
        .wallets
        .iter()
        .filter_map(|w| {
            w.tron.map(|address| KnownAddress {
                address,
                label: w.label.clone(),
            })
        })
        .filter(|k| k.address != me)
        .collect();
    let sources = Sources::new(&state.http, &state.config);
    // Transfers (token movements) and the account's own transactions, both at once.
    let (transfers, transactions) = futures_util::future::join(
        tokio::time::timeout(ACTIVITY_TIME_LIMIT, sources.tron_history(&me)),
        tokio::time::timeout(ACTIVITY_TIME_LIMIT, sources.tron_transactions(&me)),
    )
    .await;
    let transfers = transfers
        .map_err(|_| timeout_msg())?
        .map_err(|e| format!("Couldn't load transfers: {e}"))?;
    let transactions = transactions
        .map_err(|_| timeout_msg())
        .and_then(|r| r.map_err(|e| format!("Couldn't load transactions: {e}")));

    let pinned = &state.config.usdt_trc20;
    let txs: &[_] = transactions
        .as_ref()
        .map(|t| t.txs.as_slice())
        .unwrap_or(&[]);
    // One look-alike reference list built from both histories.
    let mut known = known_counterparties(&me, &own, pinned, &transfers.events, txs);
    known.extend(book_known(state, Network::Tron));
    let entries = classify_tron_with_known(&me, pinned, &transfers.events, &known);
    let mut page = summarize(
        wallet.id.clone(),
        &me,
        transfers.provider,
        entries,
        transfers.unreadable,
    );
    page.attach_transactions(transactions.map(|t| {
        let entries = classify_tron_transactions(&me, pinned, &t.txs, &known);
        transactions_view(t.provider, entries, t.unreadable)
    }));
    Ok(page)
}

async fn eth_activity(
    state: &AppState,
    registry: &Registry,
    wallet: &WatchWallet,
) -> Result<WalletActivity, String> {
    let me = wallet
        .eth
        .ok_or_else(|| "This wallet has no Ethereum address.".to_owned())?;
    let own: Vec<KnownEth> = registry
        .wallets
        .iter()
        .filter_map(|w| {
            w.eth.map(|address| KnownEth {
                address,
                label: w.label.clone(),
            })
        })
        .collect();
    let sources = Sources::new(&state.http, &state.config);
    let (transfers, transactions) = futures_util::future::join(
        tokio::time::timeout(ACTIVITY_TIME_LIMIT, sources.eth_token_transfers(&me)),
        tokio::time::timeout(ACTIVITY_TIME_LIMIT, sources.eth_transactions(&me)),
    )
    .await;
    let transfers = transfers
        .map_err(|_| timeout_msg())?
        .map_err(|e| format!("Couldn't load token transfers: {e}"))?;
    let transactions = transactions
        .map_err(|_| timeout_msg())
        .and_then(|r| r.map_err(|e| format!("Couldn't load transactions: {e}")));

    let usdt = &state.config.usdt_erc20;
    let txs: &[EthTx] = transactions
        .as_ref()
        .map(|t| t.value.items.as_slice())
        .unwrap_or(&[]);
    // "Spent by someone else" needs the full list of what this address sent
    // for the period the transfers cover.
    let my_txids: Option<HashSet<String>> = transactions.as_ref().ok().and_then(|t| {
        let oldest_tx = t.value.items.iter().map(|x| x.time_ms).min().unwrap_or(0);
        let covered = !t.value.more || transfers.value.items.iter().all(|x| x.time_ms >= oldest_tx);
        covered.then(|| {
            t.value
                .items
                .iter()
                .filter(|x| x.from == me)
                .map(|x| x.txid.to_lowercase())
                .collect()
        })
    });
    let mut known = known_counterparties_eth(&me, &own, usdt, &transfers.value.items, txs);
    known.extend(book_known(state, Network::Ethereum));
    let entries =
        classify_eth_transfers(&me, usdt, &transfers.value.items, &known, my_txids.as_ref());
    let mut page = summarize_for(
        wallet.id.clone(),
        Network::Ethereum,
        me.to_checksum(),
        transfers.provider.clone(),
        entries,
        transfers.value.unreadable,
    );
    if transfers.value.more {
        page.notes.push(
            "Showing the latest token transfers only; older ones can be seen on a block explorer."
                .into(),
        );
    }
    page.attach_transactions(transactions.map(|t| {
        let entries = classify_eth_transactions(&me, usdt, &t.value.items, &known);
        transactions_view(t.provider, entries, t.value.unreadable)
    }));
    Ok(page)
}

async fn btc_activity(
    state: &AppState,
    registry: &Registry,
    wallet: &WatchWallet,
) -> Result<WalletActivity, String> {
    let watch = wallet
        .btc
        .as_ref()
        .ok_or_else(|| "This wallet has no Bitcoin key or address.".to_owned())?;
    // Single Bitcoin addresses of your other wallets, for the look-alike check.
    let mut own_other: Vec<Known> = registry
        .wallets
        .iter()
        .filter(|w| w.id != wallet.id)
        .filter_map(|w| match &w.btc {
            Some(BtcWatch::Address(a)) => Some((
                BtcAddress::to_string(a),
                format!("your wallet \"{}\"", w.label),
            )),
            _ => None,
        })
        .collect();
    own_other.extend(book_known(state, Network::Bitcoin));
    let sources = Sources::new(&state.http, &state.config);
    let h = tokio::time::timeout(BTC_ACTIVITY_TIME_LIMIT, load_btc_history(&sources, watch))
        .await
        .map_err(|_| timeout_msg())?
        .map_err(|e| format!("Couldn't load Bitcoin history: {e}"))?;
    let known = known_counterparties_btc(&h, &own_other);
    let entries = classify_btc(&h, &known);
    let address = match watch {
        BtcWatch::AccountXpub(x) => format!(
            "Account key {} · {} address(es) checked, {} used for receiving",
            x.0.fingerprint(),
            h.mine.len(),
            h.used_receive.len()
        ),
        BtcWatch::Address(a) => BtcAddress::to_string(a),
    };
    let source = h.providers.iter().cloned().collect::<Vec<_>>().join(", ");
    let mut page = summarize_for(
        wallet.id.clone(),
        Network::Bitcoin,
        address,
        source,
        entries,
        h.unreadable,
    );
    if let Some(why) = &h.incomplete {
        page.notes
            .push(format!("History is incomplete. {why}. Try again later."));
    }
    if h.truncated > 0 {
        page.notes.push(format!(
            "{} address(es) have more than {} transactions; the oldest were left out.",
            h.truncated,
            MAX_PAGES_PER_ADDRESS * chain_btc::esplora::TXS_PAGE
        ));
    }
    Ok(page)
}

// ---------------------------------------------------------------------------
// Address book (§7.1)
// ---------------------------------------------------------------------------

/// Your own addresses, for the look-alike and "own wallet" checks. For a
/// Bitcoin account key, the first receive and change addresses.
fn own_addresses(registry: &Registry) -> Vec<OwnAddress> {
    const BTC_OWN_CHECK: u32 = 50;
    let mut out = Vec::new();
    for w in &registry.wallets {
        let label = w.label.clone();
        if let Some(a) = w.eth {
            out.push(OwnAddress {
                network: Network::Ethereum,
                address: a.to_checksum(),
                label: label.clone(),
            });
        }
        if let Some(a) = w.tron {
            out.push(OwnAddress {
                network: Network::Tron,
                address: a.to_base58(),
                label: label.clone(),
            });
        }
        match &w.btc {
            Some(BtcWatch::Address(a)) => out.push(OwnAddress {
                network: Network::Bitcoin,
                address: BtcAddress::to_string(a),
                label: label.clone(),
            }),
            Some(BtcWatch::AccountXpub(x)) => {
                for chain in [Chain::Receive, Chain::Change] {
                    for i in 0..BTC_OWN_CHECK {
                        if let Ok(a) = x.0.derive_address(chain, i) {
                            out.push(OwnAddress {
                                network: Network::Bitcoin,
                                address: a.to_string(),
                                label: label.clone(),
                            });
                        }
                    }
                }
            }
            None => {}
        }
    }
    out
}

/// Network time from the latest Ethereum block times (≥ 2 providers agreeing).
async fn current_network_time(state: &AppState) -> Option<u64> {
    let sources = Sources::new(&state.http, &state.config);
    let times = tokio::time::timeout(Duration::from_secs(20), sources.eth_block_times())
        .await
        .unwrap_or_default();
    network_time(&times)
}

#[derive(Serialize)]
pub struct BookEntryView {
    id: String,
    label: String,
    network: Network,
    network_name: &'static str,
    address: String,
    verified_by: &'static str,
    note: String,
    tiers: Vec<&'static str>,
    added_at: u64,
    usable: Usable,
    /// When this same address was removed before, if ever.
    previously_removed_at: Option<u64>,
}

#[derive(Serialize)]
pub struct OwnWalletView {
    label: String,
    network_name: &'static str,
    address: String,
}

#[derive(Serialize)]
pub struct AddressBookView {
    entries: Vec<BookEntryView>,
    own: Vec<OwnWalletView>,
    revoked: Vec<Revoked>,
    /// `None` when network time couldn't be confirmed (waiting periods then
    /// count as not over).
    network_time: Option<u64>,
    waiting_hours: u64,
}

fn book_view(registry: &Registry, book: &AddressBook, now: Option<u64>) -> AddressBookView {
    let mut own = Vec::new();
    for w in &registry.wallets {
        if let Some(a) = w.eth {
            own.push(OwnWalletView {
                label: w.label.clone(),
                network_name: Network::Ethereum.display_name(),
                address: a.to_checksum(),
            });
        }
        if let Some(a) = w.tron {
            own.push(OwnWalletView {
                label: w.label.clone(),
                network_name: Network::Tron.display_name(),
                address: a.to_base58(),
            });
        }
        match &w.btc {
            Some(BtcWatch::Address(a)) => own.push(OwnWalletView {
                label: w.label.clone(),
                network_name: Network::Bitcoin.display_name(),
                address: BtcAddress::to_string(a),
            }),
            Some(BtcWatch::AccountXpub(_)) => own.push(OwnWalletView {
                label: w.label.clone(),
                network_name: Network::Bitcoin.display_name(),
                address: "(account key: use a fresh address from the Receive page)".into(),
            }),
            None => {}
        }
    }
    AddressBookView {
        entries: book
            .entries
            .iter()
            .map(|e| BookEntryView {
                id: e.id.clone(),
                label: e.label.clone(),
                network: e.network,
                network_name: e.network.display_name(),
                address: e.address.clone(),
                verified_by: e.verified_by.display_name(),
                note: e.note.clone(),
                tiers: e.tiers.iter().map(|t| t.display_name()).collect(),
                added_at: e.added_at,
                usable: usable(e, now),
                previously_removed_at: book
                    .revoked
                    .iter()
                    .rev()
                    .find(|r| {
                        r.network == e.network
                            && r.address == e.address
                            && r.removed_at <= e.added_at
                    })
                    .map(|r| r.removed_at),
            })
            .collect(),
        own,
        revoked: book.revoked.clone(),
        network_time: now,
        waiting_hours: WAITING_SECS / 3600,
    }
}

#[tauri::command]
pub async fn get_address_book(state: State<'_, AppState>) -> Result<AddressBookView, String> {
    // Login check first, so a locked app doesn't ask the network.
    state.session.with_book(false, |_, _| Ok(()))?;
    let now = current_network_time(&state).await;
    state
        .session
        .with_book(false, |r, b| Ok(book_view(r, b, now)))
}

#[tauri::command]
pub async fn add_address_book_entry(
    state: State<'_, AppState>,
    entry: NewBookEntry,
) -> Result<AddressBookView, String> {
    state.session.with_book(false, |_, _| Ok(()))?;
    let now = current_network_time(&state).await.ok_or_else(|| {
        "Couldn't confirm the current time from at least two network sources, so the waiting period can't start. Check the internet connection and try again.".to_owned()
    })?;
    let (view, detail) = state.session.with_book(true, |r, b| {
        let e = b
            .add(&entry, &own_addresses(r), now)
            .map_err(|e| e.to_string())?;
        let detail = format!(
            "{} ({}), may be paid from: {}",
            e.id,
            e.network.display_name(),
            e.tiers
                .iter()
                .map(|t| t.display_name())
                .collect::<Vec<_>>()
                .join(", ")
        );
        Ok((book_view(r, b, Some(now)), detail))
    })?;
    state.session.audit().record(Event::AddressAdded, &detail);
    Ok(view)
}

#[tauri::command]
pub async fn remove_address_book_entry(
    state: State<'_, AppState>,
    id: String,
) -> Result<AddressBookView, String> {
    if id.len() > 16 {
        return Err("Unknown entry.".into());
    }
    state.session.with_book(false, |_, _| Ok(()))?;
    let now_net = current_network_time(&state).await;
    let pc_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (view, detail) = state.session.with_book(true, |r, b| {
        let e = b
            .remove(&id, now_net.unwrap_or(pc_now))
            .map_err(|e| e.to_string())?;
        Ok((
            book_view(r, b, now_net),
            format!("{} ({})", e.id, e.network.display_name()),
        ))
    })?;
    state.session.audit().record(Event::AddressRemoved, &detail);
    Ok(view)
}

#[tauri::command]
pub async fn rename_address_book_entry(
    state: State<'_, AppState>,
    id: String,
    label: String,
) -> Result<AddressBookView, String> {
    if id.len() > 16 {
        return Err("Unknown entry.".into());
    }
    state.session.with_book(false, |_, _| Ok(()))?;
    let now = current_network_time(&state).await;
    let view = state.session.with_book(true, |r, b| {
        b.rename(&id, &label).map_err(|e| e.to_string())?;
        Ok(book_view(r, b, now))
    })?;
    state
        .session
        .audit()
        .record(Event::AddressRenamed, &format!("{id} (label changed)"));
    Ok(view)
}

#[tauri::command]
pub fn get_progress(state: State<'_, AppState>) -> Result<ProgressView, String> {
    // Requires login, but polling doesn't count as activity.
    state.session.with_registry(false, false, |_| Ok(()))?;
    let d = state.progress.0.lock().map_err(|_| LOCK_ERR.to_owned())?;
    Ok(ProgressView {
        running: d.running,
        elapsed_ms: if d.running {
            elapsed_ms(d.started)
        } else {
            d.finished_ms.unwrap_or(0)
        },
        checks: d.checks,
        lines: d.lines.iter().cloned().collect(),
    })
}

#[derive(Serialize)]
pub struct ProviderView {
    id: String,
    network: &'static str,
    operator: String,
    base_url: String,
}

#[derive(Serialize)]
pub struct AppInfo {
    version: &'static str,
    config_version: u32,
    config_sha256: String,
    usdt_erc20: String,
    usdt_trc20: String,
    providers: Vec<ProviderView>,
    independence_warnings: Vec<String>,
}

#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> AppInfo {
    let c = &state.config;
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        config_version: c.version,
        config_sha256: c.sha256.clone(),
        usdt_erc20: c.usdt_erc20.to_checksum(),
        usdt_trc20: c.usdt_trc20.to_base58(),
        providers: c
            .providers
            .iter()
            .map(|p| ProviderView {
                id: p.id.clone(),
                network: p.network.display_name(),
                operator: p.operator.clone(),
                base_url: p.base_url.clone(),
            })
            .collect(),
        independence_warnings: c
            .networks_lacking_independence()
            .into_iter()
            .map(|n| {
                format!(
                    "{} has fewer than 2 independent providers",
                    n.display_name()
                )
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Receive (§7.2)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ReceiveView {
    network: &'static str,
    /// Assets that can be sent to this address, each stating its network.
    assets: Vec<&'static str>,
    address: String,
    qr: crate::qr::Qr,
    /// Bitcoin account wallets: which receive address this is.
    btc_index: Option<u32>,
    /// What to compare on the signer's screen.
    signer_hint: String,
    warnings: Vec<String>,
}

#[tauri::command]
pub async fn get_receive(
    state: State<'_, AppState>,
    id: String,
    network: String,
    skip: u32,
) -> Result<ReceiveView, String> {
    if id.len() > 32 {
        return Err("Unknown wallet.".into());
    }
    let registry = read_registry(&state)?;
    let wallet = registry
        .wallets
        .iter()
        .find(|w| w.id.as_str() == id)
        .ok_or_else(|| "Unknown wallet.".to_owned())?;
    let mut warnings = Vec::new();
    match wallet.tier {
        Tier::Vault => warnings.push(
            "Vault: only receive from your own wallets. Never give this address to anyone else.".to_owned(),
        ),
        Tier::WatchOnly => warnings.push(
            "Watch-only wallet: its keys are not on your signer tablet. Only use this address if you control that wallet elsewhere.".to_owned(),
        ),
        _ => {}
    }
    let (net, assets, address, btc_index, signer_hint) = match network.as_str() {
        "bitcoin" => match &wallet.btc {
            Some(BtcWatch::AccountXpub(acct)) => {
                let sources = Sources::new(&state.http, &state.config);
                let r = tokio::time::timeout(
                    ACTIVITY_TIME_LIMIT,
                    wallet_core::receive::fresh_btc_address(&sources, &acct.0, skip),
                )
                .await
                .map_err(|_| "The providers didn't answer within 30 seconds.".to_owned())??;
                if r.check == wallet_core::receive::UnusedCheck::Unverified {
                    warnings.push(
                        "Only one provider confirmed this address is unused. It's still your address, but it may have been used before.".to_owned(),
                    );
                }
                let hint = format!(
                    "On the signer, open this wallet's Bitcoin receive address #{} (path …/0/{}) and compare it.",
                    r.index, r.index
                );
                (
                    "Bitcoin",
                    vec![wallet_types::Asset::Btc.label()],
                    r.address,
                    Some(r.index),
                    hint,
                )
            }
            Some(BtcWatch::Address(a)) => {
                warnings.push(
                    "This wallet is watched by a single Bitcoin address, so it can't give a fresh address each time.".to_owned(),
                );
                (
                    "Bitcoin",
                    vec![wallet_types::Asset::Btc.label()],
                    a.to_string(),
                    None,
                    "On the signer, open this wallet's Bitcoin address and compare it.".to_owned(),
                )
            }
            None => return Err("This wallet has no Bitcoin address.".into()),
        },
        "ethereum" => {
            let a = wallet
                .eth
                .ok_or_else(|| "This wallet has no Ethereum address.".to_owned())?;
            (
                "Ethereum",
                vec![
                    wallet_types::Asset::UsdtErc20.label(),
                    wallet_types::Asset::Eth.label(),
                ],
                a.to_checksum(),
                None,
                "On the signer, open this wallet's Ethereum address and compare it.".to_owned(),
            )
        }
        "tron" => {
            let a = wallet
                .tron
                .ok_or_else(|| "This wallet has no TRON address.".to_owned())?;
            (
                "TRON",
                vec![
                    wallet_types::Asset::UsdtTrc20.label(),
                    wallet_types::Asset::Trx.label(),
                ],
                a.to_base58(),
                None,
                "On the signer, open this wallet's TRON address and compare it.".to_owned(),
            )
        }
        _ => return Err("Unknown network.".into()),
    };
    Ok(ReceiveView {
        network: net,
        assets,
        qr: crate::qr::matrix(&address)?,
        address,
        btc_index,
        signer_hint,
        warnings,
    })
}

// ---------------------------------------------------------------------------
// Login (§9.8)
// ---------------------------------------------------------------------------

fn blocking_err(_: tauri::Error) -> String {
    LOCK_ERR.to_owned()
}

#[tauri::command]
pub fn auth_status(state: State<'_, AppState>) -> Result<AuthStatus, String> {
    state.session.status()
}

#[tauri::command]
pub fn setup_begin(state: State<'_, AppState>) -> Result<SetupInfo, String> {
    state.session.setup_begin()
}

/// Password hashing (Argon2id) is deliberately slow, so it runs off the UI thread.
#[tauri::command]
pub async fn setup_finish(
    state: State<'_, AppState>,
    password: String,
    code: String,
) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let session = Arc::clone(&state.session);
    tauri::async_runtime::spawn_blocking(move || session.setup_finish(&password, &code))
        .await
        .map_err(blocking_err)?
}

#[tauri::command]
pub async fn unlock(
    state: State<'_, AppState>,
    password: String,
    code: String,
) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let session = Arc::clone(&state.session);
    tauri::async_runtime::spawn_blocking(move || session.unlock(&password, &code))
        .await
        .map_err(blocking_err)?
}

#[tauri::command]
pub fn lock(state: State<'_, AppState>, idle: bool) {
    state.session.lock(idle);
}

// ---------------------------------------------------------------------------
// Start-up checks (§9.8)
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn startup_checks(state: State<'_, AppState>) -> Result<Vec<sys_checks::Check>, String> {
    let local = tauri::async_runtime::spawn_blocking(sys_checks::run_local_checks);
    let sources = Sources::new(&state.http, &state.config);
    let block_times = tokio::time::timeout(Duration::from_secs(20), sources.eth_block_times())
        .await
        .unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut checks = local.await.map_err(blocking_err)?;
    checks.push(sys_checks::evaluate_clock(now, &block_times));
    checks.push(sys_checks::Check {
        id: "config",
        title: "Network config",
        status: sys_checks::Status::Pass,
        detail: format!(
            "SHA-256 {}. Compare with the value recorded for the reviewed release.",
            state.config.sha256
        ),
        blocks_sends: false,
    });
    let audit = state.session.audit().status();
    checks.push(sys_checks::Check {
        id: "audit_log",
        title: "Audit log",
        status: if audit.intact {
            sys_checks::Status::Pass
        } else {
            sys_checks::Status::Fail
        },
        detail: match &audit.problem {
            None => format!(
                "Intact: {} entries, each linked to the one before. Head {}.",
                audit.count, audit.head_short
            ),
            Some(p) => p.clone(),
        },
        blocks_sends: true,
    });
    record_check_problems(&state, &checks);
    Ok(checks)
}

/// Write failed or warning checks to the audit log, but only when the list of
/// problems changed since the last time (the checks run often).
fn record_check_problems(state: &AppState, checks: &[sys_checks::Check]) {
    let problems: Vec<String> = checks
        .iter()
        .filter(|c| {
            matches!(
                c.status,
                sys_checks::Status::Fail | sys_checks::Status::Warn
            )
        })
        .map(|c| {
            let word = if matches!(c.status, sys_checks::Status::Fail) {
                "failed"
            } else {
                "warning"
            };
            format!("{} {word}", c.title)
        })
        .collect();
    let summary = problems.join("; ");
    let Ok(mut last) = state.last_check_problems.lock() else {
        return;
    };
    if last.as_deref() == Some(summary.as_str()) {
        return;
    }
    if !summary.is_empty() {
        state.session.audit().record(Event::ChecksProblem, &summary);
    }
    *last = Some(summary);
}

#[derive(Serialize)]
pub struct AuditView {
    intact: bool,
    count: u64,
    head_short: String,
    problem: Option<String>,
    /// Newest first.
    entries: Vec<Entry>,
}

/// Audit log page: the newest entries and whether the chain is intact.
#[tauri::command]
pub fn get_audit_log(state: State<'_, AppState>) -> Result<AuditView, String> {
    // Login required (same gate as the wallet list).
    state.session.with_registry(true, false, |_| Ok(()))?;
    let audit = state.session.audit();
    let (entries, read_problem) = match audit.recent(AUDIT_PAGE) {
        Ok(e) => (e, None),
        Err(e) => (Vec::new(), Some(e)),
    };
    let st = audit.status();
    let problem = read_problem.or(st.problem);
    Ok(AuditView {
        intact: problem.is_none(),
        count: st.count,
        head_short: st.head_short,
        problem,
        entries,
    })
}

/// Entries shown on the Log page.
const AUDIT_PAGE: usize = 300;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_preview_matches_the_tablet() {
        // Export made by the tablet code from the public test phrase.
        let text = r#"WWX1:{"id":"test-01","label":"Test spending","tier":"spending","fingerprint":"73c5da0a","btc_zpub":"zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs","eth":"0x9858EfFD232B4033E47d90003D41EC34EcaEda94","tron":"TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"}#55971832"#;
        let w = from_signer_export(text).expect("import");
        let p = preview_of(&w, None).expect("preview");
        // The tablet's "verify" screen shows the same address #0 (BIP-84 vector).
        assert_eq!(
            p.btc_first_address,
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(p.fingerprint, "73c5da0a");
        assert_eq!(p.tier_name, Tier::Spending.display_name());
        let view = WalletView::from(&w);
        assert_eq!(view.signer_fingerprint.as_deref(), Some("73c5da0a"));
    }

    /// CI guard (§9.1): every `#[tauri::command]` must be on the reviewed list
    /// in build.rs, in the capability file and in the isolation script.
    #[test]
    fn command_list_is_reviewed() {
        let src = include_str!("commands.rs");
        let marker = concat!("#[tauri", "::command]");
        let mut in_code: Vec<String> = Vec::new();
        let mut lines = src.lines();
        while let Some(line) = lines.next() {
            if line.trim() == marker {
                let sig = lines.next().unwrap_or_default();
                let name = sig
                    .split("fn ")
                    .nth(1)
                    .and_then(|s| s.split('(').next())
                    .unwrap_or_default()
                    .to_owned();
                in_code.push(name);
            }
        }
        in_code.sort();

        let build = include_str!("../build.rs");
        let caps = include_str!("../capabilities/main.json");
        let iso = include_str!("../../isolation/index.js");
        for name in &in_code {
            assert!(
                build.contains(&format!("\"{name}\"")),
                "{name} missing from build.rs COMMANDS"
            );
            let perm = format!("allow-{}", name.replace('_', "-"));
            assert!(
                caps.contains(&perm),
                "{perm} missing from capabilities/main.json"
            );
            assert!(
                iso.contains(&format!("\"{name}\"")),
                "{name} missing from isolation allowlist"
            );
        }
        assert_eq!(
            in_code.len(),
            21,
            "command count changed: review the new command, then update this test"
        );
        let lib = include_str!("lib.rs");
        for name in &in_code {
            assert!(
                lib.contains(&format!("commands::{name}")),
                "{name} not registered in lib.rs"
            );
        }
    }
}
