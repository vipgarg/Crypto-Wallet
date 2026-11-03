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

use chain_btc::{BtcAddress, Chain};
use data_sources::fetch::Sources;
use data_sources::{NetworkConfig, ReqwestClient};
use serde::Serialize;
use tauri::State;
use wallet_core::activity::{
    classify_tron_transactions, classify_tron_with_known, known_counterparties, summarize,
    transactions_view, KnownAddress, WalletActivity,
};
use wallet_core::{
    build_portfolio, from_signer_export, BtcWatch, NewWalletInput, Portfolio, ProgressLevel,
    ProgressSink, Registry, WatchWallet,
};
use wallet_types::Tier;
use zeroize::Zeroizing;

use crate::session::{AuthStatus, SessionState, SetupInfo};

pub struct AppState {
    /// Login state and the encrypted wallet list (session.rs).
    pub session: Arc<SessionState>,
    pub config: NetworkConfig,
    pub http: ReqwestClient,
    pub progress: ProgressState,
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
    state.session.with_registry(true, true, |r| {
        r.add(wallet).map_err(|e| e.to_string())?;
        Ok(views(r))
    })
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
    state.session.with_registry(true, true, |r| {
        r.add(wallet).map_err(|e| e.to_string())?;
        Ok(views(r))
    })
}

#[tauri::command]
pub fn remove_wallet(state: State<'_, AppState>, id: String) -> Result<Vec<WalletView>, String> {
    if id.len() > 32 {
        return Err("Unknown wallet.".into());
    }
    state.session.with_registry(true, true, |r| {
        r.remove(&id).map_err(|e| e.to_string())?;
        Ok(views(r))
    })
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

#[tauri::command]
pub async fn get_activity(
    state: State<'_, AppState>,
    id: String,
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
    let me = wallet.tron.ok_or_else(|| {
        "Activity is available for TRON addresses for now. Ethereum and Bitcoin are next."
            .to_owned()
    })?;
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
    let timeout_msg = || "The history provider didn't answer within 30 seconds.".to_owned();
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
    let known = known_counterparties(&me, &own, pinned, &transfers.events, txs);
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
pub fn lock(state: State<'_, AppState>) {
    state.session.lock();
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
    Ok(checks)
}

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
            16,
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
