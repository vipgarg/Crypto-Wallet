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
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chain_btc::BtcAddress;
use data_sources::{NetworkConfig, ReqwestClient};
use serde::Serialize;
use tauri::State;
use wallet_core::{
    build_portfolio, BtcWatch, NewWalletInput, Portfolio, ProgressLevel, ProgressSink, Registry,
    WatchWallet,
};
use wallet_types::Tier;

pub struct AppState {
    /// `Err` if the wallet file on disk is corrupted: the app then refuses to
    /// change it (never silently replaced, §9.7).
    pub registry: Mutex<Result<Registry, String>>,
    pub registry_path: PathBuf,
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
        }
    }
}

const LOCK_ERR: &str = "Internal error. Restart the app.";

fn views(r: &Registry) -> Vec<WalletView> {
    r.wallets.iter().map(WalletView::from).collect()
}

fn with_registry<T>(
    state: &AppState,
    f: impl FnOnce(&mut Registry) -> Result<T, String>,
) -> Result<T, String> {
    let mut guard = state.registry.lock().map_err(|_| LOCK_ERR.to_owned())?;
    match guard.as_mut() {
        Ok(reg) => f(reg),
        Err(e) => Err(e.clone()),
    }
}

#[tauri::command]
pub fn list_wallets(state: State<'_, AppState>) -> Result<Vec<WalletView>, String> {
    with_registry(&state, |r| Ok(views(r)))
}

#[tauri::command]
pub fn add_wallet(
    state: State<'_, AppState>,
    input: NewWalletInput,
) -> Result<Vec<WalletView>, String> {
    let wallet = input.validate().map_err(|e| e.to_string())?;
    with_registry(&state, |r| {
        let mut next = r.clone();
        next.add(wallet).map_err(|e| e.to_string())?;
        next.save(&state.registry_path).map_err(|e| e.to_string())?;
        *r = next;
        Ok(views(r))
    })
}

#[tauri::command]
pub fn remove_wallet(state: State<'_, AppState>, id: String) -> Result<Vec<WalletView>, String> {
    if id.len() > 32 {
        return Err("Unknown wallet.".into());
    }
    with_registry(&state, |r| {
        let mut next = r.clone();
        next.remove(&id).map_err(|e| e.to_string())?;
        next.save(&state.registry_path).map_err(|e| e.to_string())?;
        *r = next;
        Ok(views(r))
    })
}

#[tauri::command]
pub async fn get_portfolio(state: State<'_, AppState>) -> Result<Portfolio, String> {
    let registry = with_registry(&state, |r| Ok(r.clone()))?;
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

#[tauri::command]
pub fn get_progress(state: State<'_, AppState>) -> Result<ProgressView, String> {
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

#[cfg(test)]
mod tests {
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
            6,
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
