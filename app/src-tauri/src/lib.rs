//! Watch-only wallet desktop app. Holds no seeds or private keys.

pub mod commands;
pub mod eth_test;
pub mod qr;
pub mod real_send;
pub mod session;
pub mod testnet;
pub mod tron_test;

use std::sync::Arc;

use data_sources::{NetworkConfig, ReqwestClient};
use tauri::{Manager, Url, WebviewUrl, WebviewWindowBuilder};

use commands::AppState;
use session::{Paths, SessionState};

/// Only the app's own pages may load in the window (§9.1): navigation to any
/// other URL is blocked.
fn allowed_navigation(url: &Url) -> bool {
    let app_origin = matches!(url.scheme(), "tauri") || url.host_str() == Some("tauri.localhost");
    let dev_server = cfg!(debug_assertions) && url.as_str().starts_with("http://127.0.0.1:5173/");
    app_origin || dev_server
}

pub fn run() {
    let config =
        NetworkConfig::embedded().expect("embedded network config is invalid; refusing to start");
    let http = ReqwestClient::new().expect("HTTP client");

    tauri::Builder::default()
        .setup(move |app| {
            let dir = app.path().app_data_dir()?;
            let session = SessionState::load(Paths {
                store: dir.join("store.v1.json"),
                legacy_registry: dir.join("wallets.json"),
                lockout: dir.join("lockout.json"),
                audit: dir.join("audit.jsonl"),
            });
            session.audit().record(
                audit_log::Event::AppStarted,
                &format!(
                    "version {} · network config {}",
                    env!("CARGO_PKG_VERSION"),
                    config.sha256.chars().take(12).collect::<String>()
                ),
            );
            app.manage(AppState {
                session: Arc::new(session),
                config,
                http,
                progress: commands::ProgressState::default(),
                last_check_problems: std::sync::Mutex::new(None),
                pending_send: std::sync::Mutex::new(None),
                pending_tron: std::sync::Mutex::new(None),
                pending_eth: std::sync::Mutex::new(None),
            });

            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("Watch-Only Wallet")
                .inner_size(1100.0, 760.0)
                .min_inner_size(420.0, 500.0)
                .on_navigation(allowed_navigation)
                .build()?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_wallets,
            commands::add_wallet,
            commands::remove_wallet,
            commands::get_portfolio,
            commands::app_info,
            commands::get_progress,
            commands::get_activity,
            commands::auth_status,
            commands::setup_begin,
            commands::setup_finish,
            commands::unlock,
            commands::lock,
            commands::startup_checks,
            commands::get_receive,
            commands::preview_signer_wallet,
            commands::add_signer_wallet,
            commands::get_audit_log,
            commands::get_address_book,
            commands::add_address_book_entry,
            commands::remove_address_book_entry,
            commands::rename_address_book_entry,
            commands::list_test_wallets,
            commands::add_test_wallet,
            commands::remove_test_wallet,
            commands::scan_test_wallet,
            commands::prepare_test_send,
            commands::finish_test_send,
            commands::get_settings,
            commands::set_bitcoin_enabled,
            commands::set_real_sending,
            commands::get_nile_balances,
            commands::prepare_tron_test_send,
            commands::finish_tron_test_send,
            commands::get_sepolia_balances,
            commands::prepare_eth_test_send,
            commands::finish_eth_test_send,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the app");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_is_restricted() {
        let ok = |s: &str| allowed_navigation(&Url::parse(s).expect("url"));
        assert!(ok("tauri://localhost/index.html"));
        assert!(ok("http://tauri.localhost/index.html"));
        assert!(!ok("https://evil.example/"));
        assert!(!ok("https://tauri.localhost.evil.example/"));
        assert!(!ok("file:///C:/Windows/"));
    }
}
