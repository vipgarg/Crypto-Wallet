//! Watch-only wallet desktop app. Holds no seeds or private keys.

pub mod commands;

use std::sync::Mutex;

use data_sources::{NetworkConfig, ReqwestClient};
use tauri::{Manager, Url, WebviewUrl, WebviewWindowBuilder};
use wallet_core::Registry;

use commands::AppState;

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
            let registry_path = dir.join("wallets.json");
            let registry = Registry::load(&registry_path).map_err(|e| {
                format!("The wallet list file can't be read ({e}). It has not been changed. See docs/incident-runbook.md.")
            });
            app.manage(AppState {
                registry: Mutex::new(registry),
                registry_path,
                config,
                http,
                progress: commands::ProgressState::default(),
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
