// The reviewed list of UI→core commands (ARCHITECTURE.md §9.1). Each one gets
// an `allow-<name>` permission; only those listed in capabilities/main.json are
// callable. The test in src/commands.rs fails if a command is added in code but
// not here.
const COMMANDS: &[&str] = &[
    "list_wallets",
    "add_wallet",
    "remove_wallet",
    "get_portfolio",
    "app_info",
    "get_progress",
    "get_activity",
    "auth_status",
    "setup_begin",
    "setup_finish",
    "unlock",
    "lock",
    "startup_checks",
    "get_receive",
    "preview_signer_wallet",
    "add_signer_wallet",
    "get_audit_log",
    "get_address_book",
    "add_address_book_entry",
    "remove_address_book_entry",
    "rename_address_book_entry",
    "list_test_wallets",
    "add_test_wallet",
    "remove_test_wallet",
    "scan_test_wallet",
    "prepare_test_send",
    "finish_test_send",
    "get_settings",
    "set_bitcoin_enabled",
    "set_real_sending",
    "set_book_wait",
    "get_nile_balances",
    "prepare_tron_test_send",
    "finish_tron_test_send",
    "get_sepolia_balances",
    "prepare_eth_test_send",
    "finish_eth_test_send",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri build configuration");
}
