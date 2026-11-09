// Tauri isolation pattern (ARCHITECTURE.md §9.1): every IPC message from the
// UI passes through this sandboxed script before it reaches Rust. Anything not
// on the reviewed command list is dropped here, as a second layer behind the
// Rust-side capability allowlist.
const ALLOWED = new Set([
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
  "get_nile_balances",
  "prepare_tron_test_send",
  "finish_tron_test_send",
  "get_sepolia_balances",
  "prepare_eth_test_send",
  "finish_eth_test_send",
]);

window.__TAURI_ISOLATION_HOOK__ = (payload) => {
  if (!payload || typeof payload.cmd !== "string" || !ALLOWED.has(payload.cmd)) {
    // Throwing stops Tauri's isolation script before the message is sent.
    throw new Error("blocked: command is not on the reviewed list");
  }
  return payload;
};
