// Typed wrappers around the Rust commands. These are the ONLY calls the UI can
// make (ARCHITECTURE.md §9.1); the Rust side validates every argument again.
import { invoke } from "@tauri-apps/api/core";

export type Tier = "vault" | "savings" | "spending" | "watch_only";
export type Asset = "btc" | "eth" | "trx" | "usdt_erc20" | "usdt_trc20";
export type BalanceStatus = "verified" | "unverified" | "disagreement" | "unavailable";

export interface AssetBalance {
  asset: Asset;
  label: string;
  status: BalanceStatus;
  /** Exact decimal string from Rust. Never parsed into a JS number. */
  display: string | null;
  sources: string[];
  problems: string[];
}

export interface WalletPortfolio {
  id: string;
  label: string;
  tier: Tier;
  tier_name: string;
  balances: AssetBalance[];
}

export interface AssetTotal {
  asset: Asset;
  label: string;
  /** null when no balance of this asset could be verified. */
  display: string | null;
  verified_wallets: number;
  complete: boolean;
}

export interface Portfolio {
  wallets: WalletPortfolio[];
  totals: AssetTotal[];
  config_sha256: string;
  warnings: string[];
}

export type BtcView =
  | { kind: "account_xpub"; fingerprint: string }
  | { kind: "address"; address: string };

export interface WalletView {
  id: string;
  label: string;
  tier: Tier;
  tier_name: string;
  btc: BtcView | null;
  eth: string | null;
  tron: string | null;
  /** Set when the wallet was imported from the signer tablet. */
  signer_fingerprint: string | null;
}

export interface SignerWalletPreview {
  id: string;
  label: string;
  tier_name: string;
  fingerprint: string;
  btc_first_address: string;
  eth: string;
  tron: string;
  /** Why it can't be added (e.g. already watched), if anything. */
  problem: string | null;
}

export type AuditEvent =
  | "app_started"
  | "chain_broken"
  | "setup_completed"
  | "login_succeeded"
  | "login_failed"
  | "login_blocked"
  | "locked"
  | "idle_locked"
  | "wallet_added"
  | "wallet_removed"
  | "checks_problem";

export interface AuditEntry {
  seq: number;
  /** PC clock, Unix seconds. */
  at: number;
  event: AuditEvent;
  detail: string;
  prev: string;
}

export interface AuditView {
  intact: boolean;
  count: number;
  head_short: string;
  problem: string | null;
  /** Newest first. */
  entries: AuditEntry[];
}

export type VerifiedBy = "phone_call" | "second_channel" | "test_transaction" | "own_account_elsewhere";

export type Usable = { kind: "yes" } | { kind: "waiting"; from: number } | { kind: "unknown"; from: number };

export interface BookEntryView {
  id: string;
  label: string;
  network: HistoryNetwork;
  network_name: string;
  address: string;
  verified_by: string;
  note: string;
  tiers: string[];
  added_at: number;
  usable: Usable;
  previously_removed_at: number | null;
}

export interface AddressBookView {
  entries: BookEntryView[];
  own: { label: string; network_name: string; address: string }[];
  revoked: { network: HistoryNetwork; address: string; label: string; removed_at: number }[];
  network_time: number | null;
  waiting_hours: number;
}

export interface NewBookEntry {
  label: string;
  network: HistoryNetwork;
  address: string;
  verified_by: VerifiedBy;
  note: string;
  tiers: Tier[];
  written_on_paper: boolean;
}

export interface TestWalletSummary {
  id: string;
  label: string;
  fingerprint: string;
  /** Test receive address #0 (tb1…), worked out on the PC. */
  first_receive_address: string;
}

export interface TestWalletView {
  id: string;
  label: string;
  fingerprint: string;
  status: "verified" | "unverified" | "unavailable";
  confirmed_sats: number;
  used: { chain: number; index: number; address: string; confirmed_sats: number }[];
  receive_address: string;
  receive_index: number;
  change_index: number;
  problems: string[];
}

export interface SendPlan {
  recipient: string;
  amount_sats: number;
  change_sats: number;
  change_index: number | null;
  fee_sats: number;
  fee_rate: number;
  inputs: number;
  txid: string;
}

export interface PreparedSend {
  plan: SendPlan;
  qr_text: string;
  qr_size: number;
  qr_modules: boolean[];
}

export interface SentView {
  txid: string;
  accepted_by: string[];
  errors: string[];
  explorer_url: string;
}

export interface NileBalances {
  address: string;
  trx: string;
  usdt: string;
  source: string;
  explorer_url: string;
}

export interface PreparedTron {
  /** "usdt" or "trx" (a top-up between your own wallets). */
  kind: string;
  recipient: string;
  amount: string;
  unit: string;
  fee_limit_trx: string;
  /** Rough network cost, for display only. */
  fee_estimate: string;
  txid: string;
  qr_text: string;
  qr_size: number;
  qr_modules: boolean[];
}

export interface TronSent {
  txid: string;
  explorer_url: string;
  /** A warning when the tablet's signing log shows signatures this PC didn't see. */
  log_note: string;
}

export interface Settings {
  bitcoin_enabled: boolean;
}

export interface NewWalletInput {
  id: string;
  label: string;
  tier: Tier;
  btc: string | null;
  eth: string | null;
  tron: string | null;
}

export interface ProviderView {
  id: string;
  network: string;
  operator: string;
  base_url: string;
}

export interface AppInfo {
  version: string;
  config_version: number;
  config_sha256: string;
  usdt_erc20: string;
  usdt_trc20: string;
  providers: ProviderView[];
  independence_warnings: string[];
}

export type ProgressLevel = "info" | "ok" | "warn" | "error";

export interface ProgressLine {
  at_ms: number;
  level: ProgressLevel;
  text: string;
}

export interface Progress {
  running: boolean;
  elapsed_ms: number;
  checks: number;
  lines: ProgressLine[];
}

export type Direction = "in" | "out" | "self_transfer" | "not_involved";

export type Flag =
  | { kind: "zero_value" }
  | { kind: "dust"; below: string }
  | { kind: "btc_dust"; below: string }
  | { kind: "unconfirmed" }
  | { kind: "look_alike"; similar_to: string; similar_to_label: string }
  | { kind: "fake_token" }
  | { kind: "unknown_token" }
  | { kind: "approval" }
  | { kind: "spent_by_other" }
  | { kind: "permission_change" }
  | { kind: "other_contract"; contract: string }
  | { kind: "trc10" }
  | { kind: "failed" };

export interface TxEntry {
  txid: string;
  time_ms: number;
  success: boolean;
  action: string;
  direction: Direction;
  amount: string | null;
  asset_label: string | null;
  counterparty: string | null;
  flags: Flag[];
  hidden: boolean;
}

export interface TransactionsView {
  source: string;
  entries: TxEntry[];
  hidden_count: number;
  unreadable: number;
}

export interface ActivityEntry {
  txid: string;
  time_ms: number;
  direction: Direction;
  is_approval: boolean;
  token_label: string;
  genuine_usdt: boolean;
  amount: string | null;
  counterparty: string;
  flags: Flag[];
  hidden: boolean;
}

export type HistoryNetwork = "tron" | "ethereum" | "bitcoin";

export interface WalletActivity {
  wallet_id: string;
  network: HistoryNetwork;
  address: string;
  source: string;
  entries: ActivityEntry[];
  hidden_count: number;
  approval_count: number;
  lookalike_count: number;
  unreadable: number;
  notes: string[];
  transactions: TransactionsView | null;
  transactions_error: string | null;
  permission_changes: number;
}

export interface AuthStatus {
  state: "needs_setup" | "locked" | "unlocked";
  wait_secs: number;
  has_legacy_wallets: boolean;
}

export interface SetupInfo {
  secret: string;
  qr_size: number;
  qr_modules: boolean[];
}

export type CheckStatus = "pass" | "warn" | "fail" | "unknown" | "not_applicable";

export interface SystemCheck {
  id: string;
  title: string;
  status: CheckStatus;
  detail: string;
  blocks_sends: boolean;
}

export type ReceiveNetwork = "bitcoin" | "ethereum" | "tron";

export interface ReceiveView {
  network: string;
  assets: string[];
  address: string;
  qr: { size: number; modules: boolean[] };
  btc_index: number | null;
  signer_hint: string;
  warnings: string[];
}

/** Fired when Rust reports the session is locked, so the app shows login. */
export const LOCKED_EVENT = "wallet-locked";

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    if (typeof e === "string" && e.startsWith("Locked")) {
      window.dispatchEvent(new Event(LOCKED_EVENT));
    }
    throw e;
  }
}

export const api = {
  listWallets: () => call<WalletView[]>("list_wallets"),
  addWallet: (input: NewWalletInput) => call<WalletView[]>("add_wallet", { input }),
  removeWallet: (id: string) => call<WalletView[]>("remove_wallet", { id }),
  getPortfolio: () => call<Portfolio>("get_portfolio"),
  appInfo: () => call<AppInfo>("app_info"),
  getProgress: () => call<Progress>("get_progress"),
  getActivity: (id: string, network: HistoryNetwork) =>
    call<WalletActivity>("get_activity", { id, network }),
  authStatus: () => call<AuthStatus>("auth_status"),
  setupBegin: () => call<SetupInfo>("setup_begin"),
  setupFinish: (password: string, code: string) => call<void>("setup_finish", { password, code }),
  unlock: (password: string, code: string) => call<void>("unlock", { password, code }),
  lock: (idle: boolean) => call<void>("lock", { idle }),
  startupChecks: () => call<SystemCheck[]>("startup_checks"),
  getReceive: (id: string, network: ReceiveNetwork, skip: number) =>
    call<ReceiveView>("get_receive", { id, network, skip }),
  previewSignerWallet: (text: string) => call<SignerWalletPreview>("preview_signer_wallet", { text }),
  addSignerWallet: (text: string) => call<WalletView[]>("add_signer_wallet", { text }),
  getAuditLog: () => call<AuditView>("get_audit_log"),
  getSettings: () => call<Settings>("get_settings"),
  getNileBalances: (id: string) => call<NileBalances>("get_nile_balances", { id }),
  prepareTronTestSend: (id: string, recipient: string, amount: string, kind: "usdt" | "trx") =>
    call<PreparedTron>("prepare_tron_test_send", { id, recipient, amount, kind }),
  finishTronTestSend: (signedQr: string) => call<TronSent>("finish_tron_test_send", { signedQr }),
  setBitcoinEnabled: (enabled: boolean) => call<Settings>("set_bitcoin_enabled", { enabled }),
  getAddressBook: () => call<AddressBookView>("get_address_book"),
  addAddressBookEntry: (entry: NewBookEntry) => call<AddressBookView>("add_address_book_entry", { entry }),
  removeAddressBookEntry: (id: string) => call<AddressBookView>("remove_address_book_entry", { id }),
  renameAddressBookEntry: (id: string, label: string) =>
    call<AddressBookView>("rename_address_book_entry", { id, label }),
  listTestWallets: () => call<TestWalletSummary[]>("list_test_wallets"),
  addTestWallet: (text: string) => call<TestWalletSummary[]>("add_test_wallet", { text }),
  removeTestWallet: (id: string) => call<TestWalletSummary[]>("remove_test_wallet", { id }),
  scanTestWallet: (id: string) => call<TestWalletView>("scan_test_wallet", { id }),
  prepareTestSend: (id: string, recipient: string, amountSats: number, feeRate: number) =>
    call<PreparedSend>("prepare_test_send", { id, recipient, amountSats, feeRate }),
  finishTestSend: (signedQr: string) => call<SentView>("finish_test_send", { signedQr }),
};

export function errorText(e: unknown): string {
  return typeof e === "string" ? e : "Something went wrong.";
}
