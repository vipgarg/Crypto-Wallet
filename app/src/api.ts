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
  | { kind: "dust" }
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

export interface WalletActivity {
  wallet_id: string;
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
  getActivity: (id: string) => call<WalletActivity>("get_activity", { id }),
  authStatus: () => call<AuthStatus>("auth_status"),
  setupBegin: () => call<SetupInfo>("setup_begin"),
  setupFinish: (password: string, code: string) => call<void>("setup_finish", { password, code }),
  unlock: (password: string, code: string) => call<void>("unlock", { password, code }),
  lock: () => call<void>("lock"),
  startupChecks: () => call<SystemCheck[]>("startup_checks"),
  getReceive: (id: string, network: ReceiveNetwork, skip: number) =>
    call<ReceiveView>("get_receive", { id, network, skip }),
  previewSignerWallet: (text: string) => call<SignerWalletPreview>("preview_signer_wallet", { text }),
  addSignerWallet: (text: string) => call<WalletView[]>("add_signer_wallet", { text }),
};

export function errorText(e: unknown): string {
  return typeof e === "string" ? e : "Something went wrong.";
}
