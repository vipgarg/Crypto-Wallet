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

export const api = {
  listWallets: () => invoke<WalletView[]>("list_wallets"),
  addWallet: (input: NewWalletInput) => invoke<WalletView[]>("add_wallet", { input }),
  removeWallet: (id: string) => invoke<WalletView[]>("remove_wallet", { id }),
  getPortfolio: () => invoke<Portfolio>("get_portfolio"),
  appInfo: () => invoke<AppInfo>("app_info"),
  getProgress: () => invoke<Progress>("get_progress"),
  getActivity: (id: string) => invoke<WalletActivity>("get_activity", { id }),
};

export function errorText(e: unknown): string {
  return typeof e === "string" ? e : "Something went wrong.";
}
