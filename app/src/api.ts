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

export const api = {
  listWallets: () => invoke<WalletView[]>("list_wallets"),
  addWallet: (input: NewWalletInput) => invoke<WalletView[]>("add_wallet", { input }),
  removeWallet: (id: string) => invoke<WalletView[]>("remove_wallet", { id }),
  getPortfolio: () => invoke<Portfolio>("get_portfolio"),
  appInfo: () => invoke<AppInfo>("app_info"),
};

export function errorText(e: unknown): string {
  return typeof e === "string" ? e : "Something went wrong.";
}
