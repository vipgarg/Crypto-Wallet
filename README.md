# Crypto Wallet — Watch-Only App (Phase 1)

A personal self-custody wallet, built in phases. This repository currently contains:

- **Design:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (full plan, rev 4.1) and [`docs/ARCHITECTURE-MOBILE.md`](docs/ARCHITECTURE-MOBILE.md) (budget variant: existing PC + offline OnePlus tablet signer).
- **Guides:** [`docs/alerts-guide.md`](docs/alerts-guide.md) (free email alerts for your addresses, works with the PC off). Evidence for the exit gates: [`docs/release-gate.md`](docs/release-gate.md).
- **Code:** the **watch-only PC app** (Phase 1). It shows balances for your wallets and **holds no seeds or private keys**. It can't sign or send anything.

## What the watch-only app does

| Feature | Detail |
|---|---|
| Wallets | Add wallets by **public data only**: a BIP-84 `zpub`/`xpub` (or one address) for Bitcoin, an Ethereum address, a TRON address. Seed phrases, private keys and `xprv` are refused. |
| Balances | BTC; USDT on Ethereum (ERC-20) and ETH for fees; USDT on TRON (TRC-20) and TRX for fees. |
| Cross-checking | Every balance is asked of **2 independent providers per network**. Identical answers = *Verified*. One answer = *Unverified*. Different answers = *Sources disagree* (no value shown, no majority vote). Totals only add verified balances. |
| Pinned contracts | USDT contract addresses are compiled in (`config/networks.v1.toml`); the app shows the config's SHA-256 on the About page. |
| Privacy | The Bitcoin xpub never leaves your PC: providers are only asked about individual addresses. The UI shows only the xpub's fingerprint. |
| Security boundary | Tauri 2 with a strict Content-Security-Policy, the isolation pattern, a capability file allowing exactly 5 commands, navigation locked to the app, no plugins (no shell/fs/http/updater). |

**Not built yet** (next increments of Phase 1): transaction history with dust/poisoning hiding, receive-address QR codes, start-up checks and login (§9.8), audit log and policy checkpoints, explorer-alert setup guide.

## Repository layout

```text
crates/
  wallet-types/   integer Amount (u128, no floats), Asset, Network, Tier, WalletId
  chain-btc/      mainnet address parsing, BIP-84 derivation from zpub/xpub, gap limit, Esplora parsing
  chain-eth/      EIP-55 strict addresses, derivation, read-only JSON-RPC encoding/parsing
  chain-tron/     Base58Check addresses (0x41), derivation, read-only /wallet API encoding/parsing
  data-sources/   compiled-in network config, HTTPS client, cross-checking (no majority vote)
  wallet-core/    watch-only wallet registry (atomic saves) and the portfolio
app/
  src/            React + TypeScript UI
  isolation/      Tauri isolation script (second command allowlist)
  src-tauri/      Rust app shell: commands.rs is the ONLY UI→core entry point
config/networks.v1.toml   providers + pinned contracts
```

## Build and run on your Windows PC

**Use the dedicated standard "wallet" Windows account only to *run* the installed app.** Build in your development account or build VM (ARCHITECTURE.md §9.3).

Prerequisites (official sources only, verify downloads):
1. **Rust** via `rustup` (the repo pins the exact toolchain in `rust-toolchain.toml`).
2. **Node.js 22 LTS**.
3. **Microsoft C++ Build Tools** ("Desktop development with C++").
4. **WebView2** (already included in Windows 10/11).

```bash
cd app
```

```bash
npm ci --ignore-scripts
```

Run in development mode:

```bash
npx tauri dev
```

Build the Windows installer (output in `target/release/bundle/nsis/` at the repository root):

```bash
npx tauri build
```

Run the tests and lints (from the repository root):

```bash
cargo test --workspace
```

```bash
cargo clippy --workspace --all-targets
```

## First run checklist

1. Open **About** and write down the *Network config SHA-256*. It must match the value recorded for the reviewed build.
2. Check that each provider in the table actually answers from your network. If a provider is down, its network shows *Unverified*. Replace providers only through a reviewed change to `config/networks.v1.toml`.
3. Add wallets with **public data exported from your signer tablet** (never from a website).
4. Compare each balance with a block explorer once (Phase 1 exit gate).

## Status

Design and Phase 1 in progress. **Not for real funds' signing** — this app can't sign, by design.
