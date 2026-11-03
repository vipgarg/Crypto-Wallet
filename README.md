# Crypto Wallet — Watch-Only App (Phase 1)

A personal self-custody wallet, built in phases. This repository currently contains:

- **Design:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (full plan, rev 4.1) and [`docs/ARCHITECTURE-MOBILE.md`](docs/ARCHITECTURE-MOBILE.md) (budget variant: existing PC + offline OnePlus tablet signer).
- **Signer (Phase 2):** [`docs/signer-app.md`](docs/signer-app.md). The Rust core (`crates/signer-core`) and Kotlin bridge (`crates/signer-ffi`) are built and tested; the Android screens come next.
- **Guides:** [`docs/alerts-guide.md`](docs/alerts-guide.md) (free email alerts for your addresses, works with the PC off). Evidence for the exit gates: [`docs/release-gate.md`](docs/release-gate.md).
- **Code:** the **watch-only PC app** (Phase 1). It shows balances for your wallets and **holds no seeds or private keys**. It can't sign or send anything.

## What the watch-only app does

| Feature | Detail |
|---|---|
| Wallets | **Add from the signer tablet**: scan its export QR with the PC webcam (or paste the export text). The PC checks the export again, shows the fingerprint, Bitcoin address #0, Ethereum and TRON addresses to compare with the tablet screen, and adds the wallet only after you confirm they match. The camera is on only while the scan panel is open. Or add by hand with **public data only**: a BIP-84 `zpub`/`xpub` (or one address) for Bitcoin, an Ethereum address, a TRON address. Seed phrases, private keys and `xprv` are refused. |
| Balances | BTC; USDT on Ethereum (ERC-20) and ETH for fees; USDT on TRON (TRC-20) and TRX for fees. |
| Cross-checking | Every balance is asked of **2 independent providers per network**. Identical answers = *Verified*. One answer = *Unverified*. Different answers = *Sources disagree* (no value shown, no majority vote). Totals only add verified balances. |
| Pinned contracts | USDT contract addresses are compiled in (`config/networks.v1.toml`); the app shows the config's SHA-256 on the About page. |
| Privacy | The Bitcoin xpub never leaves your PC: providers are only asked about individual addresses. The UI shows only the xpub's fingerprint. |
| Receive | QR code and address (even groups of 4, first and last 6 characters in bold) with a clear network banner. Bitcoin gives a fresh, never-used address each time (checked with both providers; fails closed if they can't confirm), with a "New address" button. Copy clears the clipboard after 60 s. A "verify on the signer" step explains what to compare on the tablet. |
| Login | First run: choose a password and link an authenticator app (QR code). Every start: password + 6-digit code. The wallet list is encrypted on disk (Argon2id + XChaCha20-Poly1305). Increasing delays on wrong attempts, 30-minute lock after 5. Auto-lock after 5 minutes idle, and a Lock button. |
| PC safety checks | Shown on the login screen and the Checks page: Windows Defender, Windows updates, admin account, remote-access tools / Remote Desktop, proxy, PC clock vs blockchain time, app file fingerprint, config hash. They catch mistakes and simple malware; admin-level malware can fake them. |
| Address book | People and accounts you pay, per network, with how each was verified (phone call, second channel, test transaction) and which tiers may pay it (Spending/Savings; never Vault). Stored in the encrypted store. A new entry is usable only after a **24-hour waiting period counted in network time** (latest block times from ≥ 2 providers that agree), so changing the PC clock doesn't shorten it; without network time it counts as still waiting. **Look-alike addresses** (same 3 characters after the prefix, or same last 3) of an entry or your own wallets are **refused**. Your own wallets can't be added (they're listed automatically). Only the label can be edited; anything else = remove + add (new waiting period). Removed addresses stay on a revocation list. Requires confirming the entry is in your paper address book, which stays the source of truth. Entries are also used by the Activity look-alike check. |
| Audit log | **Log** page: every login (and failed attempt), lock, wallet added or removed, and PC check problem, newest first. Each entry is hash-linked to the one before, and the whole log is checked at every start (result also on the Checks page). Catches accidental damage and edits to old entries; not tamper-proof against someone controlling the PC, so write the shown *head* on paper now and then. Not encrypted (failed logins are logged before login), so it never contains addresses, labels or amounts. |
| Security boundary | Tauri 2 with a strict Content-Security-Policy, the isolation pattern, a capability file allowing exactly the 21 reviewed commands, navigation locked to the app, no plugins (no shell/fs/http/updater). |

**Also built:** Activity (history) for TRON, Ethereum and Bitcoin with address-poisoning detection: 0-value and dust transfers and fake tokens hidden, look-alike addresses flagged, approvals and tokens moved by someone else always shown. History comes from one source per network (TronGrid, Blockscout, Esplora) and is labelled as not cross-checked.

**Not built yet:** policy checkpoints to an external monitor, sending (Phase 2), the signer tablet's own allowlist.

## Repository layout

```text
crates/
  wallet-types/   integer Amount (u128, no floats), Asset, Network, Tier, WalletId
  chain-btc/      mainnet address parsing, BIP-84 derivation from zpub/xpub, gap limit, Esplora parsing
  chain-eth/      EIP-55 strict addresses, derivation, read-only JSON-RPC encoding/parsing
  chain-tron/     Base58Check addresses (0x41), derivation, read-only /wallet API encoding/parsing
  data-sources/   compiled-in network config, HTTPS client, cross-checking (no majority vote)
  wallet-core/    watch-only wallet registry (atomic saves) and the portfolio
  watch-export/   the tablet's watch-only export format (shared; no seed code)
  audit-log/      append-only, hash-chained audit log
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
