# Personal Self-Custody Wallet — Security Architecture

**Status:** Design, revision 3 (two external gap reviews applied, see §14). Nothing is built yet. **Not ready for real funds** until the §15 release sequence completes.
**Owner:** Vipul
**Platform:** Windows 10/11 desktop
**Assets:** BTC, USDT on Tron (TRC-20), USDT on Ethereum (ERC-20)
**Expected holdings:** more than ₹1 Crore, spread across several wallets
**Source:** the ChatGPT conversation "Create Crypto Wallet" (shared 2026-10), plus the security review in this document

---

## 0. How to read this document

| Section | What it answers |
|---|---|
| 1. Goals & non-goals | What the wallet must and must not do |
| 2. Threat model | Who/what can steal funds, and how |
| 3. Core security principles | Rules every phase must follow |
| 4. Multi-wallet model | How the wallets are split into tiers, and why |
| 5. System architecture | The components and trust boundaries |
| 6. Key, seed & backup management | How secrets are created, stored and recovered |
| 7. Transaction security pipeline | How a send is protected end to end |
| 8. Chain-specific rules | BTC / ERC-20 / TRC-20 details |
| 9. Application & OS hardening | Tauri, Rust, Windows, and the supply chain |
| 10. Monitoring & incident response | How you find out about an attack, and what to do |
| 11. Phased roadmap | What gets built in which order, with exit gates |
| 12. Threat → control map | Which control stops which threat, and in which phase |
| 13. Open decisions | Choices you still need to make |
| 14. Gap reviews (rev 2, rev 3) | Each finding from the external reviews: already covered, strengthened, or new |
| 15. Mainnet release sequence & gate | The exact order and checklist before any real funds touch the custom app |

Every phase in section 11 has an **exit gate**. Do not start the next phase until its gate passes. Phase 4 (real funds) also needs the full **§15 release sequence**.

**Core idea (from the review, adopted as-is):** a hardware wallet protects the private keys, but it does **not** protect you from *approving a malicious transaction*. The desktop app is never trusted to tell the truth about a transaction. Only the device display and data you verify independently are.

**Final authorization boundary (rev 3):** *the hardware wallet's screen + your physical confirmation on it.* Nothing on the PC (review screen, native dialog, `review_id`, post-sign check) is an authorization control; those only catch app bugs and protect the app's own broadcast path. **Once you approve on the device, assume the signed transaction can be broadcast by malware.** So approve only what the device itself shows correctly.

---

## 1. Goals & non-goals

### Goals

1. **Only you can move funds.** No exchange, company, server or API provider can sign for you.
2. **No single point of compromise.** One infected PC, one stolen device or one leaked backup must not be enough to drain the main holdings.
3. **No silent transactions.** Every outgoing transaction is shown in readable form and approved physically by you.
4. **Recoverable without this app.** If the app, the PC or the developer (you) disappears, the funds can still be recovered with standard tools and the written backups.
5. **Multiple wallets, one view.** One app shows balances and activity for all wallets and all three networks.
6. **Detect fast.** Any unexpected outgoing transaction, token approval or permission change raises an alert within minutes.

### Non-goals

- **Not a custodial service** and not used by other people.
- **No new cryptography.** Only established, widely reviewed libraries and standards (BIP-32/39/44/84, PSBT, EIP-155/1559, secp256k1).
- **Not anonymous.** Blockchains are public, and RPC providers can see your IP address and which addresses you query.
- **No DeFi, swaps or dApp browser** in the first release. Each one adds contract-approval risk.
- **No reversal of transactions.** Once confirmed on-chain, a transfer cannot be undone. Every control is about *prevention* and *early detection*.

---

## 2. Threat model

### 2.1 What we protect

| Asset | If it is lost or stolen |
|---|---|
| Recovery phrase (seed) | Attacker can take **everything** derived from it, from any computer |
| Private keys (derived) | Attacker can spend from those addresses |
| Signing approval (your click/button) | Attacker can trick you into signing their transaction |
| BTC multisig descriptor / xpubs | Can't spend, but **without it a multisig cannot be recovered** (and privacy is lost) |
| Vault password / device PIN | Unlocks the local vault or the hardware device |
| Address book / allowlist | If changed, sends go to the attacker |
| Wallet inventory | Privacy loss, and a target list for social engineering |

### 2.2 Attackers and attack paths

| # | Threat | Example | Severity |
|---|---|---|---|
| T1 | **Malware on the Windows PC** | Keylogger, remote-access trojan, infostealer reads the decrypted vault while the wallet is unlocked | Critical |
| T2 | **Clipboard / address swap** | Malware replaces the copied address with the attacker's | Critical |
| T3 | **Address poisoning** | Attacker sends a 0-value USDT transfer from a look-alike address (same first and last characters) so you copy it from history | High (very common on TRON and Ethereum USDT) |
| T4 | **Seed phrase theft** | Photo, cloud backup, typed into a fake "wallet sync" site, found by a visitor | Critical |
| T5 | **Malicious or confusing signing** | App shows A, device signs B; blind signing of contract data | Critical |
| T6 | **Unlimited token approvals** | `approve(spender, MAX)` lets a contract take all USDT later | High |
| T7 | **TRON account permission hijack** | Attacker who gets a key one time changes the account's owner/active permission and keeps control even after you notice | High |
| T8 | **Supply-chain compromise** | A hijacked npm/crates package, a compromised build machine or build tool, a malicious installer/update replacing the wallet, a fake wallet download, a tampered hardware device | Critical |
| T9 | **Bugs in your own wallet code** | Wrong derivation path, bad randomness, float rounding, wrong change output | High |
| T10 | **Lying RPC provider** | Fake balance, fake nonce, inflated fee estimate, a "tx confirmed" that never happened, **or an unsigned transaction built by the node with a swapped field** (e.g. TRON's `triggersmartcontract` returns a ready-made tx) | High |
| T11 | **Physical theft or loss** | Stolen laptop, stolen hardware wallet, fire/flood destroys backups | High |
| T12 | **Coercion / social engineering** | "Support agent" call, fake airdrop, "$5 wrench" attack | High |
| T13 | **Self-lockout** | Forgotten passphrase, lost descriptor, corrupted only backup | Critical (equally total loss) |
| T14 | **Phishing and fake software** | Fake Trezor/Ledger app, fake VeraCrypt, fake "USDT recovery" tool | High |
| T15 | **Indirect-drain signatures** | Off-chain signatures that move tokens later (EIP-2612 `permit`, Permit2, EIP-712 typed data), an EIP-7702 delegation that turns your Ethereum address into attacker-controlled code, or any contract call that isn't a plain transfer | Critical |
| T16 | **Compromised WebView / UI** | Injected script in the UI calls native commands directly, or shows a fake review screen | Critical |
| T17 | **Secrets leaking through errors** | Seed or key appearing in a log line, panic message, Windows crash dump, page file or hibernation file | High |

### 2.3 What the design assumes

- **The Windows PC may be compromised at some point.** The design must stay safe even then. This is why the main keys never live on the PC.
- **The hardware wallet screen is trusted**, the PC screen is not. This includes the app's own review screen and the native OS dialog: they are conveniences, not security controls. Malware that controls the PC can alter a transaction before it reaches the device and can broadcast anything you have signed.
- **Local policy (limits, cool-downs, allowlist) can be bypassed by malware with full control of the PC.** It protects against mistakes, social engineering and partial compromise. Against full compromise, the protections are: the device display, keys held off the PC, multisig, and the **independent monitor** (§10).
- **The UI (WebView) can be compromised.** All security checks live in the Rust core; the UI can only *request*.
- **RPC providers are honest-but-unreliable.** They can't steal funds, but their data is cross-checked before you act on it.
- **You are the weakest link under pressure.** Cool-down periods and allowlists exist to slow down a rushed or tricked decision.

---

## 3. Core security principles

These rules apply to every phase. Code review checks against them.

| # | Principle | In practice |
|---|---|---|
| P1 | **Keys never touch the PC for meaningful balances** | Vault and Savings tiers sign only on hardware wallets. The app holds public keys (xpubs) only. |
| P2 | **Separate signing from connectivity** | The component that talks to the internet never holds secrets. The component that holds secrets never talks to the internet. |
| P3 | **Verify on the device, not on the screen** | Recipient, amount, network and fee are checked on the hardware wallet display before approval. |
| P4 | **No blind signing** | If the device can't show a transaction in readable form, the app refuses to send it. |
| P5 | **Fail closed** | Unknown network, unverified token contract, mismatched RPC data, failed simulation → **stop**, don't guess. |
| P6 | **Least privilege** | The UI can ask the core for "prepare transfer" and "submit reviewed transfer", never for "give me the key". |
| P7 | **Defense in depth** | App policy (allowlist, limits, cool-down) + device confirmation + multisig + monitoring. Each layer assumes the one before it failed. |
| P8 | **No single point of failure for recovery** | ≥ 2 offline seed backups in separate places. Recovery tested before funding. |
| P9 | **Integers only** | Satoshis for BTC and base units (6 decimals for USDT) for tokens. No floating point anywhere money is calculated. |
| P10 | **Pin everything** | Token contract addresses, chain IDs, dependency versions and the hardware-wallet SDK version are all pinned and reviewed. |
| P11 | **Secrets never logged** | No seed, key, password or raw signing payload in logs, crash reports, analytics, screenshots or clipboard history. |
| P12 | **Small first, big later** | Every new capability goes through testnet → tiny mainnet amount → normal use. |
| P13 | **Explicit operation allowlist** | Only these operations can be signed: **BTC send**, **ERC-20 USDT `transfer`**, **TRC-20 USDT `transfer`**, plus **plain ETH / TRX transfers to your own allowlisted wallets** (to top up gas/energy fees). Everything else is rejected by the core: `approve`, `permit`, EIP-712 / message signing, EIP-7702 authorizations, arbitrary contract calls, TRON permission updates (except a deliberate, separately reviewed recovery flow). |
| P14 | **Build locally, decode before signing** | Transactions are built by the core, never accepted from a node. Every unsigned tx is decoded field by field and checked by the chain validator (§8) right before it goes to the signer. |
| P15 | **Independent review before real funds** | The signing path and the release build are reviewed by someone other than the author before Phase 4 (§15). |

---

## 4. Multi-wallet model

The ChatGPT chat recommended separating "long-term BTC", "USDT savings" and "day-to-day transfer" wallets. This design formalises that as **tiers**. Each tier is a separate wallet with **its own recovery phrase**, so compromising a lower tier never exposes a higher one.

> **Change from the chat:** the chat proposed one shared vault/seed with three chain adapters. That still applies **inside** a tier (one seed → BTC + ETH + TRON addresses). But across tiers, use **separate seeds**. One seed for everything would make a single leak catastrophic.

### 4.1 Tiers

| Tier | Purpose | Share of holdings (suggested) | Signing | Seed backup | How often used |
|---|---|---|---|---|---|
| **T-0 Vault** | Long-term reserve | Majority (e.g. 70–85%) | **Differs per asset, see §4.1b.** BTC: 2-of-3 multisig. ETH USDT and TRON USDT: hardware single-sig on dedicated seeds. **Never signed by the custom app in v1**; signed with vendor software / Sparrow | Separate seed per key, each stored in a different location | Rarely (a few times a year) |
| **T-1 Savings** | Medium-term, occasional moves | e.g. 10–25% | Hardware wallet single-sig | 2 metal/paper copies, 2 locations | Monthly |
| **T-2 Spending** | Daily/weekly transfers | **Hard cap**, e.g. ≤ ₹50,000 (≈0.5% at ₹1 Cr) | **A separate, cheaper hardware wallet: the only supported production signer (rev 3).** The software vault is a labelled **weak mode** (§6.4) | 2 paper copies | Weekly/daily |
| **T-W Watch-only** | Exchange deposit addresses, old wallets, other people's addresses you track | n/a | **None** (public addresses/xpubs only) | n/a | Read-only |

The percentages and cap are suggestions. Pick your own numbers in Phase 0 and write them down; the app enforces them in Phase 3.

### 4.1a Security domains: independent keys (rev 2)

The review warned that one seed deriving BTC + ETH + TRON keys is a single point of failure. This design handles it in layers:

| Rule | Detail |
|---|---|
| **Separate seed per tier** | Already in rev 1. A Spending leak never reaches Savings or Vault. |
| **Separate seeds per chain inside the Vault** | The 3 BTC multisig keys are used **only** for BTC. Vault USDT (ETH/TRON) uses **its own** hardware-wallet seed(s), so one leaked seed can't reach both BTC and USDT reserves. |
| **Savings: one seed for 3 chains is accepted** | It's a trade-off for usability. It is protected by the hardware wallet + passphrase (D3) + monitoring. If Savings grows above ~₹10 lakh, split it into `savings-btc` and `savings-usdt` with separate seeds. |
| **The primary seeds never enter the desktop app** | T-0/T-1 seeds exist only inside hardware wallets and on steel/paper. The app never asks for, imports or stores them. The only seed the app may ever hold is a capped **weak-mode** seed (§6.4); the production T-2 signer is a hardware wallet. |
| **No recovery phrase on any USB** | Already in rev 1 (§6.3). The USB holds only non-secret recovery material. |

### 4.1b Actual protection level per asset (rev 3)

The Vault is **not** equally protected on every chain. This table is the honest state for v1; nothing elsewhere in this document should be read as implying more.

| Asset & tier | v1 signing design | Survives 1 compromised signer/seed? | Who signs | Upgrade path |
|---|---|---|---|---|
| BTC Vault | 2-of-3 P2WSH multisig, ≥2 vendors | **Yes** | Sparrow (or vendor app) on a clean machine + devices. The custom app is watch-only for it | — |
| ETH USDT Vault | Hardware single-sig, dedicated seed | **No.** One leaked seed = loss | Vendor app / clean machine + device | Safe 2-of-3, **only** after §8.4 validator, recovery and review are done (deferred, not in v1) |
| TRON USDT Vault | Hardware single-sig, dedicated seed, permission baseline monitored | **No.** One leaked seed = loss; a permission change is detected, not prevented | Vendor app / clean machine + device | TRON permission multisig, **only** after §8.5 policy, recovery and review are done (deferred, not in v1) |
| Savings (all 3) | Hardware single-sig | No | Custom app **only if** §15 independent review passed (else vendor app) | Split seeds per chain (§4.1a) |
| Spending (all 3) | Separate hardware wallet (weak-mode software vault optional) | No; loss is limited to the cap | Custom app | — |

Because ETH and TRON USDT Vault holdings have single-seed protection, keep their seed backups to the strictest standard (§6.3) and decide in Phase 0 how much of the reserve you accept holding with single-seed protection (D4).

### 4.2 Money flow between tiers

```
              (rare, planned, cool-down 48h)
   ┌───────────────────────────────────────────┐
   ▼                                           │
┌──────────┐   top-up (monthly)   ┌──────────┐ │ top-up (weekly)  ┌──────────┐
│ T-0 VAULT│ ───────────────────▶ │T-1 SAVING│ ─┴────────────────▶ │T-2 SPEND │ ──▶ outside world
│ multisig │                      │ hardware │                     │  capped  │
└──────────┘                      └──────────┘                     └──────────┘
     ▲  incoming deposits go to Vault/Savings receive addresses; never "pass through" Spending
```

Rules:
- Funds flow **downward only** (Vault → Savings → Spending → out). Sending *to* a higher tier is always allowed.
- Outside addresses can be paid from **Spending** freely (within limits), from **Savings** only to allowlisted addresses, and from **Vault** only to Savings (pre-allowlisted).
- Spending's cap means the most a compromised PC can steal is that cap.

### 4.3 Wallet inventory (no secrets)

Kept in the app's public data store and as an encrypted copy on the backup USB:

| Field | Example |
|---|---|
| Wallet ID / label | `vault-btc-2of3`, `savings-01`, `spend-01` |
| Tier | T-0 / T-1 / T-2 / T-W |
| Networks | BTC, ETH (USDT), TRON (USDT) |
| Signer type | Ledger / Trezor / Keystone / software vault / none |
| Fingerprint & xpub / descriptor | `[a1b2c3d4/84'/0'/0']xpub…` |
| Derivation paths & account index | `m/84'/0'/0'`, `m/44'/60'/0'/0/0`, `m/44'/195'/0'/0/0` |
| Public addresses | per network |
| Backup locations (described, not revealed) | "Seed A: location 1, metal plate" |
| Recovery instructions | step-by-step, without any secret |
| Limits & policy | daily cap, allowlist ID, cool-down |

**Never in the inventory:** seed words, private keys, passphrases, PINs, exchange passwords, 2FA recovery codes.

---

## 5. System architecture

### 5.1 Component overview

```
┌───────────────────────────────────────── Windows PC (untrusted) ─────────────────────────────────────────┐
│                                                                                                          │
│  ┌─────────────────────────────┐   narrow IPC     ┌──────────────────────────────────────────────────┐   │
│  │  UI  (React + TypeScript)   │ ───────────────▶ │  Wallet Core  (Rust, Tauri backend)              │   │
│  │  WebView2, strict CSP,      │  typed commands  │                                                  │   │
│  │  no remote content          │ ◀─────────────── │  ┌────────────┐ ┌────────────┐ ┌──────────────┐  │   │
│  │  Portfolio · Receive · Send │   view models    │  │  Policy    │ │ Tx Builder │ │ Address Book │  │   │
│  │  Activity · Wallets · Alerts│   (no secrets)   │  │  Engine    │ │ & Review   │ │ & Allowlist  │  │   │
│  └─────────────────────────────┘                  │  └────────────┘ └────────────┘ └──────────────┘  │   │
│                                                   │  ┌────────────┐ ┌────────────┐ ┌──────────────┐  │   │
│                                                   │  │ Chain      │ │ Data Store │ │ Audit Log    │  │   │
│                                                   │  │ Adapters   │ │ (SQLite,   │ │ (append-only,│  │   │
│                                                   │  │ BTC/ETH/TRX│ │ encrypted) │ │ hash-chained)│  │   │
│                                                   │  └─────┬──────┘ └────────────┘ └──────────────┘  │   │
│                                                   │        │          ┌────────────────────────────┐ │   │
│                                                   │        │          │ Signer Interface (trait)   │ │   │
│                                                   │        │          │  ├─ HardwareSigner (T-0/1) │ │   │
│                                                   │        │          │  └─ SoftwareVault  (T-2)   │ │   │
│                                                   │        │          └────────────┬───────────────┘ │   │
│                                                   └────────┼───────────────────────┼─────────────────┘   │
└────────────────────────────────────────────────────────────┼───────────────────────┼─────────────────────┘
                                                             │ HTTPS/WSS             │ USB / QR (air-gap)
                                          ┌──────────────────▼──────────┐   ┌────────▼───────────────────┐
                                          │ Blockchain data sources     │   │ Hardware wallet(s)         │
                                          │ ≥2 per network, cross-check │   │ TRUSTED: keys + screen     │
                                          │ (later: own BTC node)       │   │ + physical button          │
                                          └─────────────────────────────┘   └────────────────────────────┘
```

### 5.2 Trust boundaries

| Boundary | Trusted side | Untrusted side | What crosses it |
|---|---|---|---|
| **B1** UI ↔ Core | Core | UI (a web view can be attacked through rendered data, so treat it as hostile) | A small set of typed commands, each validated in Rust and checked against a state machine; view models without secrets. Final authorization happens **only on the hardware device** (§0, §7 ⑦). |
| **B2** Core ↔ Internet | Core | RPC/API providers | Signed raw transactions out; chain data in (always validated and cross-checked) |
| **B3** PC ↔ Hardware wallet | Hardware wallet | Whole PC | Unsigned tx (PSBT / RLP / TRON protobuf) out; signatures in. The device shows what it is signing. |
| **B4** Digital ↔ Physical backups | Offline backups | Everything digital | Nothing automated. Seeds are written by hand, never typed into the PC. |

### 5.3 Technology stack (from the chat, with additions)

| Layer | Choice | Why / notes |
|---|---|---|
| Desktop shell | **Tauri 2** | Small, Rust backend, capability-based permissions. Better security model than Electron for this use. |
| UI | **React + TypeScript** (Vite) | From the chat. No external CDN, no remote scripts. |
| Core language | **Rust** | Memory safety; `zeroize`/`secrecy` crates for secret handling. |
| Bitcoin | **rust-bitcoin** + **BDK** (bitcoin dev kit) | Descriptors, PSBT, coin selection, multisig. BDK is mature and adds wallet logic on top of rust-bitcoin. |
| Ethereum | **Alloy** | Modern successor to ethers-rs (which is deprecated). EIP-1559 tx, ABI encoding. |
| TRON | **Rust implementation of TRON tx protobuf + base58check**, or a **pinned TronWeb in a sidecar** | The chat suggested TronWeb behind a narrow adapter. Prefer Rust; if TronWeb is used, run it only in a sandboxed sidecar process, never in the UI web view. |
| BIP-39 / BIP-32 | `bip39`, `bitcoin::bip32` (or `coins-bip32`) | Vetted crates; check against official test vectors. |
| Vault encryption | **Argon2id** (KDF) + **XChaCha20-Poly1305** (AEAD) | Strong password hardening + authenticated encryption. |
| OS secret binding | **Windows DPAPI / Credential Manager** (via the `keyring` crate or `windows` crate) | Extra wrapping layer bound to your Windows account. **Not** a replacement for the password. |
| Hardware signer transport | Official vendor SDK (Ledger/Trezor/Keystone), see Phase 0 gate | Must be able to sign PSBT, EIP-1559 ERC-20 transfer, and TRC-20 transfer with readable on-device display. |
| Local data | **SQLite** (via `rusqlite`/`sqlx`), encrypted for the private parts | Public data: addresses, history, labels, settings. |
| QR | `qrcode` (generation), camera scanning optional | For receive addresses and air-gapped signers. |

### 5.4 Project structure

Refines the structure from the chat. Each Rust module from the chat becomes a separate crate, so the secret-handling code stays small and auditable.

```text
D:\Crypto\
├── docs/
│   ├── ARCHITECTURE.md              ← this file
│   ├── security-model.md            ← threats/controls, kept in sync with §2 and §12
│   ├── recovery-runbook.md          ← how to recover each wallet WITHOUT this app
│   ├── incident-runbook.md          ← what to do if something looks wrong
│   └── release-gate.md              ← evidence for each §15 gate item
├── app/                             ← Tauri application
│   ├── src/                         ← React + TS UI
│   │   ├── pages/ (portfolio, receive, send, activity, wallets, alerts, settings)
│   │   └── components/
│   └── src-tauri/
│       ├── capabilities/            ← Tauri permission allowlist
│       ├── tauri.conf.json          ← strict CSP
│       └── src/commands.rs          ← the ONLY UI→core entry points
├── crates/
│   ├── wallet-types/                ← Amount (integer), Network, Address, WalletId …
│   ├── wallet-core/                 ← orchestration, wallet registry, tiers
│   ├── policy/                      ← allowlist, limits, cool-downs, tier flow rules
│   ├── tx-review/                   ← builds the human-readable review from the *final* unsigned tx
│   ├── chain-btc/                   ← BDK, descriptors, PSBT, fee sanity
│   ├── chain-eth/                   ← Alloy, ERC-20 transfer only, nonce/gas checks
│   ├── chain-tron/                  ← TRC-20 transfer, energy/bandwidth, permission watch
│   ├── data-sources/                ← multiple RPC providers + cross-check
│   ├── signer/                      ← Signer trait
│   │   ├── signer-hw/               ← hardware wallet integration
│   │   └── signer-soft/             ← T-2 software vault (Argon2id + XChaCha20-Poly1305 + zeroize)
│   ├── store/                       ← SQLite, encrypted columns, migrations
│   └── audit-log/                   ← append-only, hash-chained log
├── tests/
│   ├── vectors/                     ← BIP-32/39/44/84, EIP-155, TRON address test vectors
│   ├── derivation/
│   ├── transactions/
│   ├── recovery/                    ← restore in a 3rd-party wallet and compare addresses
│   └── adversarial/                 ← malicious RPC, fake token, look-alike addresses
├── monitor/                         ← (rev 3) independent watch-only monitor, runs on a separate device
│   ├── watcher/                     ← polls chains, validates state, keeps checkpoints
│   └── config/                      ← addresses/xpubs (watch-only), baselines, alert channels
├── config/
│   └── networks.v1.toml             ← (rev 3) signed network/token/policy configuration (§9.6)
└── deny.toml, Cargo.lock, package-lock.json   ← pinned, audited dependencies
```

### 5.5 Data sources: what "independent" means (rev 3)

Two providers agreeing is **not** proof of truth. They can share infrastructure (many APIs resell the same backend), upstream data or bugs. So:

| Rule | Detail |
|---|---|
| Independence | Providers count as independent only if they're **different companies on different infrastructure** (not resellers of the same backend) and use different client software where possible. The chosen set and the reasoning go in the network config (§9.6). |
| Facts verified locally (never trusted from providers) | Tx encoding/decoding, signatures, address derivation, txid/`txID` computation, contract address and calldata, BTC prevout data via `txid(prev_tx)` match, and BTC block headers / proof-of-work (own node). |
| Facts taken from providers (cross-checked, never a safety proof) | Balances, UTXO "unspent" status (until own node), ETH nonce, fee estimates, TRON reference blocks, permission objects, receipts/confirmations. |
| Disagreement | Any disagreement on a fact that feeds a signature → **stop**, show which sources disagree, retry later. Never pick "the majority" or "the safer looking" value automatically. |
| Safety | Provider agreement can **never** replace the §8 validators or the device check. |
| Bitcoin own node (moved earlier) | A pruned **Bitcoin Core** node is the BTC source **from Phase 1 where practical** (on the monitor device, §10, or the wallet PC), rather than Phase 5. External BTC APIs then serve only as a second opinion. |
| Ethereum/TRON | Running full nodes is optional (heavy). Safety rests on local construction + validation + the device; providers supply data only. |

---

## 6. Key, seed & backup management

### 6.1 Seed generation

| Rule | Detail |
|---|---|
| Where | **On the hardware wallet itself** for every production wallet (T-0, T-1, T-2). Only testnet and weak-mode seeds are generated by the app. |
| How (app, testnet/weak mode only) | OS CSPRNG (`getrandom` / `OsRng`) → BIP-39 **24 words**. Never `rand::thread_rng` seeded by time, never a website, never your own algorithm. |
| Verification | After writing the words down, the app/device asks for random words back to confirm the backup. |
| BIP-39 passphrase ("25th word") | Optional for T-0/T-1. Protects against a stolen seed, but **if you forget it the funds are gone**. If used, store it **separately** from the seed, and test it. |

### 6.2 Derivation paths (one seed → three networks)

| Network | Standard | Account path | First receive address |
|---|---|---|---|
| Bitcoin (single-sig) | BIP-84 native SegWit (`bc1q…`) | `m/84'/0'/0'` | `m/84'/0'/0'/0/0` |
| Bitcoin (multisig) | BIP-48 P2WSH | `m/48'/0'/0'/2'` | via descriptor `wsh(sortedmulti(2, …))` |
| Ethereum | BIP-44 | `m/44'/60'/0'` | `m/44'/60'/0'/0/0` |
| TRON | BIP-44, coin type 195 | `m/44'/195'/0'` | `m/44'/195'/0'/0/0` |

Exit test: restore each seed in **at least one other well-known wallet** and confirm the exact same addresses appear. If they differ, your derivation is wrong. Fix it before funding.

### 6.3 Backup layout (three separate things, never together)

This is the chat's "hardware wallet + encrypted USB + offline recovery" model, made concrete:

| Backup | Contains | Medium | Where |
|---|---|---|---|
| **Seed backup A** | Seed words (one wallet/key) | Stamped steel plate (fire/water resistant) | Location 1 (home safe) |
| **Seed backup B** | Same seed words | Steel plate or paper in a sealed tamper-evident bag | Location 2 (bank locker / trusted family) |
| **Passphrase** (if used) | BIP-39 passphrase | Paper | **A different location** from its seed |
| **Encrypted USB** | Wallet inventory, BTC multisig descriptors + xpubs, recovery runbook, app config export. **No seeds, no keys.** | VeraCrypt container on a dedicated USB (or a hardware-encrypted drive such as a keypad-locked USB) | With Location 1; a 2nd copy at Location 2 |
| **Printed runbook** | Recovery steps in plain language (for you or your heir) | Paper | With each seed location |

For **T-0 2-of-3 multisig**, the three keys' seeds go to **three different locations**. Any one location being burgled or burned loses nothing; any two can recover the funds. **Each location also needs a copy of the descriptor** (it's not secret enough to hurt, and multisig recovery is impossible without it).

Never: photos, cloud drives, email, WhatsApp, password managers, notes apps, text files, screenshots, or typing a hardware-wallet seed into the PC.

**USB backups still expose information (rev 3).** "No seed on USB" removes theft of funds, not exposure: descriptors, xpubs, address lists, labels and runbooks reveal your holdings and history and help someone target you. So:

| Rule | Detail |
|---|---|
| Minimize | Only what recovery needs: recovery manifests (§6.6), descriptors/xpubs for multisig, the runbook. **No** balances, transaction history, labels like "main savings ₹40L", exchange accounts or personal ID documents. |
| Encrypt | VeraCrypt container (or hardware-encrypted drive) with a strong passphrase that isn't stored with the drive. |
| Verify | Every 6 months: open **both** USB copies on an offline machine, check the SHA-256 of each file against the hash list on paper, and confirm the content is current. Recovery drills (§6.5) use the USB copies, not your working files. |
| Retire | Old copies are overwritten and then **physically destroyed** (drill/shred the flash chip). Never sold, reused or thrown away whole. Retirement is logged on paper. |
| Printed runbook check | Before printing or storing, the runbook is checked (by you, and by the reviewer once) to contain **no** seed words, passphrases, PINs or hints to them. |

### 6.4 Software vault (testnet / weak mode only)

```
password ──Argon2id(m=256 MiB, t=3, p=1, 16-byte salt)──▶ KEK
random 32-byte DEK ──XChaCha20-Poly1305(KEK)──▶ wrapped DEK ──DPAPI (CurrentUser)──▶ stored
seed ──XChaCha20-Poly1305(DEK, 24-byte nonce, AAD = wallet_id ‖ version)──▶ vault.bin
```

> **Weak mode (rev 3).** A software vault decrypts a seed on the PC. No amount of `VirtualLock`, `zeroize` or DPAPI makes that safe against privileged malware, which contradicts §2.3. Therefore:
> - The production T-2 signer is a **separate hardware wallet**. The software vault is used for **testnets and development**, and on mainnet only if you explicitly enable "weak mode".
> - In weak mode the UI shows a permanent red "Software signing: not protected against a compromised PC" banner.
> - Weak-mode balance cap is **≤ ₹10,000**. Because the PC itself can't be trusted to enforce a cap, the **real cap is the balance you keep in it**: the independent monitor (§10) alerts when a weak-mode wallet's balance exceeds the cap, whatever the app says.
> - **Recovery never depends on the vault file** (see "Recovery" below).

- **Minimal unlocked time (rev 2):** the seed is decrypted **only for the duration of one signing call**: decrypt → derive the one key needed → sign → `zeroize`, usually under a second. "Unlocking" the app for browsing never decrypts the seed; it only decrypts the local data store.
- Decrypted material lives only in memory, inside `secrecy::SecretBox` with `zeroize` on drop, in pages locked with `VirtualLock` so they aren't written to the page file (§9.2).
- **Auto-lock** of the data store after 5 minutes idle (configurable), on screen lock and on sleep.
- Key material is **never** sent over IPC to the UI.
- Vault writes are atomic (write temp → fsync → rename) with a versioned header, so a crash can't corrupt the only copy.
- Wrong-password attempts: increasing delay (the Argon2 cost already makes guessing slow).

**Recovery & portability of the software vault (rev 3).** DPAPI (CurrentUser) ties the wrapped key to one Windows user profile; the vault file alone **cannot** be opened on another PC or a reinstalled Windows. That is by design:
- The vault file is **not** a backup and is not copied to USB.
- Disaster recovery for a weak-mode wallet = **restore from its paper seed backup** into a fresh vault (or into any BIP-39 wallet).
- Test (Phase 2 gate): restore the weak-mode wallet from its seed on a **different Windows installation and user account**, and confirm the same addresses. Losing the vault file must never mean losing funds.

### 6.5 Recovery drills

| When | What |
|---|---|
| Before funding any wallet | Full restore of every seed on a clean device; compare addresses |
| Every 6 months | Restore **one** wallet (rotate which) and check balances in watch-only mode |
| After any change to multisig setup | Full 2-of-3 recovery test on testnet with the real devices |

**(rev 3) Every drill uses only what is stored at the backup locations** (seed plates, passphrase paper, USB copies, printed runbook), **on a machine without the custom app**, following the recovery manifest step by step. If any step needs something that isn't at a backup location, the drill fails and the manifest is fixed.

### 6.6 Recovery manifest per wallet (rev 3)

"Restore every seed" isn't enough when a wallet uses a passphrase, a multisig descriptor, a Safe or custom TRON permissions. Every wallet has a manifest (no secrets) stored on paper with each seed location and in the encrypted USB:

| Field | Example |
|---|---|
| Wallet ID, tier, networks | `vault-btc-2of3`, T-0, BTC |
| Script / account type | P2WSH 2-of-3 `sortedmulti` (BIP-48); or P2WPKH (BIP-84); or ETH EOA; or TRON account |
| Derivation path(s) & account index | `m/48'/0'/0'/2'` |
| Descriptor / contract / account config | Full descriptor with checksum; Safe address + version (if ever used); TRON permission baseline (§8.5) |
| Signers | Each key: device vendor/model, master fingerprint, which backup location holds its seed |
| Threshold | 2 of 3 |
| Passphrase dependency | "Yes, BIP-39 passphrase, stored at location C", or "No" |
| Expected first addresses | First 3 receive addresses (to confirm the restore is correct) |
| Recovery software | e.g. Sparrow Wallet ≥ version X (verified download), vendor app; for TRON/ETH single-sig: any BIP-39 wallet supporting the path |
| Recovery steps | Numbered steps that end with **spending** a small amount, not just seeing the balance |
| Last tested | Date + result |

For multisig and smart accounts, the drill must prove **ability to spend** (a small testnet or mainnet tx signed by the threshold), not just that the individual keys restore.

---

## 7. Transaction security pipeline

Every outgoing transaction passes through the same pipeline. Any stage failing → **stop** and show why.

```
 ① Draft ─▶ ② Validate ─▶ ③ Policy ─▶ ④ Build ─▶ ④b Chain validator ─▶ ⑤ Simulate ─▶ ⑥ Review
        ─▶ ⑦ Device sign ─▶ ⑧ Verify ─▶ ⑨ Broadcast ─▶ ⑩ Monitor
```

| Stage | What happens | Stops these threats |
|---|---|---|
| **① Draft** | Pick source wallet, asset+network, recipient (**from address book preferred**), amount. Pasting is allowed but flagged. | — |
| **② Validate** | Address checksum & format per network: bech32/bech32m (BTC), EIP-55 checksum (ETH), base58check `T…` (TRON). Reject cross-network addresses (e.g. TRON address for ERC-20 USDT). Amount is an integer in base units, > 0, ≤ balance minus fee. | Typos, wrong network (T9) |
| **③ Policy** | Tier flow rules (§4.2); allowlist check; limits per §7.4; **new-address cool-down** (e.g. 24 h for Savings, 48 h for Vault), measured in trusted time (§9.5); **look-alike check** against every address in history (same first 4 + last 4 chars but different = **block**). If the policy state can't be established as current (§9.5) → **no sends**. On success the core creates an immutable **Transaction Intent** (§7.3). | Address poisoning (T3), rushed decisions (T12), partial PC compromise (T1, T2) |
| **④ Build** | The core builds the unsigned tx **locally**: PSBT (BTC), EIP-1559 tx calling `transfer(to, amount)` on the **pinned** USDT contract (ETH), `TriggerSmartContract` on the **pinned** USDT contract (TRON). Nodes only supply inputs (UTXOs, nonce, recent block reference, fee data), each cross-checked. A node-built tx is never signed as-is. No `approve` ever (P13). | Fake tokens, approvals (T6), node-built tx tampering (T10) |
| **④b Chain validator** | The chain-specific validator (§8.1/8.2/8.3 "pre-sign validator") decodes the unsigned tx bytes and checks **every** field against the review intent and the fixed rules. Any unknown field, extra output or call → reject. | Malicious/confusing tx (T5, T15), own bugs (T9) |
| **⑤ Simulate** | ETH: `eth_estimateGas` + `eth_call` on ≥2 providers. TRON: `triggerconstantcontract` for energy estimate; check TRX available for fees. BTC: fee policy in §8.1. All fee checks follow the fee policies in §8 and the caps in §7.4; an override can raise a fee cap only up to its hard maximum and **never** skips any other check. | Lying RPC (T10), fee drain |
| **⑥ Review** | Review screen is generated **from the final unsigned tx bytes** (decoded again), not from the form inputs. Shows: wallet, network, asset, full recipient address (chunked `bc1q 7x9a …`), address book label, amount, fee, total, new-address warning. The core issues a **single-use `review_id`** bound to the Intent hash and the unsigned-tx hash, expiring after 120 s. Any change → new Intent, new review. A native OS dialog repeats the summary. **This stage is a bug-catcher and convenience, not an authorization control** (malware can fake both screens). | App bugs (T9), WebView-only compromise (T16) |
| **⑦ Device sign: THE authorization boundary** | Hardware wallet must show **network, asset or contract, full recipient address, amount and fee**. You compare **character by character** with your source of truth (§7.1): for your own wallets, an address you verified on *that wallet's* device; for outside recipients, the address confirmed out of band. **Never** against the PC screen alone. If **any** of these fields isn't shown clearly (truncated address, hex data, "blind signing" or "unknown contract" warning) → **reject**, and that workflow is disabled for that device (§11 Phase 0 matrix). Weak-mode software vault: password re-entry required, with no device protection. | Malware (T1), clipboard (T2), blind signing (T5) |
| **⑧ Verify** | Core decodes the signed tx and checks it matches the **Intent** and the reviewed unsigned tx field by field (recipient, amount, fee, nonce/inputs/ref-block), and that each signature verifies against the expected pubkey. Only then may the app broadcast. **Limitation:** this protects the app's own broadcast path; it can't stop malware that captures the signed tx and broadcasts it itself. That's why ⑦ is the boundary. | Compromised signer transport (T8), app bugs (T9) |
| **⑨ Broadcast** | Send to ≥2 independent providers (§5.5). Record txid. The txid must equal the one computed in ⑧. | Censorship/single provider failure |
| **⑩ Monitor** | Track confirmations on ≥2 sources. BTC: wait ≥ 3 confirmations for "done", ETH/TRON: finalized/solidified block. Write to audit log. | Fake "confirmed" (T10) |

### 7.1 Address book & allowlist

- Each entry: label, network, address, **added-at (trusted time, §9.5)**, **verified-by** (e.g. "checked with recipient by phone"), tier permissions, entry version.
- **Own wallets:** an address is added only after it is shown on **that wallet's own hardware device** ("verify address") and matches.
- **Outside recipients:** verified out of band (phone call, second channel, small test tx) and the method recorded. A device can't vouch for someone else's address.
- A new entry is usable only after its cool-down expires.
- **(rev 3) Integrity rules:**
  - **Edit = delete + new entry.** Changing an address, network or tier permission creates a new entry that needs fresh verification and a new cool-down. Only the label can change without one.
  - Every add/remove is part of the **policy state** (§9.5): versioned, anchored outside the PC, alerted by the monitor ("address added to Savings allowlist").
  - **Restoring a backup never restores trust.** Entries imported from any backup or older database come back as *unverified* and must be re-verified with a new cool-down. A removed address stays on a **revocation list** so an old snapshot can't bring it back silently.
- **Never** fill the recipient from transaction history with one click; history is exactly where poisoned addresses show up.

### 7.2 Receive flow

1. Select wallet + asset + network (network shown in large text: "USDT on **TRON (TRC-20)**").
2. Show address + QR. For hardware wallets: **"Verify on device"** button displays the same address on the device screen (stops malware from swapping the receive address).
3. Use a fresh BTC address each time (BIP-84 gap limit 20); ETH/TRON reuse the account address.
4. When a deposit arrives: show it with confirmations; ignore and **hide** 0-value / dust token transfers (poisoning attempts), and flag them in the activity log.

### 7.3 Transaction Intent & layer tests (rev 3)

**Intent:** an immutable record created at stage ③ and hashed (SHA-256 over a canonical encoding):
`{intent_id, wallet_id, chain, operation (enum, §8.0), recipient, amount_base_units, max_fee, nonce_or_inputs, policy_state_version, created_at_chain_time}`.

- Stages ④b and ⑧ compare the tx against the **Intent**, not against UI input or another stage's output.
- Nothing in an Intent can change. Any change (new fee, new UTXOs, new nonce) = new Intent, new review, **new device approval**.
- The Intent hash and outcome go to the audit log and the external checkpoint (§9.5).

**Recipient-substitution tests at every layer** (required suite, Phase 2/3): swap the recipient (and separately the amount and fee) at **builder**, **IPC**, **signer transport** (a test proxy between core and device) and **broadcast** layers. Expected result: caught by ④b/⑧, or visibly different on the device screen. Neither "silently signed" nor "silently broadcast" may happen.

### 7.4 Limits: units, scope and anti-bypass (rev 3)

| Rule | Definition |
|---|---|
| **Primary unit = the asset** | Every limit is set in the asset's base units: sats (BTC), USDT base units (6 decimals), wei (ETH), sun (TRX). These need no price feed and always work. |
| Secondary unit = INR | An INR-equivalent limit is also checked, using the **higher** of two independent price sources (conservative). If prices are unavailable or disagree by > 3%, only the asset limits apply **and** the INR limit is treated as already reached (no sends that need it). |
| Scopes (all apply at once) | Per transaction · per wallet per rolling 24 h · per tier per rolling 24 h · **global aggregate** across all wallets per rolling 24 h · per recipient per rolling 24 h. |
| Splitting | Splitting a payment over several transactions, wallets or Spending wallets doesn't help: the per-tier, global and per-recipient totals still apply. |
| Fees | Max fee per transaction (asset units + INR) and max total fees per 24 h. |
| Time | Rolling windows measured in trusted time (§9.5), never the Windows clock alone. |
| Fail closed | If the policy state, its version or trusted time can't be established → no sends. |
| Honest scope | These limits stop mistakes and rushed decisions. **Malware with full PC control can skip them**; the hard cap against that is the balance held in each hot wallet + device approval + the monitor. |

### 7.5 Signer errors, disconnects and cancellation (rev 3)

| Event | Behavior |
|---|---|
| Device disconnects / times out | The Intent is marked *aborted*. Nothing is broadcast. The user restarts from stage ③, which creates a new Intent. |
| User rejects on device | Intent *rejected*; logged; no automatic retry. |
| Partial signature (e.g. some BTC inputs unsigned) | Discard; never broadcast; logged as an error. |
| Signed tx fails ⑧ | **Critical**: discard, lock signing for that wallet, alert the monitor, start the incident runbook (the device or transport may be compromised). |
| Retry policy | **No automatic retries with changed fields.** A retry is a new Intent with a new device approval. Re-sending the *same* signed tx after a network error is allowed (same txid). |
| Already signed but not broadcast | Signed blobs are never written to disk. On app exit they are erased; a new send needs a new Intent. |
---

## 8. Chain-specific rules

### 8.0 Operation registry (rev 3)

Signing is driven by a **closed list** (a Rust `enum` with no "other" variant). **Every operation has its own validator and its own negative tests; there is no generic `sign_transaction()` and no fallback for unrecognised types.**

| Operation | Validator | Allowed tiers (custom app) | v1 status |
|---|---|---|---|
| `BtcSend` | §8.1 | Spending, Savings* | Enabled |
| `BtcRbfBump` | §8.1 (fee policy, RBF) | Spending, Savings* | Enabled |
| `EthUsdtTransfer` | §8.2 | Spending, Savings* | Enabled |
| `EthNativeTransfer` (fee top-up / cancel) | §8.2b | Spending, Savings*; **destination = own allowlisted wallet only** | Enabled |
| `TronUsdtTransfer` | §8.3 | Spending, Savings* | Enabled |
| `TronNativeTransfer` (fee top-up) | §8.3b | Spending, Savings*; **destination = own allowlisted wallet only** | Enabled |
| `SafeExecTransaction` | §8.4 (spec only) | — | **Not in v1** |
| `TronMultisigTransfer` / `AccountPermissionUpdate` | §8.5 (spec only) | — | **Not in v1** |
| Anything else (`approve`, `permit`, typed data, 7702, swaps, staking …) | none | — | **Rejected, no code path** |

\* Savings only when the §15 independent review has passed (release configuration, §15). Vault is **never** signed by the custom app in v1 (§4.1b).

Cross-tier native transfers follow §4.2: downward only to the next tier's own allowlisted address, upward always allowed. Each has the same limits (§7.4) as USDT, in the native asset's units.

### 8.1 Bitcoin

- Native SegWit (`bc1q`) for single-sig; P2WSH 2-of-3 multisig via descriptors for the Vault.
- **Vault multisig:** 3 hardware wallets, **ideally from at least 2 different vendors** (a bug or backdoor in one vendor can't reach 2 of 3 keys). Coordinator = this app (via BDK) + one independent coordinator you can use for recovery (e.g. Sparrow Wallet), so you're never dependent on your own code.
- Coin control: show UTXOs; avoid merging Vault UTXOs with Savings ones.
- Change output must go back to an address **derived from the same wallet descriptor** — verified in stage ⑧ (hardware wallets also check this).
- RBF (replace-by-fee) enabled so a stuck tx can be bumped. No unconfirmed-input spending from outside sources.

**Pre-sign validator — BTC (rev 2).** Runs on the final PSBT; every check must pass:

| Check | Rule |
|---|---|
| Network | Mainnet addresses and descriptor only (no testnet keys on mainnet and vice versa). |
| Inputs | Every input belongs to **this wallet's descriptor** (script matches a derived address). Each input carries the **full previous transaction** (`non_witness_utxo`) as well as `witness_utxo`, and the prevout amount is checked against it. This defends against fee-lying attacks on SegWit inputs. |
| Outputs | Exactly **one recipient output** + at most **one change output**. No `OP_RETURN`, no extra outputs, no dust outputs. Recipient script == reviewed address. |
| Change | Change script is derived from the **same descriptor** on the internal (`/1/*`) chain, and the PSBT includes its `bip32_derivation` so the **device recognises it as change** and doesn't show it as a payment. If the device shows the change as an external output → reject. |
| Outpoints (rev 3) | For each input: `txid(non_witness_utxo) == outpoint.txid` (recomputed locally); the referenced output's **amount and script** are read from that tx; the script is derived from **this descriptor** at the PSBT's stated path (re-derived locally, not trusted from the PSBT); the outpoint is **unspent** per your own node (or ≥2 independent sources until the node exists, §5.5). |
| Fee | Fee = Σinputs − Σoutputs, **computed locally** (never taken from a provider). Must satisfy the fee policy below. |
| Fields | Version 2; locktime 0 or current height; sequence signals RBF; no unknown PSBT fields from outside sources. |
| Signing | Device signs with `SIGHASH_ALL` (default) only. |
| After signing (rev 3) | Every input's signature is verified against its expected pubkey and sighash; the PSBT is finalized locally; the **final transaction** is checked once more (same outputs, same fee, same txid as computed) and run through `bitcoinconsensus` script verification before broadcast. |

**BTC fee policy (rev 3):**

| Item | Rule |
|---|---|
| Fee-rate bounds | ≥ min relay fee, ≤ max(3× median of independent estimates, a configured "urgent" rate). Estimates come from your node's `estimatesmartfee` + one external source. |
| Absolute cap | Per-tx fee ≤ the asset-unit cap in §7.4 (e.g. 100,000 sats) **and** ≤ 2% of the amount for normal sends. |
| Override | Allowed only for Spending/Savings, requires typed confirmation, and can raise the fee up to a **hard maximum** (e.g. 300,000 sats). An override changes **only** the fee limit; every other validator rule still runs. It's logged and alerted by the monitor. |
| RBF bump (`BtcRbfBump`) | Same inputs (may add own inputs), **same recipient output and amount**; the only change is a smaller change output and a higher fee. The new fee must satisfy the policy. It is a new Intent and needs a new device approval. |
| CPFP | Not supported in v1. |

**Signer change recognition** is tested per device and firmware in the Phase 0 compatibility matrix; a device that shows change as a payment can't be used for that wallet type.

**xpub privacy (rev 2).** xpubs reveal your full address history and balance:
- Stored only in the encrypted part of the data store and in the encrypted USB, never in plain files.
- **Never sent to third-party providers.** The app queries individual addresses, and from Phase 1 your own Bitcoin Core node where practical (§5.5).
- Alerts and logs never contain xpubs or addresses (§10.1).

### 8.2 USDT on Ethereum (ERC-20)

- **Pinned contract:** `0xdAC17F958D2ee523a2206206994597C13D831ec7` (chain ID 1). Any other "USDT" is treated as a fake. **(rev 3)** The address lives in the versioned, signed **network configuration** (§9.6), not in code constants scattered around. Before each release it's re-verified from ≥3 independent sources (Tether's official transparency page, Etherscan's verified-contract page, and the bytecode hash read from your RPC sources), and the check is recorded in `release-gate.md`.
- USDT's ERC-20 `transfer` **does not return a bool** (non-standard). Success is judged by the receipt status **and** the `Transfer` event log, not by a return value.
- Only `transfer` is supported. **No `approve`, no `permit`, no arbitrary contract calls.** The app also watches existing allowances and alerts on any non-zero one.
- Gas is paid in ETH: keep a small ETH balance per sending wallet; the app warns when it's too low.
- EIP-1559 with a **max fee cap**; chain ID enforced (EIP-155) so a tx can't be replayed on another network.
- Vault option (deferred, **not v1**): hold Vault USDT in a **Safe** 2-of-3 smart account. It needs its own validator (§8.4).

**Pre-sign validator — ERC-20 USDT (rev 2).** ERC-20 transfers and approvals are different operations and are never treated alike. Only this exact shape is signable:

| Field | Rule |
|---|---|
| Tx type | **Type 2 (EIP-1559) only.** Reject legacy (0), type 1, blob (3) and **type 4 (EIP-7702 set-code)** transactions. |
| `chain_id` | `== 1` (Ethereum mainnet). |
| `to` | `==` pinned USDT contract (byte-exact, not by symbol or name). |
| `value` | `== 0` (no ETH attached). |
| `data` | Exactly **68 bytes**: selector `0xa9059cbb` (`transfer(address,uint256)`) + 32-byte recipient (upper 12 bytes zero) + 32-byte amount. Any other selector, including `approve` `0x095ea7b3`, `transferFrom`, `permit`, multicall → reject. |
| Recipient (decoded) | `==` reviewed recipient; not the zero address; not the USDT contract itself; not one of your own addresses on a different tier unless the tier rules allow it. |
| Amount (decoded) | `==` reviewed amount in base units (6 decimals, read from the pinned config, not from the RPC). |
| `nonce` | Per the nonce reconciliation rules below. |
| `gas_limit` | ≤ cap (e.g. 100,000; USDT transfers normally need far less). |
| Final check (rev 3) | After signing: recover the sender from the signature (must equal this wallet), re-decode recipient and amount **from the signed RLP** and compare with the Intent. |
| `max_fee_per_gas`, `max_priority_fee_per_gas` | ≤ caps; total max fee in ₹ ≤ the fee cap. |
| `access_list` | Empty. |

**Never signed on Ethereum (rev 2):** `personal_sign` messages, `eth_signTypedData` / EIP-712 (this blocks `permit` and Permit2 signatures), EIP-7702 authorizations. The app has no code path for them at all.

**Nonce reconciliation (rev 3):**

| Situation | Rule |
|---|---|
| Normal | `expected_nonce` = confirmed nonce (`eth_getTransactionCount(addr, "latest")`) from ≥2 independent providers (§5.5) **and** = last confirmed nonce in the audit log + 1. |
| Pending tx from this app | Tracked by Intent. A new send waits until it confirms, or replaces it explicitly. One pending tx per wallet at a time in v1. |
| **Confirmed nonce higher than the audit log expects** | A transaction you didn't send through this app exists → **critical alert, signing disabled** for that wallet until investigated (it may be a compromise or a use of the seed elsewhere). |
| `pending` count differs between providers | Mempools may differ; **wait and re-check**. Never pick the higher or lower value to "make it work". If still inconsistent after N minutes → stop. |
| Speed-up | Same nonce, **same calldata** (same recipient and amount), higher fees within the fee policy = new Intent + new device approval. |
| Cancel | Same nonce, `EthNativeTransfer` of **0 ETH to the wallet's own address** (§8.2b), higher fees = new Intent + device approval. |

**Separate allowance & delegation checks (rev 2, discovery defined in rev 3).** A safe transfer says nothing about older approvals. Allowance monitoring is a **detection** control; it can't stop an existing allowance from being used.

| Step | Procedure |
|---|---|
| Baseline (before funding) | Wallet must have **confirmed nonce 0** (never sent a tx) → no allowance can exist (USDT on Ethereum has no `permit`, so an allowance needs an on-chain `approve` from you). For an older address: index **all** `Approval(owner = you)` logs on the USDT contract since the address's first transaction, read `allowance()` for each spender found, and require all to be 0. Cross-check manually with Etherscan's token-approval checker. |
| Ongoing | The independent monitor (§10) subscribes to and polls `Approval` logs with `topic1 = your address` on the pinned contract, and also alerts on **any outgoing tx whose nonce isn't in the audit log** (an `approve` needs a nonce). |
| Gap recovery | The monitor stores the last fully scanned block. After any outage it rescans from there; it never skips ahead. A scan with errors doesn't advance the marker. |
| After suspected compromise | Full rescan from the first block + manual Etherscan check; revoke from a clean device. |

**Delegation (EIP-7702) check (rev 3):** `eth_getCode` for each address is checked by the monitor on ≥2 independent providers. Any non-empty result (a `0xef0100…` delegation designator or anything else) → **critical alert and signing disabled** for that wallet. A single provider's result triggers an investigation, not a conclusion. Signing resumes only after you verify independently (e.g. on Etherscan and your own query).

#### 8.2b Pre-sign validator — native ETH transfer (rev 3)

Used only to top up gas between your own wallets, or to cancel a pending tx.

| Field | Rule |
|---|---|
| Tx type / `chain_id` | Type 2 only / `== 1`. |
| `to` | An **own wallet** address in the allowlist (top-up), or this wallet's own address (cancel). The destination must have **empty code** (checked as in the delegation check). |
| `value` | `>0` and ≤ native top-up cap (e.g. 0.05 ETH) for top-ups; `== 0` for cancel. |
| `data` | **Empty.** |
| `gas_limit` | **Exactly 21,000.** |
| Fees / nonce | Same caps and nonce rules as USDT. |
| `access_list` | Empty. |
| Tier rule | §4.2 flow rules; counts toward §7.4 limits in wei. |
| Tests | Same negative suites as USDT: wrong `to`, non-empty data, wrong gas limit, chain ID, type 4, substituted recipient. |

### 8.3 USDT on TRON (TRC-20)

- **Pinned contract:** `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`. Verify against Tether's official site and Tronscan before pinning.
- Fees: energy + bandwidth. If the account has no staked energy, TRX is **burned** to pay. Warn when TRX is too low, and show estimated burn before signing. Consider staking TRX for energy on the Spending wallet.
- **Permission watch (critical for TRON):** TRON accounts have owner/active permissions. Attackers who get a key once often add their own key as owner. The **independent monitor** (§10) validates the **entire permission object** of every wallet continuously against the policy in §8.5; any deviation = critical alert and signing disabled.
- **TRC-20 approvals (rev 3):** TRC-20 USDT also has `approve`. The monitor indexes `Approval` events with owner = your address, the same way as for Ethereum (§8.2), and alerts on any outgoing tx the audit log doesn't know.
- **Address poisoning is especially common with TRC-20 USDT**; the look-alike check in stage ③ is mandatory here.
- `TriggerSmartContract` with `fee_limit` capped (e.g. 30 TRX, tune in testing).
- Vault option (deferred, **not v1**): TRON native multi-signature via account permissions. It needs the full policy in §8.5, a tested emergency procedure and an independent review first.

**Pre-sign validator — TRC-20 USDT (rev 2; construction decided in rev 3).** TRON nodes offer endpoints that *build* a transaction for you (`/wallet/triggersmartcontract`). **Decision (rev 3): the signing path uses local construction only.** Node endpoints are used only for read-only estimates (`triggerconstantcontract` for energy) and for fetching block references; their output is never signed, even after checking. The local protobuf encoder is generated from TRON's official `.proto` files at a pinned version. The decoder used by the validator **rejects unknown fields and unknown contract types**. TRON's own documentation separates building, local signing and broadcasting; private keys are **never** sent to a node or API (no `gettransactionsign`-style endpoints).

| Field | Rule |
|---|---|
| Network | Mainnet; reference block confirmed by ≥2 nodes. |
| `raw_data.contract` | Exactly **one** contract, type `TriggerSmartContract`. |
| `contract_address` | `==` pinned USDT. Compared in **hex** form (`41` + 20 bytes), after converting the pinned Base58 address with a tested Base58Check routine (the round-trip `Base58 → hex → Base58` must reproduce the original). |
| `owner_address` | `==` this wallet's address. |
| `call_value`, `call_token_value` | `== 0`. |
| `data` | Selector `0xa9059cbb` + recipient word + amount word; **68 bytes exactly**. Recipient = last 20 bytes of word 1, prefixed with `0x41` → Base58Check `==` reviewed recipient. Amount `==` reviewed amount. |
| `fee_limit` | ≤ cap (e.g. 30 TRX). |
| `expiration` | Within `now + 60 s … now + 10 min`; a far-future expiration would let a signed tx be held and replayed later. |
| `ref_block_bytes`, `ref_block_hash` | Match a recent **solidified** block fetched from ≥2 nodes. |
| `Permission_id` | Absent/0 (owner). v1 accounts use the default single-key permission layout (§8.5), so no other ID is valid. And the account's **current** on-chain permission object must still equal the §8.5 baseline at signing time (checked on ≥2 sources); otherwise → reject. |
| `raw_data.data` (memo) | Empty. |
| `txID` | Recomputed locally as `SHA-256(raw_data)`. It must match the ID that is signed and later broadcast. |
| Final check (rev 3) | After signing: recover the signer's address from the signature (must equal `owner_address`); re-decode the signed `raw_data` and compare with the Intent. |

Also never signed on TRON: `AccountPermissionUpdateContract` (except in a separate, offline-reviewed recovery procedure), `TransferContract` to non-allowlisted addresses, freeze/delegate/vote contracts (not needed in v1).

#### 8.3b Pre-sign validator — native TRX transfer (rev 3)

Used only to top up TRX for energy/bandwidth between your own wallets.

| Field | Rule |
|---|---|
| `raw_data.contract` | Exactly one, type **`TransferContract`**. |
| `owner_address` | `==` this wallet. |
| `to_address` | An **own wallet** in the allowlist (hex `41…` ↔ Base58 round-trip checked); not this wallet itself. |
| `amount` | `>0` and ≤ native top-up cap (e.g. 200 TRX), in sun. |
| `expiration`, `ref_block_*`, `Permission_id`, memo, `txID` | Same rules as the TRC-20 validator. |
| `fee_limit` | Absent/0 (not used by `TransferContract`). A non-zero value is rejected as unexpected. |
| Tier rule | §4.2; counts toward §7.4 limits in sun. |
| Tests | Wrong contract type, wrong `to`, substituted recipient, far-future expiration, wrong ref block, non-zero `Permission_id`. |

### 8.4 Safe (Ethereum smart account): specification for later, **not in v1** (rev 3)

The ERC-20 validator correctly rejects Safe transactions; Safe signing is a different operation. Before `SafeExecTransaction` can exist, all of this must be specified, implemented, tested and independently reviewed:

- **Account checks:** the Safe address; proxy → **singleton/implementation address** equals an official, pinned Safe release; **owners** set and **threshold** equal the recorded config; **modules** list empty; **guard** unset (or equal to a pinned, reviewed guard); **fallback handler** equals the pinned official one.
- **Transaction checks (`SafeTx`)**: `to == pinned USDT`, `value == 0`, `data` = exact 68-byte `transfer`, **`operation == 0` (CALL; `DELEGATECALL` always rejected)**, `safeTxGas/baseGas/gasPrice == 0`, `gasToken == 0`, `refundReceiver == 0`, `nonce ==` the Safe's current on-chain nonce. The EIP-712 Safe tx hash is recomputed locally.
- **Device display:** each signer's device must show the decoded `SafeTx` clearly; it must not ask to blind-sign a hash.
- **Recovery:** spend from the Safe using only 2 seeds + the recorded Safe address, **without this app** (Safe's own UI or CLI), on testnet and then with a small mainnet amount.
- **Monitoring:** owner/threshold/module/guard changes are critical alerts.

### 8.5 TRON permission policy (rev 3)

**v1 baseline (single-sig wallets), validated by the monitor and before every signature:**

| Element | Required value |
|---|---|
| `owner_permission` | `threshold == 1`; exactly **one** key = this wallet's own address; weight 1. |
| `active_permission` | Exactly **one** entry, `id == 2`, `threshold == 1`, exactly one key = this wallet's own address, weight 1. Its `operations` mask equals the recorded default mask from wallet creation. |
| `witness_permission` | Absent. |
| Any other entry / key / threshold / weight | Deviation → **critical alert, signing disabled**. |

**Permission updates:** the custom app **cannot** build `AccountPermissionUpdateContract`. A permission change is an **emergency procedure** (`docs/incident-runbook.md`): done from a clean machine with the official tools, then re-baselining the monitor.

**TRON multisig (deferred, not v1)** requires first: a written target layout (owner and active keys, weights, thresholds, operation masks), a validator for `Permission_id`-based multi-signature transactions, device display tests, a tested **emergency recovery procedure** (losing one key; a hostile permission change), and an independent review.

---

## 9. Application & OS hardening

### 9.1 Tauri / UI

- **CSP:** `default-src 'self'; script-src 'self'; connect-src ipc: http://ipc.localhost; img-src 'self' data:; style-src 'self'; object-src 'none'; frame-ancestors 'none'`. All RPC traffic goes through the Rust core, so the web view needs **no** external network access.
- Tauri **capabilities**: enable only the custom commands; no shell, no arbitrary fs, no http plugin in the UI.
- No `dangerouslySetInnerHTML`; render token names/memos as plain text (token metadata is attacker-controlled).
- IPC commands are few, typed and validated in Rust: `list_wallets`, `get_portfolio`, `get_receive_address`, `prepare_transfer`, `submit_reviewed_transfer(review_id)`, `lock`, … Nothing like `sign(bytes)` or `export_key`.
- Clipboard: the app copies addresses only on explicit click and clears the clipboard after 60 s; it never reads the clipboard silently.
- Screenshot protection on secret screens (T-2 seed display) using `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`.

**Native command boundary (rev 2).** Rust commands are not safe just because they're Rust; a compromised WebView can call any command it is allowed to. So:

| Control | Detail |
|---|---|
| Minimal command set | ≤ ~12 registered commands, listed in `commands.rs`. CI fails if a new `#[tauri::command]` appears without being added to the reviewed list. |
| Capabilities | One capability file for the single `main` window; only the app's own commands; **no** `remote` URLs; no shell, fs, http, process, updater or opener plugins exposed to the UI. |
| Isolation pattern | Tauri's **isolation pattern** enabled, so every IPC message passes through a sandboxed isolation script that can reject unexpected commands/arguments before they reach Rust. |
| State machine | The core tracks state: `locked → unlocked → prepared(review_id) → awaiting_device → done`. A command called in the wrong state is rejected and logged (e.g. `submit` without a fresh `prepare`). |
| Validation | Every argument is parsed into strong types in Rust (address, amount, wallet ID). The UI never sends raw tx bytes, derivation paths, contract addresses or fee values that bypass policy. |
| No remote code | CSP as above + `require-trusted-types-for 'script'`; no `eval`/`new Function`; `withGlobalTauri` off; navigation to any non-app URL blocked; new windows blocked; DevTools disabled in release builds. |
| Out-of-WebView approval | The hardware device is the authorization boundary (§7 ⑦). The native OS dialog only stops a WebView-only compromise from starting a device request silently; it is not a security boundary against PC malware. |
| Rate limits | Failed unlocks and rejected commands are counted; repeated failures lock the app and raise an alert. |

### 9.2 Rust core

- `#![forbid(unsafe_code)]` in all crates except thin, reviewed FFI wrappers.
- Secrets in `secrecy::SecretBox` + `zeroize`; never `Debug`/`Display`-printable; never cloned into `String`.
- `Amount` is a newtype over `u128` with checked arithmetic; overflow = error.
- Errors shown to the UI never include secret material or raw payloads.
- Hash-chained audit log: each entry includes `SHA-256(previous_entry)`; verified at startup. **It is not tamper-proof.** What it can and can't detect is listed in §9.5.

**Error handling & secret hygiene (rev 2):**

| Leak path | Control |
|---|---|
| Logs | Logging only through redacting types: secret, address and amount types implement `Debug` as `[REDACTED]` / shortened. Raw tx bytes are not logged in release builds. |
| Panics | `panic = "abort"` in release; a custom panic hook writes only the location, never the payload. |
| Windows crash dumps | The app process is excluded from Windows Error Reporting dumps (`WerAddExcludedApplication`), and no `LocalDumps` are configured for it. |
| Page file / hibernation | Secret buffers held in `VirtualLock`-ed memory (small reviewed wrapper, the only `unsafe` allowed). BitLocker encrypts page and hibernation files at rest; hibernation is disabled on the wallet PC. |
| UI errors | Error messages sent to the UI are fixed codes + safe text, never formatted from internal values. |
| Test | An automated test runs every flow on testnet, then scans logs, the database, the temp folder and a forced crash dump for seed words, keys and passwords (§11 Phase 2 gate). |

### 9.3 Supply chain

- `Cargo.lock` and `package-lock.json` committed; `cargo deny` (licenses, advisories, banned/duplicate crates), `cargo audit`, `npm audit` in every build.
- Minimal npm dependencies in the UI; **no** blockchain JS libraries in the web view.
- Hardware-wallet SDK pinned to an exact, reviewed version and **vendored**, never loaded at runtime from a CDN. (In December 2023, a hijacked Ledger Connect Kit npm release drained users of dApps that loaded it dynamically. This is the exact pattern to avoid.)
- Build reproducibly from a clean checkout; sign the Windows installer with your own code-signing certificate (or at least record and verify its SHA-256 hash).
- **No auto-updates** until Phase 6. Updates are installed by hand after you build them yourself.

**Build environment & release integrity (rev 2):**

| Control | Detail |
|---|---|
| Protected build environment | Release builds run in a **dedicated build VM / Windows user** that is used for nothing else; not the wallet account, not your daily account. |
| Locked builds | `cargo build --locked --release`; `npm ci --ignore-scripts` (no install scripts run); toolchain pinned with `rust-toolchain.toml`. |
| Dependency updates are reviewed | No blanket `cargo update` / `npm update`. Each update is a separate change; read the changelog and diff for crates in the signing path (`bitcoin`, `bdk`, `alloy`, `bip39`, crypto crates). Consider `cargo vet` to record which versions were reviewed. |
| Two-build check | Build the release twice (clean VM each time) and compare SHA-256 hashes of the core binary; investigate any difference. |
| Signed releases | Installer signed with a code-signing certificate whose private key lives on a **hardware token**. The SHA-256 of every release is written to the audit log and on paper. |
| Install-time check | Before installing on the wallet PC: verify the signature and hash against the paper record. |
| Updates (Phase 6 only) | If the Tauri updater is ever enabled: its signing key is generated and kept **offline** (encrypted USB, not on the build VM). The app verifies the update signature, refuses **downgrades**, and asks before installing. |
| (rev 3) Build evidence kept | A clean dependency scan doesn't prove a build is trustworthy. For each release, `docs/releases/<version>/` keeps: the reviewed source commit hash, toolchain versions (`rustc`, `cargo`, `node`, `npm`, Tauri CLI), hashes of `Cargo.lock` / `package-lock.json`, the scan outputs, build logs from both builds, installer + core binary SHA-256, and the reviewer's report. |
| (rev 3) Operational separation | You are both developer and operator, so a release you change can't be silently treated as reviewed. The reviewer's report names the **exact commit and installer hash** they reviewed, and the reviewer keeps their own copy. Before installing on the wallet PC you compare the installer hash with **the reviewer's copy** (not just your own notes). Any rebuild, patch or config change after review = **unreviewed release** → the §15 release configuration falls back to "no custom signing for Savings". |
- Download wallets, VeraCrypt, Sparrow etc. only from official sites, and verify signatures/hashes.
- Buy hardware wallets **directly from the manufacturer**, never second-hand or from marketplaces. Check the device-authenticity check on first use.

### 9.4 Windows PC hardening

| Control | Setting |
|---|---|
| Dedicated account | A separate **standard (non-admin)** Windows user just for the wallet. Ideally a dedicated PC/laptop used for nothing else. |
| Disk | BitLocker (or Device Encryption) on. |
| Sign-in | Windows Hello PIN/biometric + strong password. |
| Updates | Windows Update automatic; reboot promptly. |
| Defender | Real-time protection, **Controlled folder access** on the app data folder, Smart App Control or WDAC if available. |
| Software | No pirated software, no game cheats/cracks, no unknown browser extensions, no remote-desktop tools (AnyDesk/TeamViewer) on the wallet account. |
| Browser | Wallet account does **no** general browsing or email. |
| Network | Home network with WPA3/WPA2; no public Wi-Fi for signing. |

### 9.5 Policy state integrity, anti-rollback and trusted time (rev 3)

**Separate policy store.** Security-critical state lives in its own store, `policy.db`, apart from portfolio data (`portfolio.db`, rebuildable from the chain):
allowlist + revocation list, cool-down start points, rolling-limit counters, per-wallet last nonce / last Intent, the active policy settings, and the release configuration (§15).

**Versioned state + external checkpoints:**
1. Every change (and every send) increments a monotonic `policy_seq` and computes `state_hash = SHA-256(seq ‖ canonical(policy) ‖ prev_state_hash)`.
2. The app sends a **checkpoint** `{seq, state_hash, event summary}` to the independent monitor (§10.0), authenticated with a per-install key. The monitor keeps an **append-only** list and **rejects** any checkpoint whose `seq` isn't greater than its last one.
3. Before every send, the app fetches the monitor's latest checkpoint. Local `seq/hash` **must equal** it. If local is older (a restored snapshot) → **rollback detected → fail closed**. If the monitor can't be reached → **no sends** (watch-only still works).
4. The monitor alerts on policy changes ("allowlist add", "limit raised"), so changes you didn't make become visible.
5. Paper fallback: after each policy change, write `seq` + the first 12 hex characters of `state_hash` in the paper log kept with the runbook. This lets you re-establish trust if the monitor is rebuilt.

**What this detects and what it doesn't. It is not called tamper-proof:**

| Detected | Not detected / not prevented |
|---|---|
| Accidental corruption, partial edits, broken hash chain | Malware with full PC control that ignores the policy entirely and gets you to approve on the device. The device check (§7 ⑦) is the defense |
| Restoring an older `policy.db` / database snapshot (rollback) | Malware that makes a *new* policy change and sends a fresh, valid checkpoint. **But** the monitor alerts on that change, so you see it |
| Edits made while the monitor already has a newer checkpoint | Compromise of both the PC and the monitor at once |
| Cool-down reset by changing the Windows clock | — |

**Trusted time.** The Windows clock is **not** trusted for cool-downs, rolling limits or Intent expiry. "Time" means **both**:
- **chain time**: Bitcoin block height from your own node (e.g. a 24 h cool-down = ≥ 144 blocks *and* ≥ 24 h of median-time-past), and
- **monitor time**: the monitor's timestamp on the checkpoint that started the cool-down.

A cool-down counts as elapsed only when both agree. If either is unavailable → treat as **not elapsed**.

### 9.6 Configuration integrity (rev 3)

| Config | Protection |
|---|---|
| **Network config** (`config/networks.v1.toml`): chain IDs, token contracts + decimals, provider list + independence notes, enabled operations (§8.0), default caps | Versioned file; reviewed with the code; **signed with the offline release key**; its hash is compiled into the binary. The app refuses to start if signature or hash don't match. Changes only through a new reviewed release. |
| **User policy** (`policy.db`): limits, cool-downs, tier caps | Part of the checkpointed policy state (§9.5). **Lowering** a limit applies immediately. **Raising** a limit, enabling weak mode or adding an operation for a tier needs a 48 h cool-down (trusted time) + monitor alert. |
| **Signer config**: which device/fingerprint signs which wallet | Part of the policy state; a change counts as raising a limit (cool-down + alert). The core rejects signatures from an unexpected fingerprint/pubkey. |

### 9.7 Safe failure on corruption (rev 3)

If `policy.db`, the audit log, the checkpoint check, the network config or the wallet inventory is corrupted or inconsistent:
- **Signing stops.** Watch-only features keep working.
- The app **never rebuilds security policy from untrusted data** (portfolio DB, tx history, an old backup, or the UI).
- Recovery: a checkpoint holds only a hash, so the content can't be rebuilt from it. Instead you perform an explicit **policy reset**: start from default (strictest) limits and an empty allowlist; the monitor records it as a "reset" checkpoint and alerts; then re-add entries. Any entries imported from an old copy come back as **unverified** (§7.1), and every cool-down restarts. The monitor checkpoint and the paper log are used to confirm *which* local copy (if any) is current, never as a source of policy content.

---

## 10. Monitoring & incident response

### 10.0 Independent monitor (rev 3)

Checking state "on each app refresh" on the wallet PC is **not** monitoring. If the PC is off, offline or compromised, those alerts are silent or forged. So monitoring is a **separate system**:

```
┌──────────── Wallet PC ────────────┐        ┌────────── Monitor device (separately administered) ──────────┐
│ Custom app (may be compromised)   │──────▶ │ Watch-only watcher: addresses/xpubs, baselines, checkpoints  │
│ sends: signed policy checkpoints  │  one-  │ Pruned Bitcoin Core + external ETH/TRON sources (§5.5)       │
│ (§9.5); never receives commands   │  way   │ NO keys, NO signing, NO ability to move funds                │
└───────────────────────────────────┘        └──────────────┬───────────────────────────────┬───────────────┘
                                                            │ alerts + daily heartbeat      │
                                                   ┌────────▼─────────┐          ┌──────────▼──────────────┐
                                                   │ Channel 1:       │          │ Channel 2 (independent):│
                                                   │ Telegram bot     │          │ email; plus explorer    │
                                                   │ to your phone    │          │ address-watch alerts    │
                                                   └──────────────────┘          └─────────────────────────┘
```

| Requirement | Design |
|---|---|
| Separate system | A small always-on device you administer separately: e.g. a Raspberry Pi 5 + SSD at home (also runs the pruned Bitcoin Core node), or a small cloud VM. Different OS account and passwords from the wallet PC. **Never** used for browsing. |
| Strictly watch-only | It holds only public addresses, xpubs (encrypted at rest), permission baselines and checkpoints. It has no signing keys and **no code path to build or sign transactions**. |
| Continuous | Polls every chain every ≤ 2 minutes, independently of the wallet PC: outgoing tx, unknown nonces, ERC-20/TRC-20 `Approval` events, Ethereum code/delegation, full TRON permission objects, balances above caps (weak-mode cap, §6.4). |
| Alert channels | Two channels that don't depend on the wallet app: Telegram bot + email. As a **third, independent** layer, also register the most important addresses with block-explorer address-watch notifications where available. |
| Heartbeat (dead-man switch) | Daily "monitor alive, last block scanned X" message. **No heartbeat = treat as an alert.** Missed scans are back-filled (§8.2 gap recovery). |
| Alert content | Wallet label, event type, amount, txid. **No** seeds, keys, xpubs or full inventory; addresses only as a short form (`TR7N…Lj6t`). |
| Tested offline | The Phase 1 gate tests alerts **with the wallet PC switched off**. |

**If the monitor itself is compromised:** an attacker learns your addresses/xpubs (privacy loss) and can suppress or fake alerts. They **cannot** move funds. Mitigations: explorer address-watch alerts as an independent backup channel, the heartbeat, quarterly manual spot checks on public explorers, and rebuilding the monitor from scratch if its integrity is doubted. **If the Telegram/email account is compromised:** alerts may be read or deleted; use 2FA on both and keep both channels. Losing one channel must not silence the other.

### 10.1 What the monitor watches (watch-only, no secrets)

| Event | Severity | Alert |
|---|---|---|
| Any outgoing tx from **Vault** or **Savings** | Critical | Windows notification + Telegram bot / email |
| Outgoing tx from Spending above normal pattern | High | Notification |
| New ERC-20 allowance from any wallet | Critical | Notification |
| TRON account permission change | Critical | Notification |
| Code appears on one of your Ethereum addresses (EIP-7702 delegation, `0xef0100…`) | Critical | Notification + sending disabled |
| Rejected/out-of-state native commands, or a validator rejection (§7 ④b) | High | Notification (may mean the UI or an RPC is compromised) |
| Incoming 0-value / dust transfer from a look-alike address | Info | Logged, hidden from main view, address flagged |
| RPC providers disagree on balance/nonce | Medium | Sending disabled until resolved |
| Audit-log hash chain broken / address book edited outside the app | Critical | App refuses to send |
| (rev 3) Policy checkpoint from the PC is **older** than the monitor's latest (rollback) | Critical | Monitor alert; the app fails closed (§9.5) |
| (rev 3) Allowlist entry added/removed, policy or network config changed, fee override used | High | Monitor alert ("Savings allowlist: new address added") |
| (rev 3) Any outgoing tx whose nonce/txid isn't in the latest checkpoint | Critical | Monitor alert |
| (rev 3) Weak-mode or Spending wallet balance above its cap | High | Monitor alert |
| (rev 3) Monitor heartbeat missing | High | Treated as an alert by you |

Telegram/email alerts contain **only** wallet label + amount + txid. No addresses, no balances.

### 10.2 Incident runbook (summary; full version in `docs/incident-runbook.md`)

| Situation | Immediate action |
|---|---|
| Unexpected outgoing tx from a **single-sig** wallet | Assume its seed is compromised. From a **clean device**, move remaining funds to a **fresh** wallet with a **new seed**. Don't reuse anything from the old wallet. |
| Unexpected outgoing tx from **multisig** Vault | Can't happen with 1 key; means 2 keys are compromised. Move to a new multisig with new keys immediately. |
| Single multisig key/device lost or stolen | No funds at risk (needs 2). Calmly rotate to a new 2-of-3 within days. |
| TRON permission changed | If you still hold a key with owner permission, revert at once and move funds; otherwise treat as lost and move what's possible. |
| Unknown ERC-20 allowance | Revoke (`approve(spender, 0)`) from a clean device, then investigate. |
| PC malware suspected | Stop using it; hardware-signed wallets are still safe; T-2 Spending wallet → move to a new seed from a clean device; reinstall Windows. |
| Seed backup location breached | Treat that seed as compromised; move funds to a new seed; for a multisig key, rotate the key. |

Also record: date, txids, addresses, what happened. Report theft to the cybercrime portal (cybercrime.gov.in) and to the exchange the funds went to; exchanges can sometimes freeze stolen USDT, and Tether can freeze USDT addresses.

---

## 11. Phased roadmap

Each phase lists **scope**, **security controls added**, and an **exit gate**. Phases 0–2 involve **no real money**.

### Phase 0 — Foundations (no code)

**Goal:** make the decisions that are expensive to change later.

| Task | Output |
|---|---|
| Write down tier sizes, Spending cap, limits, cool-downs | `docs/security-model.md` §policy |
| **Hardware wallet selection gate** (see below) | Chosen model(s), bought from the manufacturer |
| Prepare a hardened Windows account/PC (§9.4) | Checklist done |
| Buy steel backup plates, prepare 2–3 backup locations | Locations decided |
| Create the wallet inventory template | `inventory` (no secrets) |
| Write the first version of the recovery runbook | `docs/recovery-runbook.md` |

**Hardware wallet selection gate.** The device (and its developer SDK) must, **verified by testing, not by marketing pages**:
1. Sign Bitcoin PSBTs, including **multisig** (P2WSH), and verify change addresses.
2. Sign Ethereum EIP-1559 transactions with **clear display of USDT ERC-20 transfers** (token, amount, recipient).
3. Sign **TRON TRC-20 USDT transfers** with readable recipient + amount (not just hex / "blind signing").
4. Expose all three through an SDK usable from your app (Rust crate, or a pinned official JS SDK in a sidecar process).
5. Have an open-source or audited firmware and a secure element or equivalent.
6. **(rev 2)** Do all of the above with every **blind-signing / "allow contract data" setting in the device's apps turned OFF**. If any required USDT transfer only works with blind signing on, the device fails the gate for that network.
7. **(rev 2)** Show the BTC **change output as change** (not as a second payment) when given a correct PSBT with derivation info.

Candidates to evaluate (**provisional until the matrix below is filled in from real tests**): Ledger (Nano S Plus / Flex), Trezor (Safe 3/5), Keystone (air-gapped QR). For a 2-of-3 BTC multisig, plan for **two different vendors**.

**Device compatibility matrix (rev 3).** Support is proven **per operation**, not per coin. One row per vendor × model × firmware × app version × operation, kept in `docs/device-matrix.md`:

| Vendor / model | Firmware | Coin app version | Network | Operation | Signing method / transport | Full recipient shown? | Amount shown? | Token/contract identity shown? | Fee shown? | BTC change recognised? | Works with blind signing **off**? | Result |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| *e.g. Vendor A model X* | *x.y.z* | *BTC app a.b* | BTC | `BtcSend` P2WPKH | PSBT over USB, SDK v… | ✅ / ❌ | | n/a | | | | Pass / Fail |
| | | | ETH | `EthUsdtTransfer` | EIP-1559 | | | | | n/a | | |
| | | | TRON | `TronUsdtTransfer` | protobuf | | | | | n/a | | |
| | | | … | every operation in §8.0 | | | | | | | | |

Rules: a firmware or app update **re-opens** the affected rows (re-test before use). Any ❌ in a required column → that operation is **disabled** for that device in the network config (§9.6). If a network has no passing device, it stays **outside the custom signing path** (watch-only, signed with vendor software if the vendor app passes).

**Exit gate:**
- [ ] Policy numbers written down.
- [ ] Hardware wallet(s) bought from the manufacturer and authenticity-checked.
- [ ] Each device passes points 1–7 on **testnet** using the vendor's own app first; results recorded in the device compatibility matrix.
- [ ] Recovery manifest (§6.6) drafted for every planned wallet.
- [ ] Monitor device chosen (§10.0).
- [ ] Hardened Windows environment ready.

### Phase 1 — Watch-only portfolio (no keys, mainnet read-only)

**Goal:** a useful app with **zero ability to lose money**. (The chat's advice: "build your app as a watch-only portfolio first".)

| Scope | Security controls |
|---|---|
| Tauri + React + Rust skeleton; strict CSP; capabilities | §9.1, §9.2 |
| Wallet registry with tiers; import **xpubs / addresses only** | No secrets anywhere in the app |
| Balances for BTC, USDT-ERC20, USDT-TRC20 (+ ETH & TRX for fees) | Integer amounts; pinned contracts |
| ≥2 **independent** data sources per network (§5.5); pruned Bitcoin Core where practical | Disagreement → warning; no "majority vote" |
| Activity history; dust/poisoning detection and hiding | §7.2 |
| Receive screen: addresses + QR | — |
| **(rev 3) Independent monitor device** (§10.0) with heartbeat and 2 alert channels | Outgoing tx, unknown nonces, ERC-20/TRC-20 approvals, ETH code/delegation, full TRON permission objects |
| Audit log (hash-chained), separate `policy.db` + checkpoints to the monitor (§9.5) | Anti-rollback groundwork; trusted time |
| Signed network config (§9.6) | App refuses to start on mismatch |
| CI: cargo deny/audit, npm audit, clippy, tests | §9.3 |

**Exit gate:**
- [ ] Balances match block explorers for every wallet.
- [ ] A test outgoing tx (from an external wallet) triggers an alert within 5 minutes, **with the wallet PC switched off** (rev 3).
- [ ] Monitor heartbeat arrives daily on both channels; stopping the monitor is noticed.
- [ ] Restoring an older `policy.db` is detected as a rollback and blocks sends.
- [ ] Allowance and permission baselines (§8.2, §8.5) are recorded for every wallet.
- [ ] A poisoning-style 0-value transfer on testnet is detected and hidden.
- [ ] Grep/scan confirms no secret-handling code paths exist yet.

### Phase 2 — Signing core on testnets (software vault, test funds only)

**Goal:** build and prove the transaction pipeline with fake money. Network order from the chat: **Bitcoin first**, then Ethereum, then TRON.

| Scope | Security controls |
|---|---|
| T-2 software vault (§6.4), testnet / **weak mode** only | Argon2id + XChaCha20-Poly1305 + DPAPI + zeroize; seed decrypted per signature only |
| (rev 3) All six validators in §8.0, Intent model (§7.3), limits (§7.4), signer error handling (§7.5) | Each operation has its own positive + negative tests; no generic signing path |
| BIP-39 generation, restore, derivation (§6.2) | Test vectors; cross-wallet address check |
| Full pipeline ①–⑩ (§7) | Validation, policy, simulation, review-from-bytes, verify-after-sign |
| BTC on **regtest** → **testnet4/signet** | PSBT, coin selection, RBF, fee cap |
| ETH on **Sepolia** with a mock 6-decimal ERC-20 | Transfer-only, no approve, receipt+event check |
| TRON on **Nile** (or Shasta) with a mock TRC-20 | fee_limit cap, energy estimate, permission baseline |
| Address book, allowlist, cool-downs, limits | §7.1 |
| Chain validators (§8 pre-sign tables) | Each rule has a positive and a negative test |
| Adversarial tests | Malicious RPC responses, fake "USDT" token, look-alike addresses, corrupted vault, wrong password, killed process mid-write |
| **(rev 2) Required automated test suites** | **Malformed tx** (truncated PSBT/RLP/protobuf, extra outputs, wrong selector, 7702/approve/permit payloads); **manipulated RPC** (wrong nonce, fake UTXO amount, swapped field in a node-built TRON tx, stale ref-block, disagreeing providers); **recipient substitution** (swap at UI, IPC, builder and signer-transport level); **fee manipulation** (inflated fee rate, gas limit, `fee_limit`, lying prevout amount) |
| **(rev 2) IPC abuse tests** | Calling each command in the wrong state, with malformed args, and from a script injected into the WebView in a test build |

**Exit gate (the chat's security checklist, extended):**
- [ ] Two new wallets have different seeds and addresses.
- [ ] Restoring from seed gives identical addresses here **and** in an independent wallet.
- [ ] All derivation/signing test vectors pass.
- [ ] Malformed / wrong-network addresses and invalid amounts are rejected.
- [ ] Changing recipient/amount after review forces a new review.
- [ ] Wrong passwords, corrupted vault files and interrupted writes are handled without data loss.
- [ ] Logs, crash dumps and the database contain no seed/key (automated scan).
- [ ] Malicious RPC/token tests fail closed.
- [ ] All four required automated suites (malformed tx, manipulated RPC, recipient substitution, fee manipulation) pass in CI.
- [ ] IPC abuse tests pass: no command works out of state or with bad arguments.
- [ ] (rev 3) Native ETH/TRX validators pass the same malformed/substitution suites as USDT; an unrecognised tx type is rejected (no fallback).
- [ ] (rev 3) Weak-mode wallet restored from its paper seed on a **different Windows install and user account** gives the same addresses.
- [ ] (rev 3) Limits: splitting across transactions/wallets is blocked by aggregate limits; changing the Windows clock doesn't shorten a cool-down.
- [ ] Self code review of `signer-soft`, `tx-review`, `policy` against §3 principles.

### Phase 3 — Hardware signer integration (testnet → tiny mainnet)

**Goal:** T-1 Savings wallets sign on hardware; policy engine enforced.

| Scope | Security controls |
|---|---|
| `signer-hw`: BTC PSBT, ETH EIP-1559 ERC-20, TRON TRC-20 | On-device display verified for each; **refuse** if blind signing would be needed |
| "Verify address on device" for receive & allowlist entries | §7.2 |
| Stage ⑧ post-sign verification | Signed tx must match reviewed tx |
| Tier flow rules + limits + cool-downs enforced | §4.2, §7 ③ |
| Sidecar isolation if a JS vendor SDK is needed | Separate process, pinned + vendored SDK, stdio-only protocol |

**Exit gate:**
- [ ] Every flow works on testnet with the real device.
- [ ] A deliberately tampered unsigned tx (recipient changed after review) is caught by stage ⑧ or by the device display.
- [ ] Recovery of the T-1 wallet from seed on a **second** device of the same model succeeds.
- [ ] Recipient/amount/fee substitution tests at builder, IPC, signer-transport and broadcast layers pass with the real device (§7.3).
- [ ] **(rev 3) Steps 1–5 of the §15 release sequence are complete**: testnet validation → independent review → canary authorization → canary → final gate. The order is fixed; see §15.

### Phase 4 — Controlled mainnet rollout

**Goal:** move real funds gradually. **Starts only after the §15 release gate passes.**

| Step | Amount limit |
|---|---|
| Week 1 | Spending tier only, ≤ ₹10,000 |
| Week 2–3 | Savings tier, ≤ ₹1 lakh |
| Week 4+ | Savings tier up to its planned size |
| Vault | **Never signed by the custom app in v1.** Signed with vendor software / Sparrow on a clean machine (§4.1b). The custom app only watches it |
| Savings | Signed by the custom app **only if** the release configuration has `custom_signing_savings = true` (§15). Otherwise vendor software |

Track every tx in the audit log; review weekly for anything unexpected.

**Exit gate:**
- [ ] 4+ weeks with no unexplained events.
- [ ] Recovery drill done on one wallet.
- [ ] Alerts fired correctly for every real outgoing tx.

### Phase 5 — Vault setup (outside the custom signer)

**Goal:** the long-term reserve has the best protection available **per asset** (§4.1b), with signing done by established software, not the custom app.

| Scope | Notes |
|---|---|
| **BTC 2-of-3 P2WSH multisig** (BIP-48 + descriptors), 3 devices, ≥2 vendors | Coordinated by Sparrow on a clean machine; custom app is watch-only for it. Full recovery tested on testnet |
| **ETH USDT Vault and TRON USDT Vault**: hardware single-sig on dedicated seeds | Signed with vendor software; monitor watches approvals, delegation and permissions. **Single-seed protection, stated as such** |
| Own Bitcoin Core node | Already running since Phase 1 if practical (§5.5) |
| Inheritance plan | Sealed letter + recovery manifests + runbook; doesn't reveal secrets on its own |

**Exit gate:**
- [ ] Full multisig recovery done on testnet with only 2 seeds + descriptor, **without this app**, using only backup-location materials (§6.6), ending in a spend.
- [ ] Mainnet multisig receive/send tested with a small amount.
- [ ] ETH/TRON Vault recovery tested per manifest, ending in a spend.
- [ ] Vault funds moved in stages.

### Phase 6 — Ongoing operations

| Cadence | Task |
|---|---|
| Weekly | Review alerts and the audit log; confirm monitor heartbeats arrived |
| Monthly | Dependency audit (`cargo audit`, `npm audit`); OS updates; device firmware updates (from the vendor app, after reading release notes) **and re-test the affected device-matrix rows before signing again** |
| Every 6 months | Recovery drill per manifest (§6.5, §6.6); verify both USB copies; check backup locations; manual explorer check of allowances/permissions/delegation |
| Yearly | Review tier sizes, limits, threat model; consider signed auto-update only now |
| On any incident | `docs/incident-runbook.md` |

### Phase 7 — Deferred: smart-account and TRON multisig (not in v1)

Only if you later decide it's worth the complexity. **Nothing in this document describes Safe or TRON multisig as supported until all of the following are done:**
- [ ] Safe: §8.4 validator implemented with negative tests; device display verified in the matrix; account config (singleton, owners, threshold, modules, guard, fallback handler) verified and monitored; recovery = **spend** with 2 seeds without this app.
- [ ] TRON: §8.5 target permission layout written; multisig validator implemented; tested emergency procedure for a lost key and for a hostile permission change; recovery = spend.
- [ ] A separate independent review of these paths.
- [ ] Testnet → canary → staged migration, as for Phase 3/4.

---

## 12. Threat → control map

| Threat | Primary controls | Phase |
|---|---|---|
| T1 PC malware | Hardware signing (P1), on-device verification (P3), Spending cap, dedicated Windows account | 0, 3, 4 |
| T2 Clipboard swap | Address book + allowlist, device display, look-alike check | 2, 3 |
| T3 Address poisoning | Look-alike block, no copy-from-history, dust hiding | 1, 2 |
| T4 Seed theft | Hardware-generated seeds, steel backups in separate places, multisig, optional passphrase | 0, 5 |
| T5 Malicious/blind signing | Review-from-bytes, post-sign verification, refuse blind signing | 2, 3 |
| T6 Unlimited approvals | Transfer-only (no `approve`), allowance monitoring | 1, 2 |
| T7 TRON permission hijack | Permission baseline + alert, incident runbook | 1, 2 |
| T8 Supply chain | Pinned + vendored deps, cargo deny/audit, no CDN, buy from manufacturer, no auto-update | 0, 1 |
| T9 Own bugs | Test vectors, cross-wallet restore check, testnets first, independent review, tiny-amount rollout | 2, 3, 5 |
| T10 Lying RPC | ≥2 sources cross-check, fail closed, own BTC node | 1, 5 |
| T11 Physical loss | Multisig, 2 backup locations, BitLocker, device PIN | 0, 5 |
| T12 Coercion/social eng. | Cool-downs, tier flow rules, Vault needs 2 devices in 2 places, never share screen/seed | 2, 5 |
| T13 Self-lockout | Recovery drills, runbook, descriptor backups, passphrase stored separately | 0, 5, 6 |
| T14 Phishing/fake software | Official sources + signature checks, no general browsing on wallet account | 0 |
| T15 Indirect-drain signatures | Operation allowlist (P13), ETH/TRON pre-sign validators, no message/typed-data/7702 signing, allowance + delegation monitoring | 1, 2 |
| T16 Compromised WebView | Native command boundary (§9.1), state machine, device approval as the only authorization | 1, 2, 3 |
| T17 Secrets in errors/dumps | Redacting types, abort-on-panic, WER exclusion, `VirtualLock`, leak-scan test | 2 |
| (rev 3) Full PC compromise bypassing review/policy | Device = authorization boundary (§0, §7 ⑦), keys off-PC, Vault signed outside the custom app, independent monitor | 0, 1, 3, 5 |
| (rev 3) Policy rollback / clock manipulation | Separate `policy.db`, monotonic checkpoints at the monitor, trusted chain+monitor time, fail closed (§9.5) | 1, 2 |
| (rev 3) Silent monitoring (PC off/compromised) | Separate monitor device, 2 channels + explorer alerts, heartbeat, offline test (§10.0) | 1 |
| (rev 3) Config tampering | Signed network config, cool-down on raising limits, signer fingerprint check (§9.6) | 1, 2 |

---

## 13. Open decisions

| # | Decision | Recommendation | Decide by |
|---|---|---|---|
| D1 | Hardware wallet vendor(s) | Run the Phase 0 gate on Ledger + one of Trezor/Keystone; use 2 vendors for the BTC multisig | Phase 0 |
| D2 | Spending tier cap | ≤ ₹50,000 or ≤ 5% of total, whichever is lower | Phase 0 |
| D3 | BIP-39 passphrase for Vault/Savings | Yes for Savings single-sig if you can store it separately and reliably; not needed with multisig | Phase 0 |
| D4 | Vault design for USDT | **Decided in rev 3 for v1:** hardware single-sig on dedicated seeds, signed with vendor software, plus monitoring. Safe / TRON multisig deferred to Phase 7. Still yours to decide: how much of the reserve you accept holding with single-seed protection (§4.1b) | Phase 0 |
| D5 | TRON implementation | Rust-native preferred; sidecar TronWeb only if necessary | Phase 2 |
| D6 | Alerts channel | Telegram bot (simple) or email | Phase 1 |
| D7 | Dedicated PC vs. dedicated Windows account | Dedicated laptop if budget allows (at ₹1 Cr, strongly recommended) | Phase 0 |
| D8 | **(rev 2) Who does the independent review** | A paid freelance reviewer with Rust + Bitcoin/Ethereum wallet experience, scoped to `signer-*`, `tx-review`, `policy`, `chain-*`, `commands.rs` and the release build. **Fallback if no reviewer is available:** the custom app stays a watch-only + transaction-*preparation* tool for Savings/Vault, and those wallets sign through the vendor's own app or Sparrow (PSBT export/import). The custom signer is then used only for the capped Spending tier. **(rev 3) This is enforced by the release configuration in §15, not left to judgment.** | Before Phase 4 |
| D9 | **(rev 2) Spending tier signer** | **Decided in rev 3:** a separate hardware wallet; software vault = weak mode only | Phase 0 |
| D10 | **(rev 3) Monitor device** | Raspberry Pi 5 + SSD at home (runs pruned Bitcoin Core too), or a small cloud VM | Phase 0 |
| D11 | **(rev 3) Exact limit numbers** | Fill in the §7.4 table in asset units: per-tx, per-wallet, per-tier, global, per-recipient, fee caps, native top-up caps | Phase 0 |

---

## 14. Gap reviews

Rev 2 and rev 3 are listed separately below. Where a rev 3 change replaced something rev 2 said (e.g. the native OS dialog, canary exemption, Phase 5 review), the rev 3 table is authoritative.

## 14A. Gap review 1 → rev 2 (2026-10-17)

An external review (ChatGPT, run on rev 1 of this document) concluded: *"Sound foundation; several critical security properties unspecified; not ready for real funds."* **Agreed.** This is a design, and no real funds go in until §15 passes.

Legend: ✅ **Already covered in rev 1** (section given) · 🔧 **Partly covered, strengthened in rev 2** · 🆕 **New in rev 2**

### 14A.1 Critical findings

| # | Finding | Status | Where it's handled |
|---|---|---|---|
| F1 | Hardware signing may not independently verify the transaction (app shows A, device signs B) | 🔧 | Rev 1 already had P3/P4, review-from-bytes (§7 ⑥), device check (⑦) and post-sign verify (⑧). **Added:** P14 build locally + decode before signing; stage ④b chain validators with field-by-field rules (§8.1/8.2/8.3); device compare against a *device-verified* address book, not the PC screen; Phase 0 gate items 6–7. |
| F2 | One recovery phrase is a single point of failure for all three chains; USB backup as another route | 🔧 | Rev 1 already had separate seeds per tier (§4), hardware-only seeds for T-0/T-1 (§6.1), no seeds on USB (§6.3). **Added:** §4.1a security domains, with separate seeds for BTC Vault vs USDT Vault, an optional Savings split, and an explicit rule that primary seeds never enter the app; T-2 moved to a separate hardware wallet (D9). |
| F3 | Blind signing or unrestricted contract calls (approvals, indirect transfers) | 🔧 | Rev 1 had P4 and "transfer only, no approve/permit" (§8.2). **Added:** P13 operation allowlist; exact calldata rules (68 bytes, `0xa9059cbb`); reject tx type 4 (EIP-7702); no message / EIP-712 signing; device blind-signing settings must stay OFF (Phase 0 gate item 6); delegation monitoring. |
| F4 | UI ↔ native command boundary too permissive | 🔧 | Rev 1 had strict CSP, capabilities, narrow typed commands (§9.1). **Added:** "Native command boundary" table: command allowlist enforced in CI, isolation pattern, state machine, single-use `review_id`, native OS approval dialog, Trusted Types, DevTools off, IPC abuse tests. |
| F5 | Custom signing/crypto not independently reviewed | 🔧 | Rev 1 had established libraries, test vectors and pinning, but put the independent review in **Phase 5, after real funds**. That was a real gap. **Fixed:** P15; review is now a Phase 3 exit item and a §15 gate, with a fallback (D8) if no reviewer is available. |

### 14A.2 Chain-specific gaps

| Chain | Review point | Status | Where |
|---|---|---|---|
| BTC | Validate every input, recipient output, change and fee | 🔧 | §8.1 pre-sign validator (adds full prev-tx check and a locally computed fee) |
| BTC | PSBT / well-defined hardware workflow | ✅ | §5.3, §7 ④, §8.1 |
| BTC | Device must recognise change via derivation paths | 🔧 | §8.1 validator "Change" row; Phase 0 gate item 7 |
| BTC | Reject unexpected outputs, excessive fees, malformed tx | 🔧 | §8.1 validator; Phase 2 malformed-tx and fee suites |
| BTC | Protect xpubs and address history | 🆕 | §8.1 "xpub privacy" |
| ETH | Verify chain ID and exact USDT contract | ✅ | §8.2 (pinned contract, EIP-155) and now the validator table |
| ETH | Decode calldata; confirm actual recipient and amount | 🔧 | §8.2 validator (`data` row) |
| ETH | Validate nonce, gas limit, fee caps, destination | 🔧 | §8.2 validator |
| ETH | Reject approve / permit / delegatecall-style flows / arbitrary calls | 🔧 | P13, §8.2 validator + "Never signed" list (incl. EIP-7702) |
| ETH | Check existing approvals separately | ✅🔧 | Rev 1 §8.2/§10.1 allowance alerts; rev 2 adds delegation (`eth_getCode`) check |
| TRON | Verify mainnet, contract and Base58/hex conversions | 🔧 | §8.3 validator (`contract_address` round-trip rule) |
| TRON | Decode contract call; validate recipient and amount | 🔧 | §8.3 validator (`data` row) |
| TRON | Validate `fee_limit`, expiration, reference block, permission ID | 🔧 | `fee_limit` was in rev 1; the others were added in the §8.3 validator |
| TRON | Device must support and properly show the TRC-20 tx | ✅🔧 | Phase 0 gate item 3, now with item 6 (blind signing off) |
| TRON | Never send a private key to a node/API | ✅🔧 | P2, §5.2 B2; rev 2 says it explicitly in §8.3 and forbids node-built tx signing as-is |

### 14A.3 "Other gaps that can compromise the wallet"

| Area | Failure mode | Status | Where |
|---|---|---|---|
| Windows malware | Reads secrets from memory / manipulates UI | 🔧 | Rev 1: P1 hardware signing, §9.4 clean OS, P11. **Added:** minimal unlocked time (§6.4: seed decrypted per signature only), `VirtualLock`, native approval dialog |
| USB backups | Phrase stolen or backup corrupted | ✅ | §6.3 (no seeds on USB, 2 copies in 2 places), §6.5 recovery drills |
| RPC providers | Wrong balances, fees or **unsigned tx fields** | 🔧 | Rev 1: ≥2 sources, fail closed. **Added:** P14, never sign node-built tx as-is, nonce/ref-block/fee/prevout cross-checks in the validators |
| Address handling | Clipboard malware swaps recipient | ✅ | §7 ③/⑦, §7.1 address book verified on device, §9.1 clipboard rules |
| Dependencies | Compromised package or build tool | 🔧 | Rev 1: lockfiles, cargo deny/audit, vendored SDK. **Added:** protected build VM, `--locked`, `--ignore-scripts`, reviewed updates, two-build hash check (§9.3) |
| Application updates | Malicious installer replaces the wallet | 🔧 | Rev 1: no auto-update, signed installer. **Added:** code-signing key on a hardware token, paper hash record, install-time check, offline updater key, downgrade protection (§9.3) |
| Error handling | Secrets in logs / crash dumps | 🔧 | Rev 1: P11. **Added:** §9.2 secret hygiene table (redacting types, abort-on-panic, WER exclusion, leak-scan test) |
| Recovery | Wrong derivation paths make funds "disappear" | ✅ | §6.2 paths + cross-wallet restore test, §6.5 drills, Phase 2 gate |

### 14A.4 Mandatory release gates from the review

All 9 are adopted word-for-word into §15 (G1–G9). Rev 1 already covered G2, G6 and most of G1/G4/G8 in phase exit gates; G9 (independent review before funds) was the real gap.

## 14B. Gap review 2 → rev 3 (2026-10-17)

The second review was run on rev 2. Each item was checked against rev 2 before changing anything. None was fully covered already, so none was skipped; partial coverage is noted.

Legend: ✅ already covered (verified, no change) · 🔧 partly covered in rev 2, completed in rev 3 · 🆕 new in rev 3

### 14B.1 Critical gaps

| # | Finding | Status | What rev 2 had → what rev 3 changes |
|---|---|---|---|
| R1 | Compromised PC can bypass the review screen; malware can broadcast a signed tx | 🔧 | Rev 2 had device confirmation + post-sign verify, but treated the native dialog + `review_id` as approval controls. **Rev 3:** device = sole authorization boundary (§0, §2.3, §7 ⑦); dialog/`review_id` demoted to bug-catchers; immutable Transaction Intent (§7.3); ⑧ limitation stated; substitution tests at builder/IPC/transport/broadcast (§7.3); Vault signed outside the custom app (§4.1b). |
| R2 | Safe and TRON multisig not covered by validators | 🔧 | Rev 2 listed them as "optional Phase 5" with no validators. **Rev 3:** not in v1 (§8.0); Safe validator spec (§8.4); full TRON permission policy (§8.5); moved to deferred Phase 7 with recovery + review requirements. |
| R3 | Monitoring depends on the wallet PC | 🆕 | Rev 2's watcher was implicitly in the app. **Rev 3:** separate monitor device, strictly watch-only, continuous, 2 alert channels + explorer alerts, heartbeat, tested with PC off, compromise analysis (§10.0). |
| R4 | Audit log and cool-downs vulnerable to rollback | 🆕 | Rev 2 had only a local hash chain. **Rev 3:** separate `policy.db`, monotonic checkpoints anchored at the monitor + paper, trusted chain/monitor time, fail closed, and an explicit detects / doesn't-detect table (§9.5). The log is no longer described as tamper-detecting in general. |
| R5 | ETH/TRX native transfers lack validators | 🔧 | Rev 2 P13 allowed them with no validator. **Rev 3:** closed operation registry (§8.0) with no fallback; §8.2b and §8.3b validators and tests. |

### 14B.2 High-priority gaps

| # | Finding | Status | Where |
|---|---|---|---|
| R6 | T-2 software vault contradicts the threat model | 🔧 | Rev 2 already preferred a hardware wallet for T-2. **Rev 3:** hardware wallet is the only production T-2 signer; software = labelled weak mode, ≤ ₹10k, cap enforced by balance + monitor (§4.1, §6.4). |
| R7 | DPAPI vault recovery/portability | 🆕 | §6.4 "Recovery & portability": the vault file is never a backup; restore from seed; test on another Windows install/user (Phase 2 gate). |
| R8 | "Two providers agree" ≠ truth | 🔧 | Rev 2 had ≥2 providers. **Rev 3:** independence definition, locally verified vs provider facts, disagreement = stop, own BTC node moved to Phase 1 (§5.5). |
| R9 | Allowance discovery strategy | 🔧 | Rev 2: "spenders ever seen". **Rev 3:** nonce-0 baseline, full `Approval` log indexing, gap recovery, post-compromise procedure, TRC-20 approvals too, "detection not prevention" stated (§8.2, §8.3). |
| R10 | Limit units and anti-bypass | 🆕 | §7.4: asset units primary, INR secondary from the higher of 2 prices, 5 scopes incl. global aggregate, anti-splitting, fee caps, fail closed, honest scope. |
| R11 | Device support per operation | 🔧 | Rev 2 Phase 0 gate items 1–7. **Rev 3:** compatibility matrix per vendor/firmware/app/operation; failed rows disable operations; firmware updates re-open rows (§11 Phase 0). |
| R12 | Recovery must cover the exact production configuration | 🔧 | Rev 2 had drills. **Rev 3:** per-wallet recovery manifest (§6.6); drills use only backup-location materials and no custom app; multisig/smart accounts must prove a spend. |

### 14B.3 Chain-specific corrections

| Area | Status | Where |
|---|---|---|
| BTC PSBT input validation completeness | 🔧 | §8.1 "Outpoints" + "After signing" rows (txid match, script re-derivation, unspent check, signature + consensus verification) |
| BTC fee policy / overrides / RBF | 🔧 | §8.1 fee policy table (bounds, hard max, override can't bypass validation, RBF rules, no CPFP) |
| ETH nonce reconciliation | 🆕 | §8.2 nonce table (unknown confirmed nonce = alert, mempool disagreement = wait, speed-up/cancel rules) |
| ETH USDT contract identity | 🔧 | §8.2 + §9.6: pinned in signed versioned config, re-verified from 3 sources each release; final check decodes the signed tx |
| ETH delegation single-source | 🔧 | §8.2 delegation check: ≥2 sources, signing disabled pending investigation |
| TRON construction choice | 🔧 | §8.3: **decided**, local construction only; node output never signed; unknown fields rejected |
| TRON permissions | 🔧 | §8.5 full permission object policy; updates not possible from the app; emergency procedure |

### 14B.4 Internal contradictions

| # | Contradiction | Resolution |
|---|---|---|
| A | Canary vs release gate order | §15 now defines one fixed sequence with a canary authorization step; Phase 3 points to it |
| B | Vault described as multisig on all chains | §4.1 row rewritten; §4.1b per-asset protection table; Safe/TRON multisig moved to Phase 7 |
| C | Weak fallback wording for "no reviewer" | §15 release configuration flags make it mechanical; D8 points to it |
| D | USB backups still expose information | §6.3 USB rules: minimize, encrypt, verify both copies, retire securely, runbook secret check |

### 14B.5 Additional requirements

| Requirement | Where |
|---|---|
| Configuration integrity | §9.6 (signed network config, cool-down on raising limits, signer fingerprint check) |
| Safe recovery from corruption | §9.7 (signing stops; no rebuild from untrusted data; explicit policy reset) |
| Dependency and build review evidence | §9.3 "Build evidence kept" |
| Signer disconnect / cancellation handling | §7.5 |
| Address-book integrity | §7.1 integrity rules (edit = new entry, restore ≠ trust, revocation list) |
| Operational separation | §9.3 "Operational separation" + §15 release configuration |

---

## 15. Mainnet release sequence & gate (rev 3)

Record the date and evidence for every step and gate item in `docs/release-gate.md` (test reports, commit hash, installer hash, reviewer's report).

### 15.1 Fixed sequence

```
① Testnet validation ─▶ ② Independent review ─▶ ③ Canary authorization ─▶ ④ Canary testing ─▶ ⑤ Final release approval ─▶ ⑥ Controlled rollout (Phase 4)
```

| Step | What must be true before it starts | Done when |
|---|---|---|
| ① Testnet validation | Phase 0–2 gates passed | Phase 3 testnet items pass; G1, G3, G4, G5, G8 pass on testnet; G7 passes for the candidate build |
| ② Independent review | ① complete; the build to review is frozen (commit + installer hash) | Reviewer's report on that exact commit/hash; every finding fixed (→ back to ①) or accepted in writing. **G9** |
| ③ Canary authorization | ② complete with **no changes since** (same hash), G2 and G6 pass, monitor live (Phase 1 gate) | **You** sign a dated entry in `release-gate.md` stating scope: which wallets, which operations, max **₹500 equivalent per asset**, max 2 weeks. You're the only authorizer; the entry is also sent as a monitor checkpoint |
| ④ Canary testing | ③ authorized | Each operation in §8.0 done on mainnet within scope; alerts observed (**G10**); a canary loss is accepted as a cost |
| ⑤ Final release approval | ④ complete with no unexplained events; G1–G11 all ✅; installed build hash = reviewed hash | Signed, dated approval entry in `release-gate.md` |
| ⑥ Rollout | ⑤ approved | Phase 4 staging table |

Any code, dependency or config change after ② restarts at ①, and requires a new or delta review at ② before custom signing is used again.

### 15.2 Release configuration (enforced, not advisory)

Stored in the signed network config (§9.6) and the checkpointed policy state (§9.5):

| Flag | Default | Becomes `true` only when |
|---|---|---|
| `custom_signing_spending` | `false` | Steps ①–⑤ complete for Spending |
| `custom_signing_savings` | `false` | Steps ①–⑤ complete **and** the independent review (②) covered the exact installed build. **No independent review → stays `false`**: Savings is signed with vendor software, and the custom app is watch-only + transaction preparation for it |
| `custom_signing_vault` | `false` | **Never in v1** (§4.1b) |
| `weak_mode_software_vault` | `false` | You enable it explicitly; 48 h cool-down + monitor alert; cap ≤ ₹10k (§6.4) |
| `safe_operations`, `tron_multisig_operations` | `false` | Phase 7 complete |

### 15.3 Gate items

| # | Gate (from the external review) | How it's verified | Defined in |
|---|---|---|---|
| G1 | The hardware signer supports the exact BTC, Ethereum USDT and TRON USDT operations required | Phase 0 device gate items 1–7 passed on testnet with the real devices, using your app | §11 Phase 0, Phase 3 |
| G2 | The application never exports or stores the hardware wallet's seed or private keys | Code search: no seed/xprv import or export paths for hardware wallets; leak-scan test passes | §4.1a, §9.2 |
| G3 | Every supported transaction type is parsed and validated before signing | Each §8 validator rule has a passing positive and negative test | §7 ④b, §8 |
| G4 | The device's independent display is used to verify details; unsupported or unclear operations fail closed | Manual test log: every operation shown clearly on device; blind-signing settings OFF; tampered-tx test caught | §7 ⑦, Phase 3 gate |
| G5 | No unapproved token allowance or arbitrary contract interaction can be initiated | No code path builds `approve`/`permit`/typed data/7702; tests for those payloads are rejected | P13, §8.2, §8.3 |
| G6 | Recovery is tested for all networks and accounts, including derivation paths | Restore every wallet in an independent wallet; addresses match on all 3 networks | §6.2, §6.5 |
| G7 | Dependency, installer and update integrity are verified | `cargo deny`/`audit`/`npm audit` clean; two-build hash match; installer signature + paper hash checked | §9.3 |
| G8 | Automated tests cover malformed tx, manipulated RPC, recipient substitution and fee manipulation | All four suites green in CI on the release commit | §11 Phase 2 |
| G9 | An independent reviewer has examined the actual signing code and release build | Reviewer's report on the release commit; findings fixed or accepted in writing. If not possible → D8 fallback | P15, D8 |
| G10 | *(added)* Monitoring works | A canary outgoing tx, a test allowance and a test 0-value poisoning transfer each raise the right alert | §10.1 |
| G11 | *(added)* Incident and recovery runbooks exist on paper | `recovery-runbook.md` and `incident-runbook.md` printed and stored with the backups | §6.3, §10.2 |

---

## Appendix A — What changed vs. the ChatGPT conversation

| Topic | Chat said | This document |
|---|---|---|
| Pen drive for keys | Not as primary storage; encrypted USB only for backups/docs | Same; USB holds **no seeds/keys at all**, only inventory, descriptors, runbook |
| Hardware vs software | Hardware signer for > ₹10 lakh | Same, made into tiers with a hard Spending cap |
| One seed vs many | One shared vault, three chain adapters | One seed **per tier/wallet**, three chain adapters inside each |
| Stack | Tauri 2 + React + TS + Rust, rust-bitcoin, Alloy/ethers-rs, TronWeb | Same, plus BDK for BTC; Alloy only (ethers-rs deprecated); TronWeb only in a sidecar if needed |
| Testnets | Regtest, Sepolia, Shasta | Same, plus testnet4/signet for BTC and Nile for TRON |
| Multisig | "Consider 2-of-3 for BTC" | Required for Vault; ≥2 vendors; optional Safe/TRON multi-sig |
| Monitoring | Not covered | Watcher + alerts for outgoing tx, approvals, TRON permissions |
| Address poisoning, TRON permission hijack, supply-chain attacks | Not covered | Threats T3, T7, T8 with controls |
| Incident response | Not covered | §10.2 runbook |
| External gap review (rev 2) | Found 5 critical findings, chain-specific gaps, 8 overlooked areas and 9 release gates | All mapped in §14A; release gates in §15 |
| External gap review (rev 3) | Found 5 critical + 7 high-priority gaps, chain corrections, 4 contradictions, 6 extra requirements | All mapped in §14B; Safe/TRON multisig deferred; independent monitor; anti-rollback; fixed release sequence |

## Appendix B — Disclaimer

This is a security-engineering design for a personal wallet, not financial or investment advice. No design removes all risk. Verify contract addresses, hardware wallet capabilities and library versions against official sources at implementation time, because they change.
