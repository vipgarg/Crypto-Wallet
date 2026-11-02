# Personal Self-Custody Wallet — Security Architecture

**Status:** Design, revision 4.1 (offline-laptop signer replaces hardware wallets, see §14C; lessons from the Binance 2026 and Bybit 2025 incidents added, see §14D). Nothing is built yet. **Not ready for real funds** until the §15 release sequence completes.
**Owner:** Vipul
**Platforms:** **Online PC:** Windows 10/11, watch-only, holds no secrets. **Offline signer:** a dedicated laptop running minimal Linux, never connected to any network, signs for every wallet.
**Assets:** BTC, USDT on Tron (TRC-20), USDT on Ethereum (ERC-20)
**Expected holdings:** more than ₹1 Crore, spread across several wallets
**Source:** the ChatGPT conversation "Create Crypto Wallet" (shared 2026-10), the security review in this document, and the rev 4 decision (2026-11-02): no hardware wallets for now (cost); one offline laptop signs for all wallets, a separate online PC watches them.

---

## 0. How to read this document

| Section | What it answers |
|---|---|
| 1. Goals & non-goals | What the wallet must and must not do |
| 2. Threat model | Who/what can steal funds, and how |
| 3. Core security principles | Rules every phase must follow |
| 4. Multi-wallet model | How the wallets are split into tiers, and how each lives on the offline signer |
| 5. System architecture | The two machines, their components and trust boundaries |
| 6. Key, seed & backup management | How secrets are created, stored, used statelessly and recovered |
| 7. Transaction security pipeline | How a send is protected end to end, across the air gap |
| 8. Chain-specific rules | BTC / ERC-20 / TRC-20 details |
| 9. Application & OS hardening | Online app, offline signer, Windows, Linux, start-up checks, login, supply chain |
| 10. Monitoring & incident response | How you find out about an attack, and what to do |
| 11. Phased roadmap | What gets built in which order, with exit gates |
| 12. Threat → control map | Which control stops which threat, and in which phase |
| 13. Open decisions | Choices you still need to make |
| 14. Gap reviews, revisions & incident lessons (rev 2, 3, 4, 4.1) | Each finding from the external reviews, what rev 4 changed, and what real exchange hacks teach this design |
| 15. Mainnet release sequence & gate | The exact order and checklist before any real funds touch the custom software |

Every phase in section 11 has an **exit gate**. Do not start the next phase until its gate passes. Phase 4 (real funds) also needs the full **§15 release sequence**.

**Core idea (adopted from the review):** a signing device protects the private keys, but it does **not** protect you from *approving a malicious transaction*. The online PC is never trusted to tell the truth about a transaction. Only the offline signer's display and data you verify independently are.

**Rev 4 design in one paragraph.** There are no hardware wallets in v1 (cost). Instead there are **two machines**. The **online PC** (Windows) shows balances, prepares unsigned transactions and broadcasts signed ones; it never holds a seed or private key. The **offline signer** (a dedicated laptop with its network hardware removed) holds or receives the seeds, decodes and checks every transaction itself, shows it to you, and signs. The two exchange data **only through QR codes** (screen → webcam). Each wallet on the signer has its own encrypted vault and password; the Vault tier is **stateless**: its seeds are never stored on the laptop and are scanned from paper SeedQR cards at signing time.

**Final authorization boundary (rev 4):** *the offline signer's screen + your approval on it, after comparing with your paper records.* Nothing on the online PC (review screen, `review_id`, policy, post-sign check) is an authorization control; those only catch bugs and protect the app's own broadcast path. **Once the signer shows the signed transaction, assume malware on the online PC can broadcast it.** So approve only what the signer itself shows correctly.

**Honest limitation (rev 4).** A general-purpose laptop is a weaker signer than a hardware wallet: no secure element, a much larger software stack, and it can be physically tampered with. The design compensates with the air gap, physical security, stateless Vault seeds, per-wallet vaults and passphrases, and a small reviewed signer app. Adding a hardware wallet later (as BTC Vault key #3, D1) is still recommended.

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
| Signer disk / vault passwords, BIP-39 passphrases (rev 4) | Unlock the offline signer's disk and a wallet's vault; a passphrase is part of the key itself |
| Offline signer laptop (rev 4) | If stolen: encrypted, but can be attacked offline. If tampered with and returned: can capture secrets entered later |
| SeedQR cards (rev 4) | Same as the seed: attacker can take everything derived from it |
| Address book / allowlists (online, signer, paper) | If changed, sends go to the attacker |
| Wallet inventory | Privacy loss, and a target list for social engineering |

### 2.2 Attackers and attack paths

| # | Threat | Example | Severity |
|---|---|---|---|
| T1 | **Malware on the online Windows PC** | Keylogger, remote-access trojan, infostealer; alters the unsigned tx or the review screen; broadcasts what you signed. (Rev 4: there are no keys on this PC to steal) | Critical |
| T2 | **Clipboard / address swap** | Malware replaces the copied address with the attacker's | Critical |
| T3 | **Address poisoning** | Attacker sends a 0-value USDT transfer from a look-alike address (same first and last characters) so you copy it from history | High (very common on TRON and Ethereum USDT) |
| T4 | **Seed phrase theft** | Photo, cloud backup, typed into a fake "wallet sync" site, found by a visitor | Critical |
| T5 | **Malicious or confusing signing** | App shows A, device signs B; blind signing of contract data | Critical |
| T6 | **Unlimited token approvals** | `approve(spender, MAX)` lets a contract take all USDT later | High |
| T7 | **TRON account permission hijack** | Attacker who gets a key one time changes the account's owner/active permission and keeps control even after you notice | High |
| T8 | **Supply-chain compromise** | A hijacked npm/crates package, a compromised build machine or build tool, a malicious installer/update replacing the wallet or the signer, a fake wallet download, a tampered Linux ISO | Critical |
| T9 | **Bugs in your own wallet code** | Wrong derivation path, bad randomness, float rounding, wrong change output | High |
| T10 | **Lying RPC provider** | Fake balance, fake nonce, inflated fee estimate, a "tx confirmed" that never happened, **or an unsigned transaction built by the node with a swapped field** (e.g. TRON's `triggersmartcontract` returns a ready-made tx) | High |
| T11 | **Physical theft or loss** | Stolen laptop, stolen hardware wallet, fire/flood destroys backups | High |
| T12 | **Coercion / social engineering** | "Support agent" call, fake airdrop, "$5 wrench" attack | High |
| T13 | **Self-lockout** | Forgotten passphrase, lost descriptor, corrupted only backup | Critical (equally total loss) |
| T14 | **Phishing and fake software** | Fake Sparrow/wallet app, fake VeraCrypt, fake Linux ISO, fake "USDT recovery" or "exchange compensation" tool | High |
| T15 | **Indirect-drain signatures** | Off-chain signatures that move tokens later (EIP-2612 `permit`, Permit2, EIP-712 typed data), an EIP-7702 delegation that turns your Ethereum address into attacker-controlled code, or any contract call that isn't a plain transfer | Critical |
| T16 | **Compromised WebView / UI** | Injected script in the UI calls native commands directly, or shows a fake review screen | Critical |
| T17 | **Secrets leaking through errors** | Seed or key appearing in a log line, panic message, crash dump, swap or hibernation file on the signer | High |
| T18 | **(rev 4) Offline signer theft or tampering** | Laptop stolen and attacked offline; an "evil maid" opens it or installs a keylogger while you're away, then waits for you to type passwords or show a SeedQR | High |
| T19 | **(rev 4) Air-gap breach** | Wi-Fi/Bluetooth re-enabled; an infected USB stick; a malicious QR payload exploiting a parser bug on the signer; a malicious signer build leaking key bits through signature data | Critical |
| T20 | **(rev 4) Seed exposure during stateless signing** | A SeedQR card photographed, lost or seen while it's out of storage, or while it's carried between a backup location and the signer | High |
| T21 | **(rev 4.1) Compromised developer machine / developer social engineering** | You are the developer. A fake job offer, a "coding test" repository, a malicious npm/crates package or a trojanised tool infects your development machine, and the attacker plants code in the signer or online app, or reaches the build VM. This is how the Binance 2026 (DevOps laptop) and Bybit 2025 (developer machine at the wallet-UI provider) attacks started | Critical |

### 2.3 What the design assumes

- **The online Windows PC may be compromised at some point.** The design must stay safe even then. This is why **no seed or private key ever exists on it**, for any tier (rev 4).
- **The offline signer is trusted only while it stays offline, physically secured and running the reviewed build.** Its screen is the trusted screen; the online PC's screen (including the app's review screen) is a convenience, not a security control. Malware that controls the online PC can alter a transaction before it reaches the signer and can broadcast anything you have signed.
- **Everything that crosses the air gap into the signer is hostile input.** A QR code can carry a malformed or malicious payload; the signer parses it with strict, size-limited, fuzzed decoders and re-checks every field itself.
- **Physical access is the main risk to the signer.** Someone who can take or tamper with the laptop while you're away (an "evil maid") is the attacker the signer's physical controls (§9.4b) are designed against.
- **Local policy on the online PC (limits, cool-downs, allowlist) can be bypassed by malware with full control of that PC.** It protects against mistakes, social engineering and partial compromise. Against full compromise the protections are: the signer's own checks and allowlist, the signer display + you, keys off the online PC, multisig for the BTC Vault, and the **independent monitor** (§10).
- **The UI (WebView) on the online PC can be compromised.** All checks live in the Rust core; the UI can only *request*. The offline signer has **no WebView at all**.
- **RPC providers are honest-but-unreliable.** They can't steal funds, but their data is cross-checked before you act on it.
- **You are the weakest link under pressure.** Cool-down periods and allowlists exist to slow down a rushed or tricked decision.

---

## 3. Core security principles

These rules apply to every phase. Code review checks against them.

| # | Principle | In practice |
|---|---|---|
| P1 | **Keys never touch an online device** (rev 4) | Seeds are generated, stored and used **only on the offline signer**. The online PC holds public data (addresses, xpubs, descriptors) only, for **every** tier, Spending included. A seed is never typed, scanned or pasted into the online PC. |
| P2 | **Separate signing from connectivity** | Two physically separate machines. The online PC never holds secrets; the signer has no network hardware enabled and never connects. |
| P3 | **Verify on the signer, not on the online screen** | Recipient, amount, network, contract and fee are checked on the **offline signer's** display, against your paper records, before approval. |
| P4 | **No blind signing** | The signer decodes every field of every transaction. If it can't decode and display something, it refuses to sign. |
| P5 | **Fail closed** | Unknown network, unverified token contract, mismatched RPC data, failed simulation, unreadable QR → **stop**, don't guess. |
| P6 | **Least privilege** | The online UI can ask its core to "prepare transfer" and "accept signed transfer", never for keys. The online PC can only *ask* the signer to sign a specific unsigned tx; it can't request keys, seeds or signatures over arbitrary data. |
| P7 | **Defense in depth** | Online policy (allowlist, limits, cool-down) + signer policy (own allowlist, limits, log) + signer display + multisig (BTC Vault) + monitoring. Each layer assumes the one before it failed. |
| P8 | **No single point of failure for recovery** | ≥ 2 offline seed backups in separate places. Recovery never depends on the signer laptop or its vault files. Recovery tested before funding. |
| P9 | **Integers only** | Satoshis for BTC and base units (6 decimals for USDT) for tokens. No floating point anywhere money is calculated. |
| P10 | **Pin everything** | Token contract addresses, chain IDs, dependency versions, signer OS image and toolchain are all pinned and reviewed. |
| P11 | **Secrets never logged** | No seed, key, password, passphrase or raw signing payload in logs, crash reports, analytics, screenshots, camera buffers or clipboard history. |
| P12 | **Small first, big later** | Every new capability goes through testnet → tiny mainnet amount → normal use. |
| P13 | **Explicit operation allowlist** | Only these operations can be signed: **BTC send**, **ERC-20 USDT `transfer`**, **TRC-20 USDT `transfer`**, plus **plain ETH / TRX transfers to your own allowlisted wallets** (to top up gas/energy fees). Everything else is rejected, **by the online core and again by the signer**: `approve`, `permit`, EIP-712 / message signing, EIP-7702 authorizations, arbitrary contract calls, TRON permission updates (except a deliberate, separately reviewed recovery flow). |
| P14 | **Build online, decode and validate on the signer** | Transactions are built by the online core, never accepted from a node. The signer decodes the unsigned tx field by field and runs the chain validator (§8) itself; **the signer's validation is authoritative** (rev 4). |
| P15 | **Independent review before real funds** | The signer app, the signing path and both release builds are reviewed by someone other than the author before Phase 4 (§15). |
| P16 | **Air gap by QR only** (rev 4) | No network, Wi-Fi, Bluetooth or cable between the two machines. Transactions cross only as QR codes. USB on the signer is allowed only to install a reviewed signer release and (optionally) to read the vault keyfile. |
| P17 | **One wallet unlocked at a time, for one signing session** (rev 4) | Each wallet has its own vault and password; unlocking one never decrypts another. Vault-tier seeds are **stateless** (never stored). Secrets are wiped right after signing. |
| P18 | **No automatic or batch signing, ever** (rev 4.1) | Every signature needs a separate human decision on the signer screen for that one transaction (§7 ⑦d). There is no auto-approve, "trusted requester", scheduled, API-driven or "sign all" mode, and none may be added later for convenience. The only multi-signature session is the two keys of one BTC multisig spend, and each is still approved on screen. This is the exact weakness behind the Binance 2026 theft (§14D). Code review and CI check that the signer has no code path that signs without the approval screen. |

---

## 4. Multi-wallet model

The ChatGPT chat recommended separating "long-term BTC", "USDT savings" and "day-to-day transfer" wallets. This design formalises that as **tiers**. Each tier is a separate wallet with **its own recovery phrase**, so compromising a lower tier never exposes a higher one.

> **Change from the chat:** the chat proposed one shared vault/seed with three chain adapters. That still applies **inside** a tier (one seed → BTC + ETH + TRON addresses). But across tiers, use **separate seeds**. One seed for everything would make a single leak catastrophic.

> **Rev 4:** all tiers sign on **one offline signer laptop**. Because that laptop now sees every key, the tiers are also separated **on the laptop**: one encrypted vault and password per wallet, passphrases that are never stored, and a stateless Vault tier (§4.1a, §6.4).

### 4.1 Tiers

| Tier | Purpose | Share of holdings (suggested) | Signing (rev 4) | Seed backup | How often used |
|---|---|---|---|---|---|
| **T-0 Vault** | Long-term reserve | Majority (e.g. 70–85%) | Offline signer, **stateless**: the seed is never stored on the laptop; it is scanned from a **SeedQR card** (or typed from the words) at signing time, plus a **BIP-39 passphrase** typed from memory/paper. BTC: **2-of-3 multisig** of three stateless seeds. ETH USDT and TRON USDT: single-sig on dedicated seeds. **See §4.1b** | Each seed: steel/paper words + SeedQR card at its own location; passphrase stored at a **different** location | Rarely (a few times a year) |
| **T-1 Savings** | Medium-term, occasional moves | e.g. 10–25% | Offline signer, **stored** encrypted vault with its own password, **plus** a BIP-39 passphrase typed at each signing (never stored) | 2 metal/paper copies, 2 locations; passphrase separate | Monthly |
| **T-2 Spending** | Daily/weekly transfers | **Hard cap**, e.g. ≤ ₹50,000 (≈0.5% at ₹1 Cr) | Offline signer, **stored** encrypted vault with its own password | 2 paper copies | Weekly |
| **T-W Watch-only** | Exchange deposit addresses, old wallets, other people's addresses you track | n/a | **None** (public addresses/xpubs only) | n/a | Read-only |

**There is no software wallet on the online PC (rev 4).** Rev 3's "weak mode" (a seed decrypted on the Windows PC) is removed entirely; even Spending signs on the offline laptop.

The percentages and cap are suggestions. Pick your own numbers in Phase 0 and write them down; the app enforces them in Phase 3.

### 4.1a Security domains: independent keys (rev 2, extended in rev 4)

The review warned that one seed deriving BTC + ETH + TRON keys is a single point of failure. Rev 4 adds a second single point: **one laptop signs for everything**. This design handles both in layers:

| Rule | Detail |
|---|---|
| **Separate seed per tier** | A Spending leak never reaches Savings or Vault. |
| **Separate seeds per chain inside the Vault** | The 3 BTC multisig seeds are used **only** for BTC. Vault USDT (ETH/TRON) uses **its own** seed(s), so one leaked seed can't reach both BTC and USDT reserves. |
| **Savings: one seed for 3 chains is accepted** | A usability trade-off, protected by the offline signer + passphrase + monitoring. If Savings grows above ~₹10 lakh, split it into `savings-btc` and `savings-usdt` with separate seeds. |
| **(rev 4) Separate vault per wallet on the signer** | Each stored wallet (Spending, Savings) is its own encrypted file with its **own password**. Unlocking Spending never decrypts Savings. Only one wallet is decrypted at a time, only for one signing session (§6.4). |
| **(rev 4) Passphrases never stored** | Savings and Vault seeds use a BIP-39 passphrase that is typed at signing and never saved. A stolen laptop, or a copied vault file plus its password, is useless without it. |
| **(rev 4) Stateless Vault** | Vault seeds are never written to the laptop's disk. Even a full forensic copy of the laptop reveals nothing about the Vault. |
| **Seeds never enter the online PC** | Not typed, scanned, pasted or photographed. |
| **No recovery phrase on any USB** | The USB holds only non-secret recovery material (§6.3). |

### 4.1b Actual protection level per asset (rev 4)

The Vault is **not** equally protected on every chain, and one laptop now signs for all of it. This table is the honest state for v1; nothing elsewhere in this document should be read as implying more.

| Asset & tier | v1 signing design | Survives 1 leaked seed / 1 burgled location? | Survives a compromised offline signer? | Who signs | Upgrade path |
|---|---|---|---|---|---|
| BTC Vault | 2-of-3 P2WSH multisig, three stateless seeds | **Yes** | **No**: both signing seeds pass through the same laptop | Custom offline signer, only when `custom_signing_vault = true` (§15.2). Independent recovery with Sparrow, without the custom app | Make key #3 a hardware wallet (D1) so no single machine ever holds 2 keys |
| ETH USDT Vault | Single-sig, dedicated stateless seed + passphrase | Only if the passphrase isn't also leaked | No | Same as above | Safe 2-of-3 (Phase 7) |
| TRON USDT Vault | Single-sig, dedicated stateless seed + passphrase, permission baseline monitored | Only if the passphrase isn't also leaked; a permission change is detected, not prevented | No | Same as above | TRON permission multisig (Phase 7) |
| Savings (all 3) | Stored vault + passphrase | Only if the passphrase isn't also leaked | No | Custom offline signer **only if** the §15 independent review passed | Split seeds per chain (§4.1a) |
| Spending (all 3) | Stored vault | No; loss is limited to the cap | No; loss is limited to the cap | Custom offline signer | — |

**The biggest remaining risk is the offline signer itself.** It is protected by the air gap (§9.4b), physical security, the stateless Vault, per-wallet vaults and passphrases, and by keeping the signer software small and independently reviewed.

**Before `custom_signing_vault` is enabled,** the Vault is **receive-only**. In an emergency, BTC Vault funds can be spent with a mature independent wallet that supports offline PSBT signing (e.g. Sparrow, installed on the offline laptop from a verified download), and ETH/TRON Vault funds by restoring the seed + passphrase into a standard wallet on a freshly installed machine and moving them straight to a new seed. Both procedures are in the recovery runbook and are tested on testnet (§6.5).

Because the ETH and TRON USDT Vault holdings have single-seed protection, keep their seed backups to the strictest standard (§6.3) and decide in Phase 0 how much of the reserve you accept holding with single-seed protection (D4).

### 4.2 Money flow between tiers

```
              (rare, planned, cool-down 48h)
   ┌───────────────────────────────────────────┐
   ▼                                           │
┌──────────┐   top-up (monthly)   ┌──────────┐ │ top-up (weekly)  ┌──────────┐
│ T-0 VAULT│ ───────────────────▶ │T-1 SAVING│ ─┴────────────────▶ │T-2 SPEND │ ──▶ outside world
│ stateless│                      │ vault +  │                     │  vault,  │
│ (SeedQR) │                      │passphrase│                     │  capped  │
└──────────┘                      └──────────┘                     └──────────┘
     ▲  incoming deposits go to Vault/Savings receive addresses; never "pass through" Spending
```

Rules:
- Funds flow **downward only** (Vault → Savings → Spending → out). Sending *to* a higher tier is always allowed.
- Outside addresses can be paid from **Spending** freely (within limits), from **Savings** only to allowlisted addresses, and from **Vault** only to Savings (pre-allowlisted on the signer).
- These rules are enforced **twice**: by the online policy engine and by the signer's own policy (§7 ⑦c).
- Spending's cap means the most a compromised signer session or a tricked approval can lose from Spending is that cap.

### 4.3 Wallet inventory (no secrets)

Kept in the online app's public data store, on the signer (public part only) and as an encrypted copy on the backup USB:

| Field | Example |
|---|---|
| Wallet ID / label | `vault-btc-2of3`, `savings-01`, `spend-01` |
| Tier | T-0 / T-1 / T-2 / T-W |
| Networks | BTC, ETH (USDT), TRON (USDT) |
| Signer type (rev 4) | offline-stored / offline-stateless / none (future: hardware) |
| Fingerprint & xpub / descriptor | `[a1b2c3d4/84'/0'/0']xpub…` |
| Derivation paths & account index | `m/84'/0'/0'`, `m/44'/60'/0'/0/0`, `m/44'/195'/0'/0/0` |
| Public addresses | per network |
| Passphrase dependency | yes/no (never the passphrase itself) |
| Backup locations (described, not revealed) | "Seed A: location 1, metal plate + SeedQR card" |
| Recovery instructions | step-by-step, without any secret |
| Limits & policy | daily cap, allowlist ID, cool-down |

**Never in the inventory:** seed words, SeedQR images, private keys, passphrases, passwords, PINs, exchange passwords, 2FA recovery codes.

---

## 5. System architecture

### 5.1 Component overview (rev 4)

```
┌──────────────────────────── ONLINE PC — Windows (untrusted, holds NO secrets) ────────────────────────────┐
│                                                                                                          │
│  ┌─────────────────────────────┐   narrow IPC     ┌──────────────────────────────────────────────────┐   │
│  │  UI  (React + TypeScript)   │ ───────────────▶ │  Online Core  (Rust, Tauri backend)              │   │
│  │  WebView2, strict CSP,      │  typed commands  │  Policy engine · Tx builder & review ·           │   │
│  │  no remote content          │ ◀─────────────── │  Address book · Chain adapters · Data store ·    │   │
│  │  Portfolio · Receive · Send │   view models    │  Audit log · Start-up checks · Login ·           │   │
│  │  Activity · Wallets · Alerts│   (no secrets)   │  Air-gap QR encoder/decoder                      │   │
│  └─────────────────────────────┘                  └──────────┬───────────────────────────┬───────────┘   │
└──────────────────────────────────────────────────────────────┼───────────────────────────┼───────────────┘
            HTTPS/WSS                                          │ screen ⇄ webcam (QR ONLY) │ checkpoints
  ┌─────────────────────────────┐                              │                           ▼
  │ Blockchain data sources     │◀──── online core ────────────┤          ┌────────────────────────────────┐
  │ ≥2 per network, cross-check │                              │          │ Independent monitor (§10)      │
  │ own pruned Bitcoin Core     │                              │          │ watch-only, separate device    │
  └─────────────────────────────┘                              │          └────────────────────────────────┘
                                         unsigned tx + Intent  │  ▲  signed tx + signer receipt
                                                               ▼  │
┌──────────────────── OFFLINE SIGNER — dedicated laptop, minimal Linux, NO network hardware ───────────────┐
│  Signer UI (native Rust GUI, full-screen kiosk, no WebView, no browser)                                  │
│  Signer Core (Rust):                                                                                     │
│   ├─ Air-gap QR decoder (strict framing, size limits, fuzzed)                                            │
│   ├─ Chain validators (§8) — AUTHORITATIVE copy                                                          │
│   ├─ Signer policy: own allowlist, per-wallet limits, hash-chained signing log                           │
│   ├─ Wallet registry (public: fingerprints, xpubs, descriptors)                                          │
│   ├─ Vaults: one encrypted file + password per stored wallet (Spending, Savings)                         │
│   ├─ Stateless loader: SeedQR / typed words + passphrase for the Vault tier, never written to disk       │
│   └─ Signing (secp256k1, RFC 6979 deterministic nonces), zeroize after every session                     │
│  TRUSTED: its screen + your approval                                                                     │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Trust boundaries

| Boundary | Trusted side | Untrusted side | What crosses it |
|---|---|---|---|
| **B1** UI ↔ Online core | Online core | UI (a web view can be attacked through rendered data, so treat it as hostile) | A small set of typed commands, each validated in Rust and checked against a state machine; view models without secrets. Final authorization happens **only on the offline signer** (§0, §7 ⑦). |
| **B2** Online core ↔ Internet | Online core | RPC/API providers | Signed raw transactions out; chain data in (always validated and cross-checked) |
| **B3** Online PC ↔ Offline signer (air gap, rev 4) | Offline signer | The whole online PC | **QR codes only.** In: unsigned tx + Intent. Out: signed tx + signer receipt. The signer treats every incoming QR as hostile input. Nothing else crosses: no network, no Bluetooth, no shared USB. |
| **B4** Digital ↔ Physical backups | Offline backups | Everything digital | Nothing automated. Seeds are written by hand. SeedQR cards are physical and only ever shown to the **offline** signer's webcam. |
| **B5** People ↔ Offline signer (rev 4) | You | Anyone else with physical access | Disk encryption, BIOS password, tamper-evident seals, locked storage (§9.4b). |

### 5.3 Technology stack (from the chat, with additions)

| Layer | Choice | Why / notes |
|---|---|---|
| Online desktop shell | **Tauri 2** (Windows) | Small, Rust backend, capability-based permissions. Better security model than Electron for this use. |
| Online UI | **React + TypeScript** (Vite) | From the chat. No external CDN, no remote scripts. |
| Offline signer OS (rev 4) | **Minimal Debian stable** (or similar), installed offline from a verified ISO, LUKS2 full-disk encryption | Mature, well-documented, easy to strip down. |
| Offline signer UI (rev 4) | **Native Rust GUI** (`iced` or `egui`), full-screen kiosk | No WebView, no JavaScript, no browser engine on the signing machine: a much smaller attack surface for hostile QR input. |
| Core language | **Rust** on both machines | Memory safety; `zeroize`/`secrecy` for secrets. Types, encoders and validators are **shared crates**, so the signer and the online core run the same reviewed code. |
| Bitcoin | **rust-bitcoin** + **BDK** | Online: descriptors, sync, coin selection, PSBT building. Signer: PSBT validation and signing. |
| Ethereum | **Alloy** | Modern successor to ethers-rs (deprecated). EIP-1559 tx, ABI encoding. |
| TRON | **Rust implementation of TRON tx protobuf + base58check** | Decided in rev 4: no TronWeb or sidecar is needed, because there is no vendor JS SDK to integrate. |
| BIP-39 / BIP-32 | `bip39`, `bitcoin::bip32` | Vetted crates; checked against official test vectors. |
| Vault encryption (signer only) | **Argon2id** (KDF) + **XChaCha20-Poly1305** (AEAD), optional keyfile | Per-wallet vault files (§6.4). DPAPI is no longer used: no secret ever lives on Windows. |
| Air-gap transport (rev 4) | **QR codes**: animated multi-part QR (fountain-coded, BC-UR style) for large payloads such as PSBTs with full previous transactions; **CompactSeedQR** for stateless seeds | Webcam on both machines. Frame size, total size and part count are capped. |
| Local data | **SQLite** (online, encrypted private parts); signer: small vault files + an append-only, hash-chained signing log | Public data online: addresses, history, labels, settings. |
| Hardware signer | **None in v1.** The `Signer` trait keeps a slot for one later (D1) | |

### 5.4 Project structure (rev 4)

Each Rust module from the chat becomes a separate crate, so the secret-handling code stays small and auditable.

```text
D:\Crypto\
├── docs/
│   ├── ARCHITECTURE.md              ← this file
│   ├── security-model.md            ← threats/controls, kept in sync with §2 and §12
│   ├── recovery-runbook.md          ← how to recover each wallet WITHOUT this software
│   ├── incident-runbook.md          ← what to do if something looks wrong
│   ├── signer-setup.md              ← (rev 4) preparing and checking the offline laptop (§9.4b)
│   └── release-gate.md              ← evidence for each §15 gate item
├── app/                             ← ONLINE Tauri application (Windows), no secrets
│   ├── src/                         ← React + TS UI
│   │   ├── pages/ (portfolio, receive, send, activity, wallets, alerts, settings)
│   │   └── components/
│   └── src-tauri/
│       ├── capabilities/            ← Tauri permission allowlist
│       ├── tauri.conf.json          ← strict CSP
│       └── src/commands.rs          ← the ONLY UI→core entry points
├── signer-app/                      ← (rev 4) OFFLINE signer, native Rust GUI, Linux only
│   └── src/ (screens: unlock, scan, review, approve, show-signed, wallet-setup, allowlist)
├── crates/
│   ├── wallet-types/                ← Amount (integer), Network, Address, WalletId …
│   ├── wallet-core/                 ← online orchestration, wallet registry, tiers
│   ├── policy/                      ← online allowlist, limits, cool-downs, tier flow rules
│   ├── tx-review/                   ← builds the human-readable review from the *final* unsigned tx (used on both machines)
│   ├── chain-btc/                   ← BDK, descriptors, PSBT, fee sanity
│   ├── chain-eth/                   ← Alloy, ERC-20 transfer only, nonce/gas checks
│   ├── chain-tron/                  ← TRC-20 transfer, energy/bandwidth, permission watch
│   ├── validators/                  ← (rev 4) the §8 pre-sign validators, shared; the signer's copy is authoritative
│   ├── airgap-qr/                   ← (rev 4) QR framing, versioning, size limits, strict decoder (fuzzed)
│   ├── data-sources/                ← multiple RPC providers + cross-check (online only)
│   ├── signer/                      ← Signer trait
│   │   ├── signer-offline/          ← (rev 4) vault files, stateless SeedQR loader, signing, zeroize
│   │   └── signer-hw/               ← reserved for a future hardware wallet (not v1)
│   ├── signer-policy/               ← (rev 4) the signer's own allowlist, limits and signing log
│   ├── store/                       ← SQLite, encrypted columns, migrations (online)
│   └── audit-log/                   ← append-only, hash-chained log
├── tests/
│   ├── vectors/                     ← BIP-32/39/44/84, EIP-155, TRON address test vectors
│   ├── derivation/
│   ├── transactions/
│   ├── recovery/                    ← restore in a 3rd-party wallet and compare addresses
│   ├── airgap/                      ← (rev 4) malformed/oversized/replayed/wrong-wallet QR payloads
│   └── adversarial/                 ← malicious RPC, fake token, look-alike addresses
├── monitor/                         ← independent watch-only monitor, runs on a separate device
│   ├── watcher/                     ← polls chains, validates state, keeps checkpoints
│   └── config/                      ← addresses/xpubs (watch-only), baselines, alert channels
├── config/
│   └── networks.v1.toml             ← signed network/token/policy configuration (§9.6)
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
| Safety | Provider agreement can **never** replace the §8 validators or the signer check. |
| Bitcoin own node (moved earlier) | A pruned **Bitcoin Core** node is the BTC source **from Phase 1 where practical** (on the monitor device, §10, or the wallet PC), rather than Phase 5. External BTC APIs then serve only as a second opinion. |
| Ethereum/TRON | Running full nodes is optional (heavy). Safety rests on local construction + validation + the signer; providers supply data only. |

---

## 6. Key, seed & backup management

### 6.1 Seed generation (rev 4)

| Rule | Detail |
|---|---|
| Where | **On the offline signer**, for every production wallet. Never on the online PC, never on a website. |
| Pre-check | The signer refuses to generate a seed if any network interface other than loopback exists, or if a Wi-Fi/Bluetooth device is detected (§9.4b). |
| How | OS CSPRNG (`getrandom`) **mixed with ≥ 99 physical dice rolls** you enter (SHA-256 over both). A weak RNG or a weak dice set alone can't weaken the result. Never `rand::thread_rng` seeded by time, never your own algorithm. BIP-39 **24 words**. |
| Verification | After you write the words down, the signer asks for random words back. For Vault seeds it then displays the **SeedQR** for you to copy onto a card by hand (or print on the signer's own printer, if one is ever dedicated to it; never on a shared printer). |
| BIP-39 passphrase ("25th word") | **Required for Vault and Savings (rev 4)**, because there is no secure element: it is the layer that protects against a stolen seed backup and a stolen laptop. If you forget it, the funds are gone, so store it **separately** from the seed and test it before funding. Not needed for Spending. |
| Fingerprint record | The master fingerprint of seed + passphrase is recorded in the wallet registry and on the recovery manifest. At every signing the signer checks it, so a mistyped passphrase (which silently opens a different, empty wallet) is caught. |

### 6.2 Derivation paths (one seed → three networks)

| Network | Standard | Account path | First receive address |
|---|---|---|---|
| Bitcoin (single-sig) | BIP-84 native SegWit (`bc1q…`) | `m/84'/0'/0'` | `m/84'/0'/0'/0/0` |
| Bitcoin (multisig) | BIP-48 P2WSH | `m/48'/0'/0'/2'` | via descriptor `wsh(sortedmulti(2, …))` |
| Ethereum | BIP-44 | `m/44'/60'/0'` | `m/44'/60'/0'/0/0` |
| TRON | BIP-44, coin type 195 | `m/44'/195'/0'` | `m/44'/195'/0'/0/0` |

Exit test: restore each seed in **at least one other well-known wallet** and confirm the exact same addresses appear. If they differ, your derivation is wrong. Fix it before funding.

### 6.3 Backup layout (three separate things, never together)

This is the chat's "cold signer + encrypted USB + offline recovery" model, made concrete (rev 4: the cold signer is the offline laptop):

| Backup | Contains | Medium | Where |
|---|---|---|---|
| **Seed backup A** | Seed words (one wallet/key) | Stamped steel plate (fire/water resistant) | Location 1 (home safe) |
| **Seed backup B** | Same seed words | Steel plate or paper in a sealed tamper-evident bag | Location 2 (bank locker / trusted family) |
| **SeedQR card** (rev 4, Vault seeds) | The seed as a CompactSeedQR. **It is the seed** | Hand-copied card in a sealed tamper-evident bag | With seed backup A of the same key |
| **Passphrase** (Savings, Vault) | BIP-39 passphrase | Paper | **A different location** from its seed |
| **Encrypted USB** | Wallet inventory, BTC multisig descriptors + xpubs, recovery runbook, app config export. **No seeds, no keys.** | VeraCrypt container on a dedicated USB (or a hardware-encrypted drive such as a keypad-locked USB) | With Location 1; a 2nd copy at Location 2 |
| **Printed runbook** | Recovery steps in plain language (for you or your heir) | Paper | With each seed location |

For **T-0 2-of-3 multisig**, the three keys' seeds go to **three different locations**. Any one location being burgled or burned loses nothing; any two can recover the funds. **Each location also needs a copy of the descriptor** (it's not secret enough to hurt, and multisig recovery is impossible without it).

Never: photos, cloud drives, email, WhatsApp, password managers, notes apps, text files, screenshots, or typing/scanning any seed or SeedQR into the online PC. A seed is only ever shown to the offline signer.

**USB backups still expose information (rev 3).** "No seed on USB" removes theft of funds, not exposure: descriptors, xpubs, address lists, labels and runbooks reveal your holdings and history and help someone target you. So:

| Rule | Detail |
|---|---|
| Minimize | Only what recovery needs: recovery manifests (§6.6), descriptors/xpubs for multisig, the runbook. **No** balances, transaction history, labels like "main savings ₹40L", exchange accounts or personal ID documents. |
| Encrypt | VeraCrypt container (or hardware-encrypted drive) with a strong passphrase that isn't stored with the drive. |
| Verify | Every 6 months: open **both** USB copies on an offline machine other than the signer, check the SHA-256 of each file against the hash list on paper, and confirm the content is current. Recovery drills (§6.5) use the USB copies, not your working files. |
| Retire | Old copies are overwritten and then **physically destroyed** (drill/shred the flash chip). Never sold, reused or thrown away whole. Retirement is logged on paper. |
| Printed runbook check | Before printing or storing, the runbook is checked (by you, and by the reviewer once) to contain **no** seed words, passphrases, PINs or hints to them. |

### 6.4 Offline signer vaults and stateless signing (rev 4)

Rev 3's Windows "software vault" and its "weak mode" are removed. All seeds live only on the offline signer, in one of two forms.

**Stored wallets (Spending, Savings):** one vault file per wallet.

```
password ──Argon2id(m=512 MiB, t=4, p=1, 16-byte salt)──┐
[optional] keyfile (32 bytes, on a separate USB) ───────┴─HKDF-SHA256──▶ KEK
random 32-byte DEK ──XChaCha20-Poly1305(KEK)──▶ wrapped DEK
seed ──XChaCha20-Poly1305(DEK, 24-byte nonce, AAD = wallet_id ‖ version)──▶ wallet-<id>.vault
whole disk ──LUKS2 (Argon2id)──▶ encrypted at rest
```

**Stateless wallets (Vault):** there is no vault file. At signing time:
1. The signer asks for the SeedQR card (webcam) or the 24 words (keyboard), then the passphrase.
2. It derives the master fingerprint and compares it with the registry. A mismatch → stop.
3. It signs, wipes the seed, and keeps nothing on disk. Camera frames are processed in memory and never saved.
4. For the BTC 2-of-3 Vault this repeats for the second seed in the same session.

**Rules for both:**
- **One wallet at a time.** Each stored wallet has its **own password**; unlocking one never decrypts another.
- **Minimal unlocked time.** A seed is decrypted only for one signing session (one Intent, or the two signatures of a BTC multisig spend), then `zeroize`. Browsing the signer's screens never decrypts a seed.
- **Memory.** Secrets live in `secrecy::SecretBox` with `zeroize` on drop, in `mlock`-ed pages. Swap, hibernation and core dumps are disabled on the signer (§9.4b).
- **Key material never leaves the signer**, never appears in a QR code (except the SeedQR you copy at creation), and never goes into a log.
- **Lock and power-off.** The signer locks after each signing session and after 2 minutes idle. Power it off after every session.
- **Atomic writes** (write temp → fsync → rename) with a versioned header, so a crash can't corrupt a vault file.
- **Wrong passwords:** increasing delay; after 5 failures the signer needs a reboot (the Argon2 cost already makes guessing slow).

**Why stateless for the Vault.** Someone who steals the laptop **and** learns your passwords still gets nothing from the Vault. The cost is that you bring the SeedQR card out each time you move Vault funds, which is rare. While a card is out of storage it is as sensitive as the seed itself (T20): carry it in a sealed bag, never photograph it, and return it the same day.

**Recovery & portability.** Vault files are **not** backups and are never copied to USB. Disaster recovery for any wallet = **restore from its paper seed (+ passphrase)** into a fresh signer, or into any BIP-39 wallet. Losing the laptop must never mean losing funds.
- Test (Phase 2 gate): wipe the signer, reinstall it from scratch, restore each test wallet from paper, and confirm the same addresses. Then restore the same seeds in an **independent** wallet and confirm again.

### 6.5 Recovery drills

| When | What |
|---|---|
| Before funding any wallet | Full restore of every seed on a clean device; compare addresses |
| Every 6 months | Restore **one** wallet (rotate which) and check balances in watch-only mode |
| After any change to multisig setup | Full 2-of-3 recovery test on testnet with the real seeds and the offline signer, and again with Sparrow |

**(rev 3) Every drill uses only what is stored at the backup locations** (seed plates, passphrase paper, USB copies, printed runbook), **on a machine without the custom app**, following the recovery manifest step by step. If any step needs something that isn't at a backup location, the drill fails and the manifest is fixed.

### 6.6 Recovery manifest per wallet (rev 3)

"Restore every seed" isn't enough when a wallet uses a passphrase, a multisig descriptor, a Safe or custom TRON permissions. Every wallet has a manifest (no secrets) stored on paper with each seed location and in the encrypted USB:

| Field | Example |
|---|---|
| Wallet ID, tier, networks | `vault-btc-2of3`, T-0, BTC |
| Script / account type | P2WSH 2-of-3 `sortedmulti` (BIP-48); or P2WPKH (BIP-84); or ETH EOA; or TRON account |
| Derivation path(s) & account index | `m/48'/0'/0'/2'` |
| Descriptor / contract / account config | Full descriptor with checksum; Safe address + version (if ever used); TRON permission baseline (§8.5) |
| Signers | Each key: signer type (offline-stored / offline-stateless / future hardware), master fingerprint, passphrase yes/no, which backup location holds its seed and SeedQR card |
| Threshold | 2 of 3 |
| Passphrase dependency | "Yes, BIP-39 passphrase, stored at location C", or "No" |
| Expected first addresses | First 3 receive addresses (to confirm the restore is correct) |
| Recovery software | e.g. Sparrow Wallet ≥ version X (verified download) for BTC; for TRON/ETH single-sig: any BIP-39 wallet supporting the path and the passphrase |
| Recovery steps | Numbered steps that end with **spending** a small amount, not just seeing the balance |
| Last tested | Date + result |

For multisig and smart accounts, the drill must prove **ability to spend** (a small testnet or mainnet tx signed by the threshold), not just that the individual keys restore.

---

## 7. Transaction security pipeline

Every outgoing transaction passes through the same pipeline. Any stage failing → **stop** and show why.

```
 ONLINE PC     ① Draft ─▶ ② Validate ─▶ ③ Policy ─▶ ④ Build ─▶ ④b Validate ─▶ ⑤ Simulate ─▶ ⑥ Review
                                                                                              │ QR
 OFFLINE       ⑦a Decode ─▶ ⑦b Validate (authoritative) ─▶ ⑦c Signer policy ─▶ ⑦d Display & approve ─▶ ⑦e Unlock & sign
 SIGNER                                                                                       │ QR
 ONLINE PC     ⑧ Verify ─▶ ⑨ Broadcast ─▶ ⑩ Monitor
```

| Stage | What happens | Stops these threats |
|---|---|---|
| **① Draft** (online) | Pick source wallet, asset+network, recipient (**from the address book only** for Savings/Vault; preferred for Spending), amount. Pasting is allowed for Spending but flagged. | — |
| **② Validate** (online) | Address checksum & format per network: bech32/bech32m (BTC), EIP-55 checksum (ETH), base58check `T…` (TRON). Reject cross-network addresses (e.g. TRON address for ERC-20 USDT). Amount is an integer in base units, > 0, ≤ balance minus fee. | Typos, wrong network (T9) |
| **③ Policy** (online) | Tier flow rules (§4.2); allowlist check; limits per §7.4; **new-address cool-down** (e.g. 24 h for Savings, 48 h for Vault), measured in trusted time (§9.5); **look-alike check** (rev 4, strengthened): any address in history or the address book that shares **≥ 3 leading or ≥ 3 trailing characters** with the recipient but isn't identical → **block** and show both. If the policy state can't be established as current (§9.5) → **no sends**. On success the core creates an immutable **Transaction Intent** (§7.3). | Address poisoning (T3), rushed decisions (T12), partial PC compromise (T1, T2) |
| **④ Build** (online) | The core builds the unsigned tx **locally**: PSBT (BTC), EIP-1559 tx calling `transfer(to, amount)` on the **pinned** USDT contract (ETH), `TriggerSmartContract` on the **pinned** USDT contract (TRON). Nodes only supply inputs (UTXOs, nonce, recent block reference, fee data), each cross-checked. A node-built tx is never signed as-is. No `approve` ever (P13). | Fake tokens, approvals (T6), node-built tx tampering (T10) |
| **④b Chain validator** (online) | The same §8 validator the signer runs, run online first so bugs are caught before you walk to the signer. **Not authoritative**: ⑦b is. | App bugs (T9) |
| **⑤ Simulate** (online) | ETH: `eth_estimateGas` + `eth_call` on ≥2 providers. TRON: `triggerconstantcontract` for energy estimate; check TRX available for fees. BTC: fee policy in §8.1. Also the checks the signer **can't** do offline: UTXOs unspent, ETH nonce on chain, TRON permission baseline and fresh solidified ref block, no EIP-7702 code (§8.2). An override can raise a fee cap only up to its hard maximum and **never** skips any other check. | Lying RPC (T10), fee drain |
| **⑥ Review & hand-over** (online) | Review screen generated **from the final unsigned tx bytes** (decoded again). Shows wallet, network, asset, full recipient (chunked `bc1q 7x9a …`), label, amount, fee, total, new-address warning, and the **Intent short hash** (first 8 hex characters). Then the unsigned tx + Intent are shown as an (animated) **QR code**. **A bug-catcher and convenience, not an authorization control.** | App bugs (T9), WebView-only compromise (T16) |
| **⑦a Transfer & decode** (signer) | The signer reads the QR with its webcam. Strict framing: protocol version, payload type, total size and part count are capped; unknown types, unknown wallet IDs or fingerprints, and anything that doesn't decode **exactly** → reject. | Malicious QR payload (T19) |
| **⑦b Chain validator: authoritative** (signer) | The §8 validator runs on the signer against the decoded bytes **and** the Intent. Plus checks the signer can make from its own records: its signing log (an ETH/TRON nonce is never reused or lower than the last one it signed; BTC inputs aren't signed into two conflicting transactions unless the Intent is an explicit `BtcRbfBump`); change addresses are re-derived from the wallet's own keys; TRON `expiration` is checked against the signer clock (±10 min tolerance). | Malicious/confusing tx (T5, T15), compromised online PC (T1), own bugs (T9) |
| **⑦c Signer policy** (signer) | The signer keeps its **own allowlist, per-wallet limits and signing log** (§7.1, §7.4), independent of the online PC. Vault → recipient must be one of your own Savings addresses (derived by the signer itself). Savings → recipient must be on the signer allowlist and past its cool-down. Spending → within its per-tx and per-day caps. | Fully compromised online PC (T1), rushed decisions (T12) |
| **⑦d Display & approve: THE authorization boundary** (signer) | Full-screen display: wallet, tier, network, asset and contract, **full recipient address** (chunked) and its signer-allowlist label, amount, fee, BTC change (marked as change), nonce/expiration, Intent short hash. You compare **character by character** with your source of truth (§7.1): the paper address book or an out-of-band confirmation, **never the online screen alone**. To approve you **type the last 6 characters of the recipient address from your paper record**; a mismatch rejects. If any field can't be shown clearly → reject (P4). | Malware (T1), clipboard (T2), blind signing (T5) |
| **⑦e Unlock & sign** (signer) | Only now is the wallet unlocked: stored wallet → its password (+ keyfile if used) + passphrase for Savings; Vault → SeedQR card(s) + passphrase (§6.4). Fingerprint check, sign (`SIGHASH_ALL`, RFC 6979 deterministic ECDSA), `zeroize`, append to the signing log. The signer shows the signed tx as a QR + a **receipt** (signed-tx hash, signing-log sequence and head hash). | Secret exposure (T17), offline theft (T18) |
| **⑧ Verify** (online) | The online core decodes the signed tx and checks it matches the **Intent** and the reviewed unsigned tx field by field (recipient, amount, fee, nonce/inputs/ref-block), that each signature verifies against the expected pubkey, and that the receipt matches. Only then may the app broadcast. **Limitation:** this protects the app's own broadcast path; malware on the online PC can capture the signed QR and broadcast it itself. That's why ⑦d is the boundary. | Malicious signer build (T8, T19), app bugs (T9) |
| **⑨ Broadcast** (online) | Send to ≥2 independent providers (§5.5). Record txid. The txid must equal the one computed in ⑧. | Censorship/single provider failure |
| **⑩ Monitor** | Track confirmations on ≥2 sources. BTC: wait ≥ 3 confirmations for "done", ETH/TRON: finalized/solidified block. Write to audit log; send the signer receipt to the monitor checkpoint (§9.5). | Fake "confirmed" (T10) |

### 7.1 Address book & allowlist (rev 4: two copies plus paper)

| Copy | Role |
|---|---|
| **Online address book** | Convenience and the online policy (③). Not trusted. |
| **Signer allowlist** | **Authoritative** for Savings and Vault sends (⑦c). Lives only on the offline signer. |
| **Paper address book** | Label + full address of every outside recipient, kept with the runbook. It is what you compare against in ⑦d. |

- Each entry: label, network, address, **added-at**, **verified-by** (e.g. "checked with recipient by phone"), tier permissions, entry version.
- **Own wallets:** the signer **derives your own addresses itself** from the keys or xpubs it holds, so own-wallet entries need no manual typing and can't be faked by the online PC. Before first use, also confirm the receive address on the signer's screen (§7.2).
- **Outside recipients:** verified out of band (phone call, second channel, small test tx) and the method recorded. Added to the signer by scanning a QR from the online PC **and then confirming it character by character against the paper copy on the signer screen**, or by typing it on the signer.
- A new entry is usable only after its cool-down expires: on the online PC in trusted time (§9.5), and on the signer by its own clock.
- **Integrity rules (rev 3, kept):**
  - **Edit = delete + new entry.** Changing an address, network or tier permission creates a new entry that needs fresh verification and a new cool-down. Only the label can change without one.
  - Every online add/remove is part of the **policy state** (§9.5): versioned, anchored outside the PC, alerted by the monitor ("address added to Savings allowlist").
  - **Restoring a backup never restores trust.** Entries imported from any backup or older database come back as *unverified* and must be re-verified with a new cool-down. A removed address stays on a **revocation list** so an old snapshot can't bring it back silently.
- **Never** fill the recipient from transaction history with one click; history is exactly where poisoned addresses show up.

### 7.2 Receive flow

1. Select wallet + asset + network on the online PC (network shown in large text: "USDT on **TRON (TRC-20)**").
2. Show address + QR. **"Verify on signer"**: the offline signer derives the address for the same wallet and index from its own registry (no unlock needed; it uses the stored xpub/descriptor) and displays it. Compare the two. This stops malware on the online PC from swapping the receive address. Required for the first deposit to any address and for every Vault/Savings deposit.
3. Use a fresh BTC address each time (BIP-84 gap limit 20); ETH/TRON reuse the account address.
4. When a deposit arrives: show it with confirmations; ignore and **hide** 0-value / dust token transfers (poisoning attempts), and flag them in the activity log.

### 7.3 Transaction Intent & layer tests (rev 3, extended in rev 4)

**Intent:** an immutable record created at stage ③ and hashed (SHA-256 over a canonical encoding):
`{intent_id, wallet_id, chain, operation (enum, §8.0), recipient, amount_base_units, max_fee, nonce_or_inputs, policy_state_version, created_at_chain_time}`.

- Stages ④b, ⑦b and ⑧ compare the tx against the **Intent**, not against UI input or another stage's output. The signer shows the Intent short hash so you can check it matches the online review.
- Nothing in an Intent can change. Any change (new fee, new UTXOs, new nonce) = new Intent, new review, **new approval on the signer**.
- The Intent hash, the signer receipt and the outcome go to the audit log and the external checkpoint (§9.5).

**Recipient-substitution tests at every layer** (required suite, Phase 2/3): swap the recipient (and separately the amount and fee) at the **builder**, **IPC**, **QR channel** (a test harness that alters the QR payload between the machines) and **broadcast** layers. Expected result: caught by ⑦b/⑧, or visibly different on the signer screen. Neither "silently signed" nor "silently broadcast" may happen.

### 7.4 Limits: units, scope and anti-bypass (rev 3)

| Rule | Definition |
|---|---|
| **Primary unit = the asset** | Every limit is set in the asset's base units: sats (BTC), USDT base units (6 decimals), wei (ETH), sun (TRX). These need no price feed and always work. |
| Secondary unit = INR | An INR-equivalent limit is also checked online, using the **higher** of two independent price sources (conservative). If prices are unavailable or disagree by > 3%, only the asset limits apply **and** the INR limit is treated as already reached (no sends that need it). |
| Scopes (all apply at once) | Per transaction · per wallet per rolling 24 h · per tier per rolling 24 h · **global aggregate** across all wallets per rolling 24 h · per recipient per rolling 24 h. |
| Splitting | Splitting a payment over several transactions, wallets or Spending wallets doesn't help: the per-tier, global and per-recipient totals still apply. |
| Fees | Max fee per transaction (asset units + INR) and max total fees per 24 h. |
| Time | Online: rolling windows in trusted time (§9.5), never the Windows clock alone. |
| **(rev 4) Signer-side limits** | The signer enforces per-transaction and per-wallet rolling limits in asset units from **its own signing log and its own clock**. It sees every transaction it has ever signed, so these limits hold even if the online PC is fully compromised. |
| Fail closed | If the policy state, its version or trusted time can't be established → no sends. If the signer's log is unreadable → no signing (§9.7). |
| Honest scope | Online limits stop mistakes and rushed decisions; malware with full control of the online PC can skip them. Signer-side limits hold unless the signer itself is compromised. The hard caps are the balance held in each lower-tier wallet + your approval on the signer + the monitor. |

### 7.5 Signer errors, disconnects and cancellation (rev 4)

| Event | Behavior |
|---|---|
| QR can't be read / partial / times out | Nothing is signed. Re-display the same QR or restart from stage ③ (new Intent). |
| User rejects on the signer | Intent *rejected*; logged on both machines; no automatic retry. |
| **Signer validation (⑦a–⑦c) rejects a tx the online PC built** | **High alert.** Either a bug or the online PC is compromised. Stop sending, run the online-PC checks in the incident runbook. |
| Partial signature (e.g. one BTC multisig signature only) | Allowed only as an explicit multisig step inside one signing session; otherwise discard, never broadcast, log as an error. |
| Signed tx fails ⑧ | **Critical**: discard, stop signing for that wallet, alert the monitor, start the incident runbook (the signer build may be compromised). |
| Retry policy | **No automatic retries with changed fields.** A retry is a new Intent with a new approval on the signer. Re-sending the *same* signed tx after a network error is allowed (same txid). |
| Already signed but not broadcast | Signed blobs are never written to disk on either machine; the signer keeps only their hash in its log. On app exit they are erased; a new send needs a new Intent. |

---

## 8. Chain-specific rules

### 8.0 Operation registry (rev 3, updated for rev 4)

Signing is driven by a **closed list** (a Rust `enum` with no "other" variant). **Every operation has its own validator and its own negative tests; there is no generic `sign_transaction()` and no fallback for unrecognised types.**

| Operation | Validator (run online at ④b and authoritatively on the signer at ⑦b) | Allowed tiers (custom signer) | v1 status |
|---|---|---|---|
| `BtcSend` | §8.1 | Spending, Savings\*, Vault\*\* | Enabled |
| `BtcRbfBump` | §8.1 (fee policy, RBF) | Spending, Savings\*, Vault\*\* | Enabled |
| `EthUsdtTransfer` | §8.2 | Spending, Savings\*, Vault\*\* | Enabled |
| `EthNativeTransfer` (fee top-up / cancel) | §8.2b | Spending, Savings\*, Vault\*\*; **destination = own allowlisted wallet only** | Enabled |
| `TronUsdtTransfer` | §8.3 | Spending, Savings\*, Vault\*\* | Enabled |
| `TronNativeTransfer` (fee top-up) | §8.3b | Spending, Savings\*, Vault\*\*; **destination = own allowlisted wallet only** | Enabled |
| `SafeExecTransaction` | §8.4 (spec only) | — | **Not in v1** |
| `TronMultisigTransfer` / `AccountPermissionUpdate` | §8.5 (spec only) | — | **Not in v1** |
| Anything else (`approve`, `permit`, typed data, 7702, swaps, staking …) | none | — | **Rejected, no code path** |

\* Savings only when `custom_signing_savings = true` (§15.2). \*\* Vault only when `custom_signing_vault = true` (§15.2), and only to your own Savings addresses (§4.2). The signer enforces both flags itself.

Cross-tier native transfers follow §4.2: downward only to the next tier's own allowlisted address, upward always allowed. Each has the same limits (§7.4) as USDT, in the native asset's units.

### 8.1 Bitcoin

- Native SegWit (`bc1q`) for single-sig; P2WSH 2-of-3 multisig via descriptors for the Vault.
- **Vault multisig (rev 4):** three **stateless** seeds, each with its own SeedQR card and passphrase at its own location. To spend, two cards are brought to the offline signer in one session. This protects against one burgled location or one lost seed; it does **not** protect against a compromised signer, since both keys pass through it (§4.1b). Coordinator = the online app (via BDK) + one independent coordinator for recovery (e.g. Sparrow Wallet), so you're never dependent on your own code. Upgrade: make key #3 a hardware wallet (D1).
- Coin control: show UTXOs; avoid merging Vault UTXOs with Savings ones.
- Change output must go back to an address **derived from the same wallet descriptor** — re-derived and verified by the signer at ⑦b and again online at ⑧.
- RBF (replace-by-fee) enabled so a stuck tx can be bumped. No unconfirmed-input spending from outside sources.

**Pre-sign validator — BTC (rev 2).** Runs on the final PSBT; every check must pass:

| Check | Rule |
|---|---|
| Network | Mainnet addresses and descriptor only (no testnet keys on mainnet and vice versa). |
| Inputs | Every input belongs to **this wallet's descriptor** (script matches a derived address). Each input carries the **full previous transaction** (`non_witness_utxo`) as well as `witness_utxo`, and the prevout amount is checked against it. This defends against fee-lying attacks on SegWit inputs. |
| Outputs | Exactly **one recipient output** + at most **one change output**. No `OP_RETURN`, no extra outputs, no dust outputs. Recipient script == reviewed address. |
| Change | Change script is derived from the **same descriptor** on the internal (`/1/*`) chain, and the PSBT includes its `bip32_derivation` so the **signer recognises it as change** and displays it as change, not as a payment. If the signer can't match the change to its own keys → reject. |
| Outpoints (rev 3) | For each input: `txid(non_witness_utxo) == outpoint.txid` (recomputed locally); the referenced output's **amount and script** are read from that tx; the script is derived from **this descriptor** at the PSBT's stated path (re-derived locally, not trusted from the PSBT); the outpoint is **unspent** per your own node (or ≥2 independent sources until the node exists, §5.5). |
| Fee | Fee = Σinputs − Σoutputs, **computed locally** (never taken from a provider). Must satisfy the fee policy below. |
| Fields | Version 2; locktime 0 or current height; sequence signals RBF; no unknown PSBT fields from outside sources. |
| Signing | The signer signs with `SIGHASH_ALL` only, with RFC 6979 deterministic nonces (so a malicious build can't hide data in random nonces without failing the determinism test). |
| After signing (rev 3) | Every input's signature is verified against its expected pubkey and sighash; the PSBT is finalized locally; the **final transaction** is checked once more (same outputs, same fee, same txid as computed) and run through `bitcoinconsensus` script verification before broadcast. |

**BTC fee policy (rev 3):**

| Item | Rule |
|---|---|
| Fee-rate bounds | ≥ min relay fee, ≤ max(3× median of independent estimates, a configured "urgent" rate). Estimates come from your node's `estimatesmartfee` + one external source. |
| Absolute cap | Per-tx fee ≤ the asset-unit cap in §7.4 (e.g. 100,000 sats) **and** ≤ 2% of the amount for normal sends. |
| Override | Allowed only for Spending/Savings, requires typed confirmation, and can raise the fee up to a **hard maximum** (e.g. 300,000 sats). An override changes **only** the fee limit; every other validator rule still runs. It's logged and alerted by the monitor. |
| RBF bump (`BtcRbfBump`) | Same inputs (may add own inputs), **same recipient output and amount**; the only change is a smaller change output and a higher fee. The new fee must satisfy the policy. It is a new Intent and needs a new approval on the signer. |
| CPFP | Not supported in v1. |

**Signer change recognition** is covered by the §8.1 validator tests (positive and negative) in the signer build.

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
| Speed-up | Same nonce, **same calldata** (same recipient and amount), higher fees within the fee policy = new Intent + new approval on the signer. |
| Cancel | Same nonce, `EthNativeTransfer` of **0 ETH to the wallet's own address** (§8.2b), higher fees = new Intent + approval on the signer. |

**Separate allowance & delegation checks (rev 2, discovery defined in rev 3).** A safe transfer says nothing about older approvals. Allowance monitoring is a **detection** control; it can't stop an existing allowance from being used.

| Step | Procedure |
|---|---|
| Baseline (before funding) | Wallet must have **confirmed nonce 0** (never sent a tx) → no allowance can exist (USDT on Ethereum has no `permit`, so an allowance needs an on-chain `approve` from you). For an older address: index **all** `Approval(owner = you)` logs on the USDT contract since the address's first transaction, read `allowance()` for each spender found, and require all to be 0. Cross-check manually with Etherscan's token-approval checker. |
| Ongoing | The independent monitor (§10) subscribes to and polls `Approval` logs with `topic1 = your address` on the pinned contract, and also alerts on **any outgoing tx whose nonce isn't in the audit log** (an `approve` needs a nonce). |
| Gap recovery | The monitor stores the last fully scanned block. After any outage it rescans from there; it never skips ahead. A scan with errors doesn't advance the marker. |
| After suspected compromise | Full rescan from the first block + manual Etherscan check; revoke from the offline signer (a separately reviewed recovery flow) or a freshly installed machine. |

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
| `expiration` | Within `now + 60 s … now + 10 min`, where **online** `now` = the timestamp of the latest solidified block confirmed by ≥2 nodes, and on the **signer** `now` = its own clock with ±10 min tolerance. A far-future expiration would let a signed tx be held and replayed later. |
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
- **Signer display:** the offline signer (and any future hardware signer) must decode and show the `SafeTx` clearly; it must never blind-sign a hash.
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

**TRON multisig (deferred, not v1)** requires first: a written target layout (owner and active keys, weights, thresholds, operation masks), a validator for `Permission_id`-based multi-signature transactions, signer display tests, a tested **emergency recovery procedure** (losing one key; a hostile permission change), and an independent review.

---

## 9. Application & OS hardening

### 9.1 Online app (Tauri / UI)

- **CSP:** `default-src 'self'; script-src 'self'; connect-src ipc: http://ipc.localhost; img-src 'self' data:; style-src 'self'; object-src 'none'; frame-ancestors 'none'`. All RPC traffic goes through the Rust core, so the web view needs **no** external network access.
- Tauri **capabilities**: enable only the custom commands; no shell, no arbitrary fs, no http plugin in the UI.
- No `dangerouslySetInnerHTML`; render token names/memos as plain text (token metadata is attacker-controlled).
- IPC commands are few, typed and validated in Rust: `list_wallets`, `get_portfolio`, `get_receive_address`, `prepare_transfer`, `show_unsigned_qr(review_id)`, `accept_signed_qr(review_id, payload)`, `lock`, … Nothing like `sign(bytes)` or `export_key`.
- Clipboard: the app copies addresses only on explicit click and clears the clipboard after 60 s; it never reads the clipboard silently.
- (rev 4) The online app never shows a seed or key, so it has no secret screens. Seed display happens only on the offline signer.

**Native command boundary (rev 2).** Rust commands are not safe just because they're Rust; a compromised WebView can call any command it is allowed to. So:

| Control | Detail |
|---|---|
| Minimal command set | ≤ ~12 registered commands, listed in `commands.rs`. CI fails if a new `#[tauri::command]` appears without being added to the reviewed list. |
| Capabilities | One capability file for the single `main` window; only the app's own commands; **no** `remote` URLs; no shell, fs, http, process, updater or opener plugins exposed to the UI. |
| Isolation pattern | Tauri's **isolation pattern** enabled, so every IPC message passes through a sandboxed isolation script that can reject unexpected commands/arguments before they reach Rust. |
| State machine | The core tracks state: `locked → unlocked → prepared(review_id) → awaiting_signer → done`. A command called in the wrong state is rejected and logged (e.g. `accept_signed_qr` without a fresh `prepare`). |
| Validation | Every argument is parsed into strong types in Rust (address, amount, wallet ID). The UI never sends raw tx bytes, derivation paths, contract addresses or fee values that bypass policy. |
| No remote code | CSP as above + `require-trusted-types-for 'script'`; no `eval`/`new Function`; `withGlobalTauri` off; navigation to any non-app URL blocked; new windows blocked; DevTools disabled in release builds. |
| Out-of-WebView approval | The offline signer is the authorization boundary (§7 ⑦d). A native OS dialog before showing the unsigned QR only stops a WebView-only compromise from starting a request silently; it is not a security boundary against PC malware. |
| Rate limits | Failed unlocks and rejected commands are counted; repeated failures lock the app and raise an alert. |

### 9.2 Rust core (both machines)

- `#![forbid(unsafe_code)]` in all crates except thin, reviewed FFI wrappers (e.g. `mlock`).
- Secrets (signer only) in `secrecy::SecretBox` + `zeroize`; never `Debug`/`Display`-printable; never cloned into `String`.
- `Amount` is a newtype over `u128` with checked arithmetic; overflow = error.
- Errors shown to either UI never include secret material or raw payloads.
- Hash-chained audit log (online) and signing log (signer): each entry includes `SHA-256(previous_entry)`; verified at startup. **Neither is tamper-proof.** What they can and can't detect is listed in §9.5.
- All QR and transaction decoders that run on the signer are **fuzzed** (`cargo fuzz`) as part of CI, with size limits enforced before parsing.

**Error handling & secret hygiene (rev 2, updated for rev 4):**

| Leak path | Control |
|---|---|
| Logs | Logging only through redacting types: secret, address and amount types implement `Debug` as `[REDACTED]` / shortened. Raw tx bytes are not logged in release builds. |
| Panics | `panic = "abort"` in release; a custom panic hook writes only the location, never the payload. |
| Crash dumps | Online PC: holds no secrets, but the app is still excluded from Windows Error Reporting dumps. Signer: core dumps disabled (`ulimit -c 0`, `systemd-coredump` disabled, `PR_SET_DUMPABLE = 0` for the signer process). |
| Swap / hibernation | Signer: **swap disabled**, hibernation disabled, secret buffers in `mlock`-ed memory. The disk is LUKS2-encrypted anyway. |
| Camera | SeedQR frames are decoded in memory and overwritten; the camera stream is never written to disk or kept in a buffer after decoding. |
| UI errors | Error messages sent to either UI are fixed codes + safe text, never formatted from internal values. |
| Test | An automated test runs every flow on testnet, then scans the signer's disk (logs, vault directory, `/tmp`, journal) and the online PC's logs, database and temp folders for seed words, keys, passphrases and passwords. A stateless Vault signing session must leave **no** seed-derived data on the signer's disk (diff of a disk image before/after) (§11 Phase 2 gate). |

### 9.3 Supply chain

- `Cargo.lock` and `package-lock.json` committed; `cargo deny` (licenses, advisories, banned/duplicate crates), `cargo audit`, `npm audit` in every build.
- Minimal npm dependencies in the UI; **no** blockchain JS libraries in the web view.
- Any third-party SDK (e.g. a future hardware-wallet SDK) pinned to an exact, reviewed version and **vendored**, never loaded at runtime from a CDN. (In December 2023, a hijacked Ledger Connect Kit npm release drained users of dApps that loaded it dynamically. This is the exact pattern to avoid.)
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
| (rev 4) Signer releases | The signer app (and any OS packages it needs) is built as a Linux release on the build VM, hashed twice (two-build check), copied to the dedicated signer-install USB, and installed on the signer only after its hash matches **the reviewer's copy**. The signer refuses to run a binary whose hash isn't in its signed release manifest. |
| (rev 4) Signer OS image | The Linux ISO is downloaded on the online PC, its signature and hash are verified, and it is written to a USB used only for installing the signer. The ISO hash goes in `release-gate.md`. |
| Updates (Phase 6 only) | If the Tauri updater is ever enabled: its signing key is generated and kept **offline** (encrypted USB, not on the build VM). The app verifies the update signature, refuses **downgrades**, and asks before installing. |
| (rev 3) Build evidence kept | A clean dependency scan doesn't prove a build is trustworthy. For each release, `docs/releases/<version>/` keeps: the reviewed source commit hash, toolchain versions (`rustc`, `cargo`, `node`, `npm`, Tauri CLI), hashes of `Cargo.lock` / `package-lock.json`, the scan outputs, build logs from both builds, installer + core binary SHA-256, and the reviewer's report. |
| (rev 3) Operational separation | You are both developer and operator, so a release you change can't be silently treated as reviewed. The reviewer's report names the **exact commit and installer hash** they reviewed, and the reviewer keeps their own copy. Before installing on the wallet PC you compare the installer hash with **the reviewer's copy** (not just your own notes). Any rebuild, patch or config change after review = **unreviewed release** → the §15 release configuration falls back to "no custom signing for Savings or Vault". |
**Developer-machine separation & social-engineering rules (rev 4.1, T21).** The Binance and Bybit attacks (§14D) both started on an engineer's computer. You are the only engineer here, so:

| Rule | Detail |
|---|---|
| Three separate roles | (1) **Development machine**: where you write and test code. (2) **Build VM**: produces release builds only (above). (3) **Online wallet PC account**: runs only the installed, reviewed release. No role is ever used for another's job. The offline signer is a fourth, completely separate machine. |
| No path from development to signing | The development machine has no access to the build VM's signing token, the signer-install USB, the wallet PC account or the monitor's credentials. A compromised development machine can produce bad code, but that code only reaches the signer through the build VM, the two-build check and the reviewer's hash (§9.3, §15). |
| Never run strangers' code | No interview "coding tests", take-home tasks, "please check my repo", trading bots, cracked tools or browser extensions from unknown sources on the development machine. If you must look at such code, do it in a disposable VM with no access to your accounts, then delete the VM. |
| Dependencies | New dependencies are added only after checking the maintainer, download history and source; `npm ci --ignore-scripts` everywhere; typosquatted names are checked by hand. Crates in the signing path are reviewed diff by diff (`cargo vet`). |
| Accounts | Code hosting (GitHub) and package registry accounts use a hardware security key for 2FA where possible; commits to the release branch are signed; branch protection on the release branch. |
| Messages | Treat unsolicited job offers, "investor" or "partnership" chats, and anyone sending you files or links on Telegram/LinkedIn/WhatsApp as possible Lazarus-style approaches. Never open their files on any wallet-related machine. |
| Reviewer independence | The reviewer gets the source from the repository, not from your machine, and builds or hashes it independently (§9.3 "Operational separation"). |

- Download wallets, VeraCrypt, Sparrow etc. only from official sites, and verify signatures/hashes.
- If a hardware wallet is bought later (D1): **directly from the manufacturer**, never second-hand or from marketplaces; run the device-authenticity check on first use.

### 9.4 Online PC (Windows) hardening

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

### 9.4b Offline signer hardening (rev 4)

| Control | Setting |
|---|---|
| Dedicated hardware | A laptop used for **nothing else**, ever. Bought new, or fully wiped. It never had and never will have an internet connection while holding any seed. |
| Network hardware | **Wi-Fi/Bluetooth card physically removed.** If it is soldered on, disable it in BIOS **and** blacklist its kernel modules. No Ethernet cable is ever plugged in. Microphone and speakers aren't needed and can be disabled. The webcam stays (QR). |
| Network check at every start | The signer app refuses to run if any network interface other than `lo` exists, or if `rfkill` / USB / PCI lists show a Wi-Fi or Bluetooth device. The result is shown on the start screen. |
| OS | Minimal Linux (D13) from an ISO whose signature and hash were checked on another machine. Installed **while offline**. No browser, no mail client, no office suite; the package manager is not used after install. Boots straight into the signer app (kiosk) under a dedicated non-admin user. |
| Disk | LUKS2 full-disk encryption with a strong passphrase (different from every wallet password). Swap disabled, hibernation disabled, core dumps disabled. |
| Boot | BIOS/UEFI admin password; boot only from the internal disk; USB/network boot disabled; Secure Boot on where supported. |
| USB | Auto-mount disabled. USB is used **only** for (a) installing a reviewed signer release (§9.3) and (b) reading the optional keyfile. Never for transactions. One dedicated, labelled stick for each purpose. |
| Physical | Stored **powered off** in a locked place (safe). **Tamper-evident seals** over the case screws and unused ports, photographed; check the seals against the photos before every use (evil-maid defence). Seals broken → incident runbook (§10.2). |
| Time | The clock is set once at install. The signer shows its date/time on the start screen so you notice tampering. Signer-side cool-downs and limits use it. |
| Updates | The OS is not updated online. A signer app update arrives only as a reviewed release on USB (§9.3). Security fixes that matter to an offline machine (e.g. in the QR/image stack) are installed the same way, as part of a reviewed release. |
| Ageing | Old laptops fail. Power it on every 3 months to check that it boots, the battery and the webcam. Recovery never depends on it (§6.4). Keep a note of the exact model so a replacement can be prepared from `signer-setup.md`. |

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
| Accidental corruption, partial edits, broken hash chain | Malware with full PC control that ignores the online policy entirely and gets you to approve on the signer. The signer's own checks and display (§7 ⑦b–⑦d) are the defense |
| Restoring an older `policy.db` / database snapshot (rollback) | Malware that makes a *new* policy change and sends a fresh, valid checkpoint. **But** the monitor alerts on that change, so you see it |
| Edits made while the monitor already has a newer checkpoint | Compromise of both the PC and the monitor at once |
| Cool-down reset by changing the Windows clock | — |

**Trusted time.** The Windows clock is **not** trusted for cool-downs, rolling limits or Intent expiry. "Time" means **both**:
- **chain time**: Bitcoin block height from your own node (e.g. a 24 h cool-down = ≥ 144 blocks *and* ≥ 24 h of median-time-past), and
- **monitor time**: the monitor's timestamp on the checkpoint that started the cool-down.

A cool-down counts as elapsed only when both agree. If either is unavailable → treat as **not elapsed**.

**Signer log (rev 4).** The offline signer keeps its own append-only, hash-chained signing log. Its sequence number and head hash appear on every signer receipt (§7 ⑦e); the online PC forwards them in the next checkpoint, so the monitor can tell if the signer's log ever goes backwards (e.g. a restored or swapped laptop disk). The signer's own clock drives its allowlist cool-downs and per-wallet limits; it is not reachable by online malware, only by someone with physical access (§9.4b).

### 9.6 Configuration integrity (rev 3)

| Config | Protection |
|---|---|
| **Network config** (`config/networks.v1.toml`): chain IDs, token contracts + decimals, provider list + independence notes, enabled operations (§8.0), default caps | Versioned file; reviewed with the code; **signed with the offline release key**; its hash is compiled into the binary. The app refuses to start if signature or hash don't match. Changes only through a new reviewed release. |
| **User policy** (`policy.db`): limits, cool-downs, tier caps | Part of the checkpointed policy state (§9.5). **Lowering** a limit applies immediately. **Raising** a limit or adding an operation for a tier needs a 48 h cool-down (trusted time) + monitor alert. |
| **Signer config**: which fingerprint signs which wallet | Part of the policy state; a change counts as raising a limit (cool-down + alert). The online core rejects signatures from an unexpected fingerprint/pubkey. |
| **(rev 4) Signer-side config**: its wallet registry, allowlist, per-wallet limits, release flags | Network config and release flags are compiled into the signed signer release. Allowlist and limit changes are made on the signer itself; raising a limit there also needs a 48 h cool-down by the signer clock. |

### 9.7 Safe failure on corruption (rev 3)

If `policy.db`, the audit log, the checkpoint check, the network config, the wallet inventory, or (rev 4) the signer's log, allowlist or registry is corrupted or inconsistent:
- **Signing stops.** Watch-only features keep working.
- The app **never rebuilds security policy from untrusted data** (portfolio DB, tx history, an old backup, or the UI).
- Recovery: a checkpoint holds only a hash, so the content can't be rebuilt from it. Instead you perform an explicit **policy reset**: start from default (strictest) limits and an empty allowlist; the monitor records it as a "reset" checkpoint and alerts; then re-add entries. Any entries imported from an old copy come back as **unverified** (§7.1), and every cool-down restarts. The monitor checkpoint and the paper log are used to confirm *which* local copy (if any) is current, never as a source of policy content.

### 9.8 Online PC start-up checks and login (rev 4)

The online PC is turned on only when you need it. Each time the app starts it runs these checks **before** login completes.

| Check | Detail | On failure |
|---|---|---|
| App integrity | The installer was verified at install time (§9.3). At start the app checks its Authenticode signature and its own binary hash against the release hash, and the signature + hash of the network config (§9.6). | **Refuse to start** |
| Account | Running under the dedicated **standard** (non-admin) wallet account, not elevated. | Sends blocked |
| Antivirus | Windows Defender real-time protection on, signatures updated within 7 days, no active threats, and the last quick scan was clean (read from Windows Security Center). | Sends blocked |
| Windows updates | Latest cumulative update installed within the last 45 days; no reboot pending. | Warning |
| Risky software | No remote-access tools running (AnyDesk, TeamViewer, RDP sessions, etc.), no debugger attached to the app, no unexpected system proxy. | Sends blocked |
| Clock | The Windows clock is within 2 minutes of the chain/provider time. | Sends blocked |
| Network sanity | TLS works to ≥ 2 independent providers per network, and they report a consistent chain tip (§5.5); own BTC node reachable where configured. | Sends blocked |
| Monitor | The monitor is reachable and the local policy checkpoint equals the monitor's latest (§9.5). | Sends blocked |
| Result | Every result is shown on one screen, written to the audit log and sent to the monitor. Watch-only features work even when sends are blocked. | — |

**Honest limit.** These checks catch misconfiguration, accidental changes and unsophisticated malware. **Malware with administrator rights can fake every one of them.** They are not the security boundary: the signer display and your approval are (§0).

**Login (online app):**
- **Password** (Argon2id) decrypts the local data store (labels, address book, policy view). It does **not** protect funds; no keys exist on this PC.
- **2FA:** a TOTP code from an authenticator app on your phone. It's a gate against someone using your PC, but its secret has to be stored on the PC to check the code, so it adds no encryption strength. **Recommended upgrade (D15):** a FIDO2 security key (`hmac-secret`), whose response is mixed into the data-store key, so it becomes a real second factor.
- Increasing delays on wrong attempts; after 5 failures the app locks for 30 minutes and alerts the monitor. Auto-lock after 5 minutes idle.

**"Login" on the offline signer** is layered by design: disk passphrase (LUKS2) → wallet password (+ optional keyfile) → BIP-39 passphrase (Savings/Vault) or SeedQR card + passphrase (Vault). That combines things you know (passwords, passphrase) and things you have (the laptop, the keyfile, the SeedQR card). TOTP is not used on the signer: an offline machine gains nothing from it.

---

## 10. Monitoring & incident response

### 10.0 Independent monitor (rev 3)

Checking state "on each app refresh" on the wallet PC is **not** monitoring. If the PC is off, offline or compromised, those alerts are silent or forged. So monitoring is a **separate system**:

```
┌──────────── Online PC ────────────┐        ┌────────── Monitor device (separately administered) ──────────┐
│ Online app (may be compromised)   │──────▶ │ Watch-only watcher: addresses/xpubs, baselines, checkpoints  │
│ sends: policy checkpoints + signer│  one-  │ Pruned Bitcoin Core + external ETH/TRON sources (§5.5)       │
│ receipts (§9.5); no commands back │  way   │ NO keys, NO signing, NO ability to move funds                │
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
| Continuous | Polls every chain every ≤ 2 minutes, independently of the wallet PC: outgoing tx, unknown nonces, ERC-20/TRC-20 `Approval` events, Ethereum code/delegation, full TRON permission objects, balances above caps (Spending cap, §4.1). |
| Alert channels | Two channels that don't depend on the wallet app: Telegram bot + email. As a **third, independent** layer, also register the most important addresses with block-explorer address-watch notifications where available. |
| Heartbeat (dead-man switch) | Daily "monitor alive, last block scanned X" message. **No heartbeat = treat as an alert.** Missed scans are back-filled (§8.2 gap recovery). |
| Alert content (rev 4, unified with §10.1) | Wallet label, event type, amount, and a **short txid prefix** (first 8 characters). **No** seeds, keys, xpubs, addresses, balances or full txids (a full txid lets anyone reading the alert find your address on an explorer). Full details are looked up on the monitor itself. |
| Tested offline | The Phase 1 gate tests alerts **with the wallet PC switched off**. |

**If the monitor itself is compromised:** an attacker learns your addresses/xpubs (privacy loss) and can suppress or fake alerts. They **cannot** move funds. Mitigations: explorer address-watch alerts as an independent backup channel, the heartbeat, quarterly manual spot checks on public explorers, and rebuilding the monitor from scratch if its integrity is doubted. **If the Telegram/email account is compromised:** alerts may be read or deleted; use 2FA on both and keep both channels. Losing one channel must not silence the other.

### 10.1 What the monitor watches (watch-only, no secrets)

| Event | Severity | Alert |
|---|---|---|
| Any outgoing tx from **Vault** or **Savings** | Critical | Telegram bot + email |
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
| Spending wallet balance above its cap | High | Monitor alert |
| (rev 4) Signer log sequence goes backwards, or an outgoing tx has no matching signer receipt | Critical | Monitor alert; signing stops until investigated |
| (rev 4) Online start-up check failed, or the signer rejected a tx the online PC built | High | Monitor alert |
| (rev 3) Monitor heartbeat missing | High | Treated as an alert by you |

Telegram/email alerts contain **only** wallet label + event type + amount + short txid prefix (§10.0). No addresses, no balances.

### 10.2 Incident runbook (summary; full version in `docs/incident-runbook.md`)

| Situation | Immediate action |
|---|---|
| Unexpected outgoing tx from a **single-sig** wallet | Assume its seed is compromised. From a **clean device**, move remaining funds to a **fresh** wallet with a **new seed**. Don't reuse anything from the old wallet. |
| Unexpected outgoing tx from **multisig** Vault | Can't happen with 1 key; means 2 keys (or the signer during a Vault session) are compromised. Move to a new multisig with new seeds, generated on a freshly rebuilt signer, immediately. |
| Single multisig key/device lost or stolen | No funds at risk (needs 2). Calmly rotate to a new 2-of-3 within days. |
| TRON permission changed | If you still hold a key with owner permission, revert at once and move funds; otherwise treat as lost and move what's possible. |
| Unknown ERC-20 allowance | Revoke (`approve(spender, 0)`) from a clean device, then investigate. |
| Online PC malware suspected | No keys are on it, so funds are safe as long as you **approve nothing on the signer**. Stop using it, reinstall Windows, rotate the online login and alert-channel passwords, then re-verify the address book against paper. |
| (rev 4) Offline signer lost or stolen | Assume the attacker will try to break its encryption. Stateless Vault: not exposed. Spending and Savings: from a freshly built signer, restore from paper and move funds to **new** seeds within hours (the passphrase buys time for Savings, not safety forever). |
| (rev 4) Signer seals broken or tampering suspected | Don't type any password or show any SeedQR on it. Treat stored wallets as at risk: rebuild a signer on a different laptop, restore from paper, move funds to new seeds. |
| (rev 4) Signer rejected a tx the online PC built, or a signed tx failed ⑧ | Stop all sending. Treat the online PC (for a rejection) or the signer build (for a ⑧ failure) as compromised until investigated. |
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
| **Offline signer selection & preparation gate** (see below) | Laptop chosen, prepared and checked per `docs/signer-setup.md` |
| Prepare a hardened Windows account/PC (§9.4) | Checklist done |
| Buy steel backup plates, SeedQR cards, tamper-evident bags and seals; prepare 2–3 backup locations | Locations decided |
| Create the wallet inventory template | `inventory` (no secrets) |
| Write the first version of the recovery runbook, including the emergency Vault procedures (§4.1b) | `docs/recovery-runbook.md` |

**Offline signer selection & preparation gate (rev 4).** Verified by testing on the actual laptop:
1. Wi-Fi and Bluetooth can be **physically removed** (preferred) or disabled in BIOS; after OS install, `ip link`, `rfkill list`, `lspci` and `lsusb` show **no** network device except loopback.
2. The webcam reliably reads **animated QR codes** at the density needed for a BTC PSBT that includes full previous transactions, and reads a CompactSeedQR card, in normal room light.
3. Supports full-disk encryption, a BIOS/UEFI admin password and disabling USB/network boot.
4. The online PC has a webcam that reads the signer's QR codes just as reliably.
5. The minimal Linux image (D13) installs and boots offline into a kiosk session.
6. The case allows tamper-evident seals over screws and unused ports.

**Exit gate:**
- [ ] Policy numbers written down.
- [ ] Offline signer passes points 1–6; results recorded in `docs/signer-setup.md`.
- [ ] Recovery manifest (§6.6) drafted for every planned wallet.
- [ ] Monitor device chosen (§10.0).
- [ ] Hardened Windows environment ready.

### Phase 1 — Watch-only portfolio (no keys, mainnet read-only)

**Goal:** a useful app with **zero ability to lose money**. (The chat's advice: "build your app as a watch-only portfolio first".)

| Scope | Security controls |
|---|---|
| Tauri + React + Rust skeleton; strict CSP; capabilities | §9.1, §9.2 |
| Start-up checks and login (password + TOTP) (§9.8) | Sends don't exist yet; checks are logged |
| Wallet registry with tiers; import **xpubs / addresses only** | No secrets anywhere in the app |
| Balances for BTC, USDT-ERC20, USDT-TRC20 (+ ETH & TRX for fees) | Integer amounts; pinned contracts |
| ≥2 **independent** data sources per network (§5.5); pruned Bitcoin Core where practical | Disagreement → warning; no "majority vote" |
| Activity history; dust/poisoning detection and hiding | §7.2 |
| Receive screen: addresses + QR | — |
| **Independent monitor device** (§10.0) with heartbeat and 2 alert channels | Outgoing tx, unknown nonces, ERC-20/TRC-20 approvals, ETH code/delegation, full TRON permission objects |
| Audit log (hash-chained), separate `policy.db` + checkpoints to the monitor (§9.5) | Anti-rollback groundwork; trusted time |
| Signed network config (§9.6) | App refuses to start on mismatch |
| CI: cargo deny/audit, npm audit, clippy, tests | §9.3 |

**Exit gate:**
- [ ] Balances match block explorers for every wallet.
- [ ] A test outgoing tx (from an external wallet) triggers an alert within 5 minutes, **with the online PC switched off**.
- [ ] Monitor heartbeat arrives daily on both channels; stopping the monitor is noticed.
- [ ] Restoring an older `policy.db` is detected as a rollback and blocks sends.
- [ ] Allowance and permission baselines (§8.2, §8.5) are recorded for every wallet.
- [ ] A poisoning-style 0-value transfer on testnet is detected and hidden.
- [ ] Each start-up check (§9.8) is shown to fail correctly when its condition is broken (Defender off, clock wrong, remote tool running, config hash changed).
- [ ] Grep/scan confirms no secret-handling code paths exist in the online app.

### Phase 2 — Offline signer and pipeline on testnets (test funds only)

**Goal:** build and prove the two-machine transaction pipeline with fake money. Network order from the chat: **Bitcoin first**, then Ethereum, then TRON.

| Scope | Security controls |
|---|---|
| `signer-app` on the prepared laptop (§9.4b), testnet only | Network check at start, kiosk, no WebView |
| Seed generation with dice mixing, restore, derivation (§6.1, §6.2) | Test vectors; cross-wallet address check |
| Stored vaults (Spending, Savings) and stateless loader (Vault) (§6.4) | Argon2id + XChaCha20-Poly1305 + zeroize; one wallet at a time; fingerprint check |
| `airgap-qr`: animated QR both ways, strict decoder | Size/part limits; fuzzing in CI |
| All six validators in §8.0, shared by both machines; Intent model (§7.3); limits (§7.4); signer error handling (§7.5) | Each operation has its own positive + negative tests; no generic signing path |
| Signer policy: own allowlist, per-wallet limits, signing log | §7.1, §7.4, ⑦c |
| Full pipeline ①–⑩ (§7) | Online review, signer validation + display, post-sign verification |
| BTC on **regtest** → **testnet4/signet**, incl. 2-of-3 stateless multisig | PSBT, coin selection, RBF, fee cap |
| ETH on **Sepolia** with a mock 6-decimal ERC-20 | Transfer-only, no approve, receipt+event check |
| TRON on **Nile** (or Shasta) with a mock TRC-20 | fee_limit cap, energy estimate, permission baseline |
| Online address book, allowlist, cool-downs, limits | §7.1 |
| Adversarial tests | Malicious RPC responses, fake "USDT" token, look-alike addresses, corrupted vault, wrong password, wrong passphrase, killed process mid-write |
| **Required automated test suites** | **Malformed tx** (truncated PSBT/RLP/protobuf, extra outputs, wrong selector, 7702/approve/permit payloads); **manipulated RPC** (wrong nonce, fake UTXO amount, swapped field in a node-built TRON tx, stale ref-block, disagreeing providers); **recipient substitution** (swap at UI, IPC, builder and QR channel); **fee manipulation** (inflated fee rate, gas limit, `fee_limit`, lying prevout amount); **(rev 4) air-gap** (malformed, oversized, truncated, replayed, wrong-wallet and wrong-version QR payloads; fuzzed decoders) |
| **IPC abuse tests** | Calling each online command in the wrong state, with malformed args, and from a script injected into the WebView in a test build |

**Exit gate:**
- [ ] Two new wallets have different seeds and addresses.
- [ ] Restoring from seed (+ passphrase) gives identical addresses on the signer **and** in an independent wallet.
- [ ] A mistyped passphrase is caught by the fingerprint check.
- [ ] All derivation/signing test vectors pass, including RFC 6979 determinism (same tx + key → identical signature).
- [ ] Malformed / wrong-network addresses and invalid amounts are rejected.
- [ ] Changing recipient/amount after review forces a new review and a new signer approval.
- [ ] Wrong passwords, corrupted vault files and interrupted writes are handled without data loss.
- [ ] Leak scan (§9.2) finds no seed/key/passphrase on either machine; a stateless Vault session leaves no seed-derived data on the signer's disk.
- [ ] The signer refuses to start with a network interface present (test with a USB Wi-Fi adapter plugged in).
- [ ] Malicious RPC/token tests fail closed.
- [ ] All five required automated suites pass in CI.
- [ ] IPC abuse tests pass: no command works out of state or with bad arguments.
- [ ] Native ETH/TRX validators pass the same malformed/substitution suites as USDT; an unrecognised tx type is rejected (no fallback).
- [ ] Wipe and rebuild the signer from `signer-setup.md`, restore from paper, same addresses.
- [ ] Limits: splitting across transactions/wallets is blocked by aggregate limits online and by per-wallet limits on the signer; changing the Windows clock doesn't shorten a cool-down.
- [ ] Self code review of `signer-offline`, `signer-policy`, `validators`, `airgap-qr`, `tx-review`, `policy` against §3 principles.

### Phase 3 — Air-gap hardening and review (testnet → tiny mainnet)

**Goal:** the full two-machine setup is hardened, independently reviewed and proven with tiny mainnet amounts.

| Scope | Security controls |
|---|---|
| Signer physical controls: seals, locked storage, BIOS lock, start-screen clock (§9.4b) | Evil-maid checklist before each use |
| "Verify on signer" for receive addresses and own-wallet allowlist entries | §7.2 |
| Typed confirmation of the last 6 recipient characters in ⑦d | §7 |
| Signer receipt + signing-log head in monitor checkpoints | §9.5 |
| Release builds of both apps with evidence (§9.3) | Two-build hash match; signer installed from USB with hash check |

**Exit gate:**
- [ ] Every flow works on testnet with the real laptop and the real online PC.
- [ ] A deliberately tampered unsigned tx (recipient changed after review, at the QR layer) is caught by ⑦b or is visibly different on the signer screen.
- [ ] Recipient/amount/fee substitution tests at builder, IPC, QR channel and broadcast layers pass (§7.3).
- [ ] Seal check: a test with a deliberately broken seal is noticed before use.
- [ ] **Steps 1–5 of the §15 release sequence are complete**: testnet validation → independent review → canary authorization → canary → final gate. The order is fixed; see §15.

### Phase 4 — Controlled mainnet rollout

**Goal:** move real funds gradually. **Starts only after the §15 release gate passes.**

| Step | Amount limit |
|---|---|
| Week 1 | Spending tier only, ≤ ₹10,000 |
| Week 2–3 | Savings tier, ≤ ₹1 lakh |
| Week 4+ | Savings tier up to its planned size |
| Vault | **Receive-only** until `custom_signing_vault = true` (§15.2). After that, the first Vault spend is ≤ ₹1 lakh |
| Savings | Signed by the custom signer **only if** the release configuration has `custom_signing_savings = true` (§15). Otherwise Savings stays receive-only, apart from the emergency procedure (§4.1b) |

Track every tx in the audit log; review weekly for anything unexpected.

**Exit gate:**
- [ ] 4+ weeks with no unexplained events.
- [ ] Recovery drill done on one wallet.
- [ ] Alerts fired correctly for every real outgoing tx.

### Phase 5 — Vault setup (stateless on the offline signer)

**Goal:** the long-term reserve has the best protection available **per asset** (§4.1b).

| Scope | Notes |
|---|---|
| **BTC 2-of-3 P2WSH multisig** (BIP-48 + descriptors), three stateless seeds with SeedQR cards at three locations | Signed on the offline signer; Sparrow is the independent recovery coordinator. Full recovery tested on testnet |
| **ETH USDT Vault and TRON USDT Vault**: dedicated stateless seeds + passphrases | Monitor watches approvals, delegation and permissions. **Single-seed protection, stated as such** |
| Own Bitcoin Core node | Already running since Phase 1 if practical (§5.5) |
| Inheritance plan | Sealed letter + recovery manifests + runbook; doesn't reveal secrets on its own |

**Exit gate:**
- [ ] Full multisig recovery done on testnet with only 2 seeds + descriptor, **without this software**, using only backup-location materials (§6.6), ending in a spend.
- [ ] Emergency Vault procedures (§4.1b) rehearsed on testnet.
- [ ] Mainnet multisig receive/send tested with a small amount.
- [ ] ETH/TRON Vault recovery tested per manifest, ending in a spend.
- [ ] Vault funds moved in stages.

### Phase 6 — Ongoing operations

| Cadence | Task |
|---|---|
| Every signing session | Check the signer's seals against the photos; check its start-screen clock; power it off afterwards |
| Weekly | Review alerts and the audit log; confirm monitor heartbeats arrived |
| Monthly | Dependency audit (`cargo audit`, `npm audit`); Windows updates on the online PC |
| Every 3 months | Power on the signer: boot, battery and webcam check (§9.4b) |
| Every 6 months | Recovery drill per manifest (§6.5, §6.6); verify both USB copies; check backup locations; manual explorer check of allowances/permissions/delegation |
| Yearly | Review tier sizes, limits, threat model; reconsider buying a hardware wallet (D1) |
| On any incident | `docs/incident-runbook.md` |

### Phase 7 — Deferred: hardware wallet, smart-account and TRON multisig (not in v1)

Only if you later decide it's worth the cost and complexity. **Nothing in this document describes these as supported until the relevant items are done:**
- [ ] **Hardware wallet as BTC Vault key #3** (D1): device tested per operation (display of recipient, amount, change; works with blind signing off); the descriptor rotated to include it; recovery re-tested. This removes the "one laptop sees 2 keys" weakness for BTC.
- [ ] Safe: §8.4 validator implemented with negative tests; signer display verified; account config (singleton, owners, threshold, modules, guard, fallback handler) verified and monitored; recovery = **spend** with 2 seeds without this software.
- [ ] TRON: §8.5 target permission layout written; multisig validator implemented; tested emergency procedure for a lost key and for a hostile permission change; recovery = spend.
- [ ] A separate independent review of these paths.
- [ ] Testnet → canary → staged migration, as for Phase 3/4.

---

## 12. Threat → control map

| Threat | Primary controls | Phase |
|---|---|---|
| T1 Online PC malware | No keys on the online PC (P1), signer validation + display (P3, P14), signer policy, Spending cap, dedicated Windows account | 0, 2, 3, 4 |
| T2 Clipboard swap | Address book + allowlists, signer display vs paper, look-alike check | 2, 3 |
| T3 Address poisoning | Look-alike block, no copy-from-history, dust hiding | 1, 2 |
| T4 Seed theft | Seeds generated on the signer, steel backups in separate places, passphrases stored apart, BTC multisig | 0, 5 |
| T5 Malicious/blind signing | Review-from-bytes, authoritative signer validator, post-sign verification, refuse undecodable data | 2, 3 |
| T6 Unlimited approvals | Transfer-only (no `approve`), allowance monitoring | 1, 2 |
| T7 TRON permission hijack | Permission baseline + alert, incident runbook | 1, 2 |
| T8 Supply chain | Pinned + vendored deps, cargo deny/audit, no CDN, verified ISO, reviewed signer release on USB, two-build check, no auto-update | 0, 1, 3 |
| T9 Own bugs | Test vectors, cross-wallet restore check, shared validators run twice, testnets first, independent review, tiny-amount rollout | 2, 3, 5 |
| T10 Lying RPC | ≥2 sources cross-check, fail closed, own BTC node, local construction | 1, 5 |
| T11 Physical loss | Multisig, 2 backup locations, recovery independent of the laptop, disk encryption | 0, 5 |
| T12 Coercion/social eng. | Cool-downs, tier flow rules, signer allowlist, stateless Vault needs SeedQR cards from separate places, never share screen/seed | 2, 5 |
| T13 Self-lockout | Recovery drills, runbook, descriptor backups, passphrase stored separately and tested, fingerprint check | 0, 5, 6 |
| T14 Phishing/fake software | Official sources + signature checks, no general browsing on the wallet account, nothing but the signer on the laptop | 0 |
| T15 Indirect-drain signatures | Operation allowlist (P13) enforced on both machines, pre-sign validators, no message/typed-data/7702 signing, allowance + delegation monitoring | 1, 2 |
| T16 Compromised WebView | Native command boundary (§9.1), state machine, signer approval as the only authorization; no WebView on the signer | 1, 2, 3 |
| T17 Secrets in errors/dumps | Redacting types, abort-on-panic, no core dumps/swap on the signer, `mlock`, leak-scan test | 2 |
| T18 (rev 4) Offline signer theft or tampering | LUKS2, per-wallet vault passwords, passphrases never stored, stateless Vault, BIOS lock, tamper seals, locked storage | 0, 2, 3 |
| T19 (rev 4) Air-gap breach / hostile QR / exfiltration | Radios removed + start-up network check, QR only, strict fuzzed decoders, no WebView on the signer, RFC 6979 deterministic signatures, reviewed reproducible signer build | 0, 2, 3 |
| T20 (rev 4) Seed exposure during stateless signing | SeedQR cards in sealed bags, used only in front of the signer, returned the same day, rare Vault use | 5, 6 |
| T21 (rev 4.1) Compromised developer machine | Developer/build/wallet-PC separation, never running strangers' code, reviewed dependencies, build VM + two-build check, independent reviewer with their own hash, P18 human approval for every signature | 0, 1, 2, 3 |
| Automated signing abuse (Binance 2026 pattern) | P18 no automatic signing; signer accepts only QR input; signer allowlist and limits | 2, 3 |
| Fake UI / hidden operation (Bybit 2025 pattern) | Signer decodes raw bytes (P14), no blind signing (P4), closed operation list (P13) | 2, 3 |
| Full online-PC compromise bypassing review/policy | Signer = authorization boundary (§0, §7 ⑦d), signer's own allowlist/limits, keys off the online PC, independent monitor | 0, 1, 2, 3 |
| Policy rollback / clock manipulation | Separate `policy.db`, monotonic checkpoints at the monitor, trusted chain+monitor time, signer's own log and clock, fail closed (§9.5) | 1, 2 |
| Silent monitoring (PC off/compromised) | Separate monitor device, 2 channels + explorer alerts, heartbeat, offline test (§10.0) | 1 |
| Config tampering | Signed network config, cool-down on raising limits, signer fingerprint check (§9.6) | 1, 2 |

---

## 13. Open decisions

| # | Decision | Recommendation | Decide by |
|---|---|---|---|
| D1 | **(rev 4) Hardware wallet** | Not in v1 (cost). Strongly recommended later as **BTC Vault key #3** (from a vendor that passes a per-operation display test), so no single machine ever holds 2 Vault keys. Revisit yearly or when holdings grow | Phase 7 |
| D2 | Spending tier cap | ≤ ₹50,000 or ≤ 5% of total, whichever is lower | Phase 0 |
| D3 | BIP-39 passphrase | **Decided in rev 4:** required for Vault and Savings, stored separately from its seed | Phase 0 |
| D4 | Vault design for USDT | **Decided for v1:** stateless single-sig on dedicated seeds + passphrase, signed on the offline signer, plus monitoring. Safe / TRON multisig deferred to Phase 7. Still yours to decide: how much of the reserve you accept holding with single-seed protection (§4.1b) | Phase 0 |
| D5 | TRON implementation | **Decided in rev 4:** Rust-native protobuf; no TronWeb | — |
| D6 | Alerts channel | Telegram bot + email (both) | Phase 1 |
| D7 | Online machine | **Decided in rev 4:** your Windows PC with a dedicated standard account. A dedicated online laptop is better if budget allows | Phase 0 |
| D8 | Who does the independent review | A paid freelance reviewer with Rust + Bitcoin/Ethereum wallet experience, scoped to `signer-app`, `signer-*`, `validators`, `airgap-qr`, `tx-review`, `policy`, `chain-*`, `commands.rs` and both release builds. **If no reviewer is available:** `custom_signing_savings` and `custom_signing_vault` stay `false` (§15.2). Savings and Vault are then receive-only except for the emergency procedures (§4.1b), and the custom signer is used only for the capped Spending tier | Before Phase 4 |
| D9 | Spending tier signer | **Decided in rev 4:** the offline signer (stored vault). No signing on the online PC | — |
| D10 | Monitor device | Raspberry Pi 5 + SSD at home (runs pruned Bitcoin Core too), or a small cloud VM. **Minimum** if neither: block-explorer address-watch email alerts for every address | Phase 0 |
| D11 | Exact limit numbers | Fill in the §7.4 table in asset units: per-tx, per-wallet, per-tier, global, per-recipient, fee caps, native top-up caps; and the signer-side per-wallet limits | Phase 0 |
| D12 | **(rev 4) Offline laptop model** | One where Wi-Fi/Bluetooth can be physically removed, with a good webcam and BIOS password support (Phase 0 gate) | Phase 0 |
| D13 | **(rev 4) Signer OS and GUI toolkit** | Minimal Debian stable; `iced` or `egui` for the native GUI | Phase 2 |
| D14 | **(rev 4) QR encoding** | Animated fountain-coded QR (BC-UR style) for transactions; CompactSeedQR for seeds | Phase 2 |
| D15 | **(rev 4) Online login second factor** | TOTP for v1; upgrade to a FIDO2 security key with `hmac-secret` mixed into the data-store key | Phase 1 |
| D16 | **(rev 4) Optional signer keyfile** | Yes for Savings if you can store the keyfile USB apart from the laptop; not needed for the stateless Vault | Phase 2 |
| D17 | **(rev 4.1) Exchange account hygiene** | Exchanges are only for buying/selling INR, never for storage. Keep only what you're trading there and withdraw to your own wallet (Savings receive address, verified on the signer) promptly. On every exchange account: **withdrawal address allowlist** on, with only your own addresses; hardware security key (FIDO2) for 2FA, not SMS; anti-phishing code set; login and withdrawal alerts on; a unique email address and password. After any exchange incident, use only the official app or website; never follow links in messages, never install "recovery" or "compensation" tools, and never share your screen, seed or 2FA codes | Before first deposit |

---

## 14. Gap reviews

Rev 2, rev 3 and rev 4 are listed separately below. Where a later revision replaced something an earlier one said (e.g. the native OS dialog, canary exemption, Phase 5 review, and in rev 4 every reference to hardware devices), the later table is authoritative. Sections 14A/14B are kept as history and still mention hardware devices.

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

## 14C. Revision 4: offline laptop signer (2026-11-02)

Rev 4 is a design decision rather than an external review: **no hardware wallets for now (cost); one offline laptop signs for all wallets; a separate online PC watches them** (the "Scenario A" design). Sections 14A and 14B are kept as history; where they mention hardware devices, rev 4 replaces them with the offline signer as below.

| Area | Rev 3 | Rev 4 | Where |
|---|---|---|---|
| Signer | Hardware wallets for every production tier; vendor software for the Vault | One **offline laptop** (radios removed, minimal Linux, native Rust GUI) for every tier | §0, §5, §9.4b |
| Authorization boundary | Hardware wallet screen | **Offline signer screen** + typed confirmation of the last 6 recipient characters from paper | §0, §7 ⑦d |
| Transport | USB / QR to the device | **QR only** (animated, size-limited, fuzzed decoders) | P16, §5.2 B3, §7 ⑦a |
| Validation | Online core validator (④b) | Same validator runs again **on the signer and is authoritative**; signer has its own allowlist, limits and signing log | P14, §7 ⑦b/⑦c, §7.4 |
| Vault | BTC multisig on 3 devices from ≥2 vendors; ETH/TRON single-sig on devices; never signed by the custom app | **Stateless** seeds via SeedQR + passphrase; BTC 2-of-3 of three stateless seeds; custom signer only when `custom_signing_vault = true` | §4.1, §4.1b, §6.4, §15.2 |
| One laptop = one point of failure | n/a | Per-wallet vaults and passwords, passphrases never stored, stateless Vault, physical controls; honest table of what isn't covered | §4.1a, §4.1b |
| Spending signer / weak mode | Hardware wallet; optional software vault on Windows ("weak mode") | Offline signer; **no keys on Windows at all**; weak mode removed | §4.1, §6.4 |
| Seed generation | On the hardware device | On the signer: CSPRNG + dice; master fingerprint checked at every signing | §6.1 |
| Passphrase | Optional | **Required** for Savings and Vault | §6.1, D3 |
| Start-up checks & login | Not specified | Online start-up checks (with honest limits), password + TOTP, FIDO2 later | §9.8 |
| Device compatibility matrix | Per vendor/firmware/operation | Replaced by the offline signer preparation gate | §11 Phase 0 |
| New threats | — | T18 signer theft/tampering, T19 air-gap breach / hostile QR / exfiltration, T20 seed exposure during stateless signing | §2.2, §12 |
| Look-alike check | Same first 4 + last 4 chars | Any shared prefix or suffix of ≥ 3 characters → block | §7 ③ |
| Inconsistencies fixed | Alert content (§10.0 vs §10.1); "Windows notification" from the monitor; Appendix A calling Safe/TRON multisig optional; TRON expiration "now" undefined | Unified alert content; monitor alerts via its own channels; Appendix A updated; expiration defined against solidified-block time and the signer clock | §10, §8.3, Appendix A |

---

## 14D. Incident lessons: Binance 2026 and Bybit 2025 (rev 4.1)

Preliminary reporting on the Binance theft (2026-10-29, about $6.3–6.4B, attributed by TRM Labs, Chainalysis and Elliptic to North Korea's TraderTraitor/Lazarus) says a **DevOps engineer's laptop was compromised**, giving access to an internal service that could submit withdrawals; **no private keys were stolen**, the hot-wallet signing system signed the attackers' transactions. Binance has not yet published a full root cause. In the Bybit theft (2025-02, about $1.5B, same group), a **developer machine** at the Safe{Wallet} provider was compromised, malicious code was injected into the web UI, and signers approved what looked like a routine transfer; their hardware wallets blind-signed a call that handed the wallet to the attacker.

| Attack step | Their weakness | This design | Where |
|---|---|---|---|
| Engineer/developer machine compromised | That machine had a path to the signing system | The online PC can only display a QR code; the signer accepts nothing else. Development, build and wallet PC are separate roles with no path to signing | P16, §9.3 (rev 4.1), T21 |
| Signing on request | The signing system signed whatever a trusted internal service asked | **No automatic signing, ever**; every signature needs a decision on the signer screen with typed recipient confirmation | P18, §7 ⑦d |
| Fake screen | Signers trusted the web UI | The signer decodes raw bytes itself; the online screen is never trusted | P3, P14, §0 |
| Blind-signed hidden operation | Devices showed a hash, not the real call | No blind signing; closed list of plain transfers; `delegatecall`, contract calls and permission changes have no code path | P4, P13, §8.0 |
| Fast drain | Large hot balance, high withdrawal speed | Spending cap; Vault can only send to own Savings; signer-side per-wallet limits; 24–48 h cool-down for new addresses; monitor alerts within minutes | §4.1, §4.2, §7.4, §10 |
| Scams after the incident | Users tricked by fake support/compensation | No exchange holds your funds; nobody is ever shown a seed; exchange hygiene rules | §6.3, D17 |

**Residual risk:** this design only stops these attacks if the signer check is done honestly every time (approval fatigue made the Bybit signers approve), and if the signer software itself isn't poisoned through your development machine (T21). Both are covered by controls above, but neither is automatic.

---

## 15. Mainnet release sequence & gate (rev 3, updated for rev 4)

Record the date and evidence for every step and gate item in `docs/release-gate.md` (test reports, commit hash, installer and signer-image hashes, reviewer's report).

### 15.1 Fixed sequence

```
① Testnet validation ─▶ ② Independent review ─▶ ③ Canary authorization ─▶ ④ Canary testing ─▶ ⑤ Final release approval ─▶ ⑥ Controlled rollout (Phase 4)
```

| Step | What must be true before it starts | Done when |
|---|---|---|
| ① Testnet validation | Phase 0–2 gates passed | Phase 3 testnet items pass; G1, G3, G4, G5, G8 pass on testnet; G7 passes for the candidate builds |
| ② Independent review | ① complete; the builds to review are frozen (commit + online installer hash + signer release hash) | Reviewer's report on those exact hashes; every finding fixed (→ back to ①) or accepted in writing. **G9** |
| ③ Canary authorization | ② complete with **no changes since** (same hashes), G2 and G6 pass, monitor live (Phase 1 gate) | **You** sign a dated entry in `release-gate.md` stating scope: which wallets, which operations, max **₹500 equivalent per asset**, max 2 weeks. You're the only authorizer; the entry is also sent as a monitor checkpoint |
| ④ Canary testing | ③ authorized | Each operation in §8.0 done on mainnet within scope; alerts observed (**G10**); a canary loss is accepted as a cost |
| ⑤ Final release approval | ④ complete with no unexplained events; G1–G13 all ✅; installed builds' hashes = reviewed hashes | Signed, dated approval entry in `release-gate.md` |
| ⑥ Rollout | ⑤ approved | Phase 4 staging table |

Any code, dependency, signer OS image or config change after ② restarts at ①, and requires a new or delta review at ② before custom signing is used again.

### 15.2 Release configuration (enforced, not advisory)

Stored in the signed network config (§9.6), compiled into the signer, and in the checkpointed policy state (§9.5). **The signer enforces these flags itself.**

| Flag | Default | Becomes `true` only when |
|---|---|---|
| `custom_signing_spending` | `false` | Steps ①–⑤ complete for Spending |
| `custom_signing_savings` | `false` | Steps ①–⑤ complete **and** the independent review (②) covered the exact installed builds. **No independent review → stays `false`**: Savings is receive-only apart from the emergency procedure (§4.1b) |
| `custom_signing_vault` | `false` | Steps ①–⑤ complete, the review covered the stateless and multisig paths, Phase 5 recovery tests passed, **and** Savings has run without unexplained events for 4+ weeks. Until then the Vault is receive-only (§4.1b) |
| `safe_operations`, `tron_multisig_operations` | `false` | Phase 7 complete |

### 15.3 Gate items

| # | Gate (from the external review, adapted in rev 4) | How it's verified | Defined in |
|---|---|---|---|
| G1 | The offline signer supports the exact BTC, Ethereum USDT and TRON USDT operations required, and **displays every field** needed to verify them | Every §8.0 operation signed on testnet with the real laptop; display checklist (recipient, amount, contract, fee, change, nonce/expiration) recorded | §7 ⑦d, Phase 2–3 |
| G2 | **No seed or private key ever exists on the online PC**; the signer never exports seeds or keys | Code search: no seed/xprv import/export paths in the online app, no key material in any QR except the SeedQR at creation; leak-scan test passes on both machines | P1, §4.1a, §9.2 |
| G3 | Every supported transaction type is parsed and validated before signing, **on the signer** | Each §8 validator rule has a passing positive and negative test, run in the signer build | §7 ⑦b, §8 |
| G4 | The signer's display is used to verify details; unsupported or unclear operations fail closed | Manual test log: every operation shown clearly; tampered-tx test caught; typed recipient confirmation works | §7 ⑦d, Phase 3 gate |
| G5 | No unapproved token allowance or arbitrary contract interaction can be initiated | No code path builds `approve`/`permit`/typed data/7702; tests for those payloads are rejected by both machines | P13, §8.2, §8.3 |
| G6 | Recovery is tested for all networks and accounts, including derivation paths and passphrases | Restore every wallet in an independent wallet; addresses match on all 3 networks; rebuild-the-signer test passes | §6.2, §6.4, §6.5 |
| G7 | Dependency, installer, signer-image and update integrity are verified | `cargo deny`/`audit`/`npm audit` clean; two-build hash match for both apps; installer signature + paper hash checked; signer release hash checked against the reviewer's copy before install | §9.3 |
| G8 | Automated tests cover malformed tx, manipulated RPC, recipient substitution, fee manipulation **and the air-gap channel** | All five suites green in CI on the release commit | §11 Phase 2 |
| G9 | An independent reviewer has examined the actual signing code and both release builds | Reviewer's report on the release commit; findings fixed or accepted in writing. If not possible → D8 fallback | P15, D8 |
| G10 | Monitoring works | A canary outgoing tx, a test allowance and a test 0-value poisoning transfer each raise the right alert | §10.1 |
| G11 | Incident and recovery runbooks exist on paper | `recovery-runbook.md` and `incident-runbook.md` printed and stored with the backups | §6.3, §10.2 |
| G12 | **(rev 4) The offline signer is air-gapped and physically protected** | Phase 0 signer gate re-checked on the final setup; start-up network check verified with a USB Wi-Fi adapter; seals photographed; BIOS locked | §9.4b |
| G13 | **(rev 4.1) No signature without a human decision; developer machine separated** | Code review + CI check that every signing path goes through the approval screen (P18); written confirmation that development, build VM and wallet PC are separate and the T21 rules are followed | P18, §9.3, T21 |

---

## Appendix A — What changed vs. the ChatGPT conversation

| Topic | Chat said | This document |
|---|---|---|
| Pen drive for keys | Not as primary storage; encrypted USB only for backups/docs | Same; USB holds **no seeds/keys at all**, only inventory, descriptors, runbook |
| Hardware vs software | Hardware signer for > ₹10 lakh | Rev 4: an **offline laptop signer** for every tier instead (cost), with a hard Spending cap; a hardware wallet is still recommended later (D1) |
| One seed vs many | One shared vault, three chain adapters | One seed **per tier/wallet**, three chain adapters inside each |
| Stack | Tauri 2 + React + TS + Rust, rust-bitcoin, Alloy/ethers-rs, TronWeb | Same, plus BDK for BTC; Alloy only (ethers-rs deprecated); TronWeb only in a sidecar if needed |
| Testnets | Regtest, Sepolia, Shasta | Same, plus testnet4/signet for BTC and Nile for TRON |
| Multisig | "Consider 2-of-3 for BTC" | Required for the BTC Vault (three stateless seeds); Safe/TRON multisig deferred to Phase 7 |
| Monitoring | Not covered | Watcher + alerts for outgoing tx, approvals, TRON permissions |
| Address poisoning, TRON permission hijack, supply-chain attacks | Not covered | Threats T3, T7, T8 with controls |
| Incident response | Not covered | §10.2 runbook |
| External gap review (rev 2) | Found 5 critical findings, chain-specific gaps, 8 overlooked areas and 9 release gates | All mapped in §14A; release gates in §15 |
| External gap review (rev 3) | Found 5 critical + 7 high-priority gaps, chain corrections, 4 contradictions, 6 extra requirements | All mapped in §14B; Safe/TRON multisig deferred; independent monitor; anti-rollback; fixed release sequence |
| Offline signer (rev 4) | Not covered | One offline laptop signs for all wallets over QR; online PC is watch-only; stateless Vault; start-up checks and login (§14C) |

## Appendix B — Disclaimer

This is a security-engineering design for a personal wallet, not financial or investment advice. No design removes all risk. Verify contract addresses, hardware wallet capabilities and library versions against official sources at implementation time, because they change.
