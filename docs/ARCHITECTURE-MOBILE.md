# Budget Variant — Existing PC + Mobile Signer

**Status:** Design, variant M1 (2026-11-02). Nothing is built yet. **Not ready for real funds** until the gates in §10 pass.
**Owner:** Vipul
**Relation to the main plan:** [`ARCHITECTURE.md`](ARCHITECTURE.md) (rev 4.1) stays unchanged and remains the target design. This variant is a **lower-cost starting point**: it reuses your **existing PC** (online, watch-only) and a **mobile phone** (signing), with no second computer. Everything not restated here (chain validators §8, derivation paths §6.2, Intent model §7.3, operation list §8.0, incident lessons §14D) applies **as written in the main plan**. §11 below is the path back to the full design.
**Scope for now:** 2–3 wallets, BTC + USDT (TRC-20) + USDT (ERC-20).

---

## 0. The idea in one paragraph

Your existing Windows PC runs the **watch-only app**: balances, history, receive addresses, preparing unsigned transactions and broadcasting signed ones. It never holds a seed or key. Your **phone runs the signer app**: it holds the keys inside an encrypted vault protected by the phone's security chip, decodes every transaction itself, shows it to you, and signs only after your approval. The two exchange data **only through QR codes** (PC screen → phone camera, phone screen → PC webcam). The phone's screen + your approval is the only authorization step; nothing the PC shows is trusted.

**The one decision that matters most (D-M1):** *which* phone.

| Option | What it is | Security | Cost | Allowed for |
|---|---|---|---|---|
| **A — Dedicated offline phone** (recommended) | A spare or cheap used Android phone, factory reset, **no SIM, never online**, used only for signing | **Cold.** Close to the main plan's offline laptop, and its security chip is actually better than an old laptop's | A spare phone you already own = free; a used Android with a security chip is usually far cheaper than a second PC | All wallets |
| **B — Your daily phone** | The phone you use for WhatsApp, banking, browsing, with the signer app installed in a separate profile | **Hot.** The phone is online and runs many apps, so it is exposed to malware, scams and theft while unlocked | Free | **Spending wallet only, capped** |

If you only have your daily phone this month, use **B for Spending only** and keep Savings/Vault **receive-only** (§3) until you have a dedicated phone. Receiving needs no signing, so receive-only wallets are fully safe to fund as long as their seeds were created offline (§5.1).

---

## 1. Devices and what each is trusted for

| Device | Role | Holds | Trusted for |
|---|---|---|---|
| **Existing Windows PC** (also used for business and development) | Watch-only app; builds unsigned tx; broadcasts | Public addresses / xpubs only | **Nothing security-critical.** Assumed compromisable |
| **Signer phone** (Option A or B) | Signer app: vault, validation, display, signing | Encrypted seeds (stored wallets) | Its screen + your approval = authorization |
| **Paper / steel** | Seed backups, passphrases, SeedQR card, paper address book | Seeds (physically) | Recovery |
| **Block explorers' email alerts** | Free independent monitoring (replaces the main plan's monitor device for now) | Your public addresses | Detecting outgoing transactions when the PC is off |

**Platform assumption:** the signer phone runs **Android**. An iPhone can't practically run your own signing app without an Apple developer account and internet-connected installs, so Option A needs an Android device. (If your daily phone is an iPhone, Option B isn't available either; use Option A.)

---

## 2. Architecture

```
┌──────────── EXISTING PC — Windows (untrusted, NO secrets) ───────────┐
│  "wallet" Windows account (standard user) — used ONLY for this app   │
│  Watch-only app (Tauri + React UI, Rust core)                        │
│  Portfolio · Receive · Send (prepare) · Activity · Alerts             │
│  Tx builder · Online validator (bug-catcher) · Broadcast · Audit log │
└───────────────┬──────────────────────────────────────────┬──────────┘
                │ HTTPS: ≥2 data sources per network       │
                │                                           │ QR codes only
                │                     unsigned tx + Intent  ▼   ▲ signed tx + receipt
┌───────────────┴──────────────────────────────────────────────────────┐
│ SIGNER PHONE — Android                                                │
│  Signer app (Kotlin UI + shared Rust core), NO internet permission    │
│   ├─ QR decoder (strict, size-limited, fuzzed)                        │
│   ├─ Chain validators (main plan §8) — AUTHORITATIVE                  │
│   ├─ Signer policy: own allowlist, per-wallet limits, signing log     │
│   ├─ Vaults: one per wallet, Argon2id + XChaCha20-Poly1305,           │
│   │   wrapping key in Android Keystore / StrongBox (security chip)    │
│   ├─ Stateless loader (Vault tier): SeedQR + passphrase, never stored │
│   └─ Signing (RFC 6979), zeroize after each session                   │
│  TRUSTED: its screen + your approval                                  │
└───────────────────────────────────────────────────────────────────────┘
        Independent alerts: block-explorer address-watch emails (free)
```

**Key design choices:**

| Choice | Why |
|---|---|
| **Signer app requests no `INTERNET` permission** | Android then blocks the app from opening any network connection, **even on a daily (online) phone**. Keys can't be sent out by the app itself, and the app can't be reached over the network. |
| **QR only, even on the daily phone** | The same flow and app work for Option A and B; the PC never talks to the phone over USB, Bluetooth or Wi-Fi. |
| **Native Kotlin UI + Rust core (via UniFFI)**, not a WebView | No browser engine on the signer (same reason as the main plan). The Rust core (types, validators, signing) is shared with the PC app. |
| **Android Keystore / StrongBox** wraps the vault key | The phone's security chip enforces lock-screen-bound keys and rate-limits guessing. Stolen phone → much harder to attack than a laptop disk. |
| **Signer's own allowlist and limits** | Hold even if the PC is fully compromised (main plan §7 ⑦c). |

---

## 3. Wallets for this month (2–3)

| Wallet | Tier | Signer | Seed created on | Status this month | Cap |
|---|---|---|---|---|---|
| `spend-01` | Spending | Phone (Option A or B) | The signer phone | Active after testnet gates (§10) | **Option A: ≤ ₹50,000. Option B: ≤ ₹25,000** |
| `savings-01` | Savings | **Option A phone only** | Option A phone (offline) | **Receive-only** until an Option A phone exists and §10 gates pass | Planned size (D2 in main plan) |
| `vault-01` (optional) | Vault | Option A phone, **stateless** (SeedQR + passphrase, never stored) | Option A phone (offline) | **Receive-only** in this variant | — |

- One seed per wallet; each seed derives BTC + ETH + TRON addresses (main plan §6.2).
- **Savings and Vault use a BIP-39 passphrase**, stored separately from the seed.
- **No BTC multisig in this variant** (it would need several signing devices). The Vault is single-sig + passphrase + stateless. Multisig comes back with the main plan (§11).
- Money flows downward only: Vault → Savings → Spending → out (main plan §4.2).

---

## 4. Flows

### 4.1 Wallet creation (once per wallet)

1. On the signer phone (Option A for Savings/Vault), with airplane mode on and no SIM: create a wallet. The app mixes the phone's random generator with **≥ 99 dice rolls** you enter.
2. Write the **24 words** on paper (2 copies). For Savings/Vault, choose a **passphrase** and write it on separate paper. For Vault, also copy the **SeedQR** onto a card.
3. The app asks for random words back, then records the wallet's **fingerprint**.
4. The phone shows the wallet's **xpubs/addresses as QR**; the PC app scans them (watch-only import).
5. **Recovery test before any deposit:** restore the seed (+ passphrase) in an independent, well-known wallet on the same offline phone or another offline device, and confirm the first 3 addresses match on all 3 networks.

### 4.2 Receiving

1. PC: Receive → choose wallet + network (shown in large text).
2. **Verify on phone:** the phone shows the same address from its own keys (no unlock needed); compare. This stops malware on the PC from swapping it.
3. Send the address to the payer over one channel and confirm the first/last 6 characters over another. Ask new payers for a small test payment first.
4. Wait for confirmations; check it's the **real USDT** contract; ignore dust/0-value transfers (address poisoning).

### 4.3 Sending

```
PC: draft → validate → policy → build → online check → review → show QR
PHONE: scan → decode → validate (authoritative) → signer policy → DISPLAY → you compare with paper
       → type last 6 chars of recipient → unlock (PIN/biometric + vault password [+ passphrase]) → sign → show signed QR
PC: scan → verify matches Intent → broadcast to ≥2 providers → confirm
```

- Compare the phone's display with **your paper address book**, never with the PC screen.
- Any mismatch, unreadable field or unknown transaction type → reject (main plan P4, P13).
- Same signer error rules as the main plan §7.5.

### 4.4 Recovery (phone lost, stolen, broken)

Funds never depend on the phone. Restore each wallet from paper (+ passphrase) onto a new signer phone (or any BIP-39 wallet in an emergency) and, for a **lost or stolen** phone, **move funds to new seeds** within hours.

---

## 5. Hardening

### 5.1 Option A — dedicated offline phone

| Control | Setting |
|---|---|
| Device | Android with a hardware security chip (**StrongBox**, e.g. Titan M on Pixel, Knox Vault on Samsung) and still able to boot a locked, verified OS. A Pixel with **GrapheneOS** is the strongest choice. |
| Reset | Factory reset before use. **No Google account.** **SIM removed permanently.** |
| Radios | Airplane mode **permanently on**; Wi-Fi, Bluetooth, NFC, location off. It never joins Wi-Fi after setup (the one exception is installing GrapheneOS, before any seed exists). |
| App install | Signer APK installed **once over a USB cable** (`adb`) after its hash matches the reviewed release. Then turn off USB debugging and Developer options. Updates the same way, rarely, with hash checks. |
| Nothing else | No other apps installed or used. Disable/remove any pre-installed apps you can. |
| Lock | Strong alphanumeric screen lock (not a pattern, not a 4-digit PIN); short auto-lock. |
| Storage | Powered off in a locked place when not in use. |
| Start-up checks in the app | Refuses to run if: airplane mode is off, any network is connected, a SIM is present, USB debugging is on, an accessibility service is enabled, the bootloader is unlocked or verified boot isn't green (checked with on-device key attestation), or a screen recording/casting is active. |

### 5.2 Option B — daily phone (Spending only)

| Control | Setting |
|---|---|
| Separate space | Install the signer in a **separate Android user, Work Profile or Private Space**, not your main profile. Keep that space empty except for the signer. |
| No network for the app | The app has no `INTERNET` permission (enforced by Android). |
| Key protection | Vault key in Keystore/StrongBox with **"user authentication required" for every signature** (biometric or lock-screen credential), **"unlocked device required"**, and invalidated when new fingerprints are enrolled. |
| Screen protection | `FLAG_SECURE` on every screen (no screenshots, screen recording or recent-apps thumbnails). |
| Keyboard | Passwords, passphrases and seed words are typed only on the app's **own in-app keyboard**, never the system keyboard (third-party keyboards can log and sync text). |
| Overlay & accessibility malware | The app refuses to run while any **accessibility service** is active or another app draws over it, and blocks touches when obscured. Accessibility/overlay trojans are common on Android. |
| Screen sharing | Refuses to run while screen sharing, casting or recording is detected. Never install remote-support apps (AnyDesk, TeamViewer, "customer support" apps). |
| Backups | `allowBackup = false`, excluded from cloud backup and device-to-device transfer. **Never** photograph seed words, even "temporarily". |
| Phone hygiene | Latest Android security updates; apps only from the official store; no sideloaded APKs except the reviewed signer; no rooting. |
| Cap | Spending balance ≤ ₹25,000. Top up from Savings only when needed. |

### 5.3 Existing PC (shared with business and development)

| Control | Setting |
|---|---|
| Separate Windows account | A **standard (non-admin) "wallet" account** used only for the watch-only app. Business work and development happen in **other** accounts. |
| Development separation (main plan T21) | Release builds are made in a **separate build account or VM** on the same PC, never in your daily development account. Untrusted code (job "coding tests", unknown repos, trading bots) is opened only in **Windows Sandbox** or a throwaway VM. |
| Basics | BitLocker on; Windows Update automatic; Defender real-time + Controlled folder access for the app's data; no remote-access tools in the wallet account; no browsing or email in the wallet account. |
| Start-up checks | As main plan §9.8 (app signature, Defender, clock, ≥2 providers agree). Honest limit: admin malware can fake them; the phone check is the boundary. |
| Login | Password + TOTP (main plan §9.8). The TOTP code must come from an authenticator app **other than** the signer, and for Option B preferably not in the signer's profile. |

---

## 6. Monitoring without a second device

The main plan's always-on monitor (Raspberry Pi) is replaced, for now, by:

1. **Block-explorer address-watch email alerts** on every address of every wallet (BTC explorer, Etherscan, Tronscan). Free, and they work while your PC is off.
2. **Signer receipts:** the phone's signing log sequence and hash are shown on every signed-transaction QR and recorded by the PC. Any outgoing transaction **without** a matching receipt = critical.
3. **App checks when the PC is on:** unknown nonces, new token approvals, EIP-7702 code on ETH addresses, TRON permission changes (main plan §8.2, §8.5).
4. **Weekly manual check** on public explorers of every wallet's balance, approvals and TRON permissions.

**What's weaker than the main plan:** no 2-minute polling, no heartbeat, and no anti-rollback checkpoints for the PC's policy database. The phone's own allowlist, limits and log are therefore the **authoritative** policy in this variant, and the PC's policy is a convenience layer.

---

## 7. Risk register

Severity = impact if it happens. Residual = what's left after the fixes.

| # | Risk | Severity | Fixes | Residual |
|---|---|---|---|---|
| R1 | **Daily phone (Option B) is online and full of apps** — malware could read the decrypted seed while signing | Critical | Option B only for a capped Spending wallet; no `INTERNET` permission; StrongBox + per-signature authentication; separate profile; Savings/Vault never on Option B | Spending balance (≤ ₹25k) can be lost |
| R2 | **Accessibility / overlay trojans** on Android tap "approve" or read the screen | Critical | Refuse to run with accessibility services or overlays active; touches blocked when obscured; typed recipient confirmation | Low on Option A; moderate on Option B |
| R3 | **Fake or poisoned signer app** (malicious update, sideloaded fake, poisoned build from your dev account) | Critical | Reviewed release, two-build hash check, install only via cable after hash match; build account separate from dev account; never install signer updates from links or messages | Depends on the independent review (main plan §15) |
| R4 | **PC compromised** (it's also your business/dev PC, so higher chance) — shows fake transaction or fake receive address | High | No keys on PC; phone decodes and displays; "verify on phone" for receive addresses; phone allowlist; compare with paper | Low, if you always check the phone screen |
| R5 | **Remote-support / screen-share scam** ("Binance support", "refund agent") | Critical | Never install remote-support apps; signer refuses during screen sharing; nobody legitimate ever needs your screen, seed or codes | Social engineering stays your risk |
| R6 | **Seed photographed or synced to cloud** (gallery backup, notes, WhatsApp to self) | Critical | Paper/steel only; never photograph; app blocks screenshots; phone cloud backup off for the signer | — |
| R7 | **Keyboard logging** of passwords/passphrases | High | In-app keyboard only for secrets | Low |
| R8 | **Phone lost or stolen** | High | Strong lock, StrongBox-wrapped vault, separate vault password, passphrase for Savings; stateless Vault; restore from paper and move funds to new seeds within hours | Spending at risk if the thief also learns PIN + vault password |
| R9 | **Phone stolen while unlocked** (snatch theft) | High | Per-signature authentication; vault password separate from phone PIN; signer locks immediately after each session; Android theft-protection lock on | Low |
| R10 | **iPhone as daily phone** — can't run the signer | Medium | Use an Android device (Option A) | — |
| R11 | **Option A phone accidentally goes online** (airplane mode turned off, Wi-Fi joined) | High | App refuses to run unless airplane mode is on with no connections and no SIM; check on every start | If it happens, treat stored seeds as exposed and move funds to new seeds |
| R12 | **Old phone without security updates** | Medium | Acceptable **only** for Option A (offline); never for Option B; prefer devices with StrongBox and verified boot | Low on Option A |
| R13 | **Rooted / unlocked-bootloader phone** | High | On-device key attestation: refuse unless verified boot is green (or GrapheneOS's verified state); no rooting | Low |
| R14 | **Malicious QR payload** exploiting a parser bug | High | Strict, size-limited, fuzzed decoder; no WebView; unknown types rejected | Low |
| R15 | **Address poisoning / clipboard swap** | High | Address book only; paper comparison; look-alike block (≥3 shared leading/trailing chars); hide dust | Low |
| R16 | **Fake USDT token or wrong network** | High | Pinned contracts; network shown in large text; cross-network addresses rejected | Low |
| R17 | **Blind signing / approvals / permits / EIP-7702** | Critical | Closed operation list (main plan P13, §8.0); no contract calls except USDT `transfer` | Low |
| R18 | **No always-on monitor** — theft noticed late | High | Explorer email alerts on all addresses; receipts check; weekly manual check; caps limit loss | Detection is slower than the main plan |
| R19 | **One phone signs for everything** (single point of failure) | High | One vault + password per wallet; passphrases never stored; stateless Vault; Savings/Vault only on Option A | Compromise of the signer phone during a Savings session exposes Savings |
| R20 | **Self-lockout** (forgotten passphrase, lost paper) | Critical | 2 paper copies in 2 places; passphrase stored separately and tested; restore test before funding; drill every 6 months | — |
| R21 | **Building and reviewing a signer app takes longer than a month** | Medium | This month: create wallets, receive-only, watch-only. Real sends only after testnet gates and review (§10) | Until then, funds can't be moved with the custom app (emergency: restore seed into a well-known wallet on a fresh device and move to a new seed) |
| R22 | **Dirty funds received** (stolen crypto from a payer; USDT frozen by Tether) | Medium | Prefer identifiable payers; keep invoices/records; don't move unexpected large funds from strangers; get advice | — |
| R23 | **Tax and records** | Medium | Record date, txid, amount, counterparty, purpose and INR value for every transaction | — |

---

## 8. What NOT to do in this variant

- Don't put Savings or Vault keys on your daily phone.
- Don't type or scan any seed into the PC, a website, or a cloud notes app.
- Don't install the signer from a link, store listing you didn't create, or a file someone sent you.
- Don't share your screen with anyone while the signer is open, or ever with "support".
- Don't approve on the phone what you haven't compared with paper.
- Don't add automatic or "sign all" signing (main plan P18).

---

## 9. Decisions

| # | Decision | Recommendation | By |
|---|---|---|---|
| D-M1 | Signer phone | **Option A** (dedicated offline Android with StrongBox; GrapheneOS-capable Pixel is best). Option B only for capped Spending until then | Week 1 |
| D-M2 | Signer app UI technology | Kotlin + Jetpack Compose UI, Rust core via UniFFI; no WebView | Week 2 |
| D-M3 | Spending cap | Option A ≤ ₹50k; Option B ≤ ₹25k | Week 1 |
| D-M4 | Wallets this month | `spend-01`, `savings-01` (receive-only until Option A), optional `vault-01` (receive-only) | Week 1 |
| D-M5 | Seed creation before the signer app is ready | Only on an offline Option A phone, with the signer's tested generator, or a well-known open-source BIP-39 wallet installed offline from a verified download; then restore-test in a second wallet | Week 1–2 |

---

## 10. Plan for this month and gates

| Week | Work | Gate before moving on |
|---|---|---|
| **1** | Decide D-M1…D-M5; prepare the PC's "wallet" account (§5.3); prepare the phone (§5.1 or §5.2); paper, passphrase, SeedQR materials; set up explorer email alerts | Phone passes its start-up checks (§5.1/§5.2) |
| **2** | Watch-only PC app (main plan Phase 1 scope, without the monitor device); import xpubs from the phone by QR | Balances match explorers; poisoning dust is hidden |
| **2** | Create `savings-01` (and `vault-01`) seeds offline; restore test | Same addresses in an independent wallet on all 3 networks → **receive-only funding allowed** |
| **3–4** | Signer app on **testnets** (BTC testnet4/signet, ETH Sepolia, TRON Nile): vaults, QR transport, validators, signer policy | All main-plan Phase 2 test suites that apply (malformed tx, manipulated RPC, recipient substitution, fee manipulation, QR channel) pass; leak scan clean; app refuses to run when its checks fail |
| **After** | Independent review → canary (≤ ₹500) → Spending live → Savings live (Option A only) | Main plan §15 sequence, with G12 replaced by "signer phone passes §5.1/§5.2 checks" |

**Receive-only funding can start in week 2** (as soon as seeds are created offline and the restore test passes), because receiving needs no signing.

---

## 11. Upgrade path to the main plan

| When | Upgrade |
|---|---|
| A spare phone is available | Move to **Option A**; retire Option B; Savings becomes signable |
| Budget allows ~₹1–3k/month or a small device | Raspberry Pi monitor (main plan §10.0) replaces explorer-only alerts |
| Budget allows a hardware wallet | Add it as a second signer; BTC Vault becomes 2-of-3 multisig (main plan §4.1, D1) |
| Budget allows a dedicated laptop | Full main plan rev 4.1; the Option A phone stays as a second signer |

Each upgrade is a new seed or an added key; **move funds to new wallets** rather than re-using seeds that were ever on Option B.

---

## Disclaimer

Security-engineering design for a personal wallet, not financial, tax or legal advice. Verify contract addresses, Android security features of your exact phone model, and library versions against official sources at implementation time.
