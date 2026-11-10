# Release Gate Evidence

Evidence for the phase exit gates (ARCHITECTURE.md §11) and the release gates (§15). Every entry records the date, what was checked, the build it was checked on, and the result. Entries are never edited afterwards; corrections are new entries.

---

## Phase 1 — Watch-only portfolio

### Provider reachability from the owner's Windows PC

| Date | Build (commit) | Network | Provider | Result | Notes |
|---|---|---|---|---|---|
| 2026-11-02 | `7dc60d7` | TRON | trongrid | ✅ answers, ~0.5–0.8 s | |
| 2026-11-02 | `7dc60d7` | TRON | publicnode-tron | ✅ answers, ~0.4–1.2 s | |
| 2026-11-02 | `7dc60d7` | Ethereum | publicnode-eth | ✅ answers, ~0.2–0.5 s | |
| 2026-11-02 | `7dc60d7` | Ethereum | drpc-eth | ✅ answers, ~0.4–0.8 s | |
| 2026-11-02 | `7dc60d7` | Ethereum | 1rpc-eth | ✅ answers, ~0.5–1.2 s | |
| 2026-11-02 | `306a185` | Ethereum | llamarpc-eth | ❌ HTTP 525 | Removed from config in `7dc60d7`. |
| 2026-11-02 | `9f1d4f5` | Bitcoin | blockstream | ✅ answers, ~0.2–2.5 s | |
| 2026-11-02 | `9f1d4f5` | Bitcoin | mempool-space | ⚠️ rate-limited | Answered ~105 address requests, then HTTP 429 and timeouts. Only reached with the busy public BIP-84 test key (90 addresses per scan). Re-check with a real wallet; consider a third Bitcoin provider (option B) or an own node (§5.5). |

### Exit gate: "Balances match block explorers for every wallet"

| Date | Build (commit) | Network | Address | Explorer | App result | Match | Checked by |
|---|---|---|---|---|---|---|---|
| 2026-11-02 | `cc03b6c` | TRON | third-party address picked from the USDT holders list (not recorded) | tronscan.org | USDT (TRC-20) and TRX, both "Verified" | ✅ Yes | Owner |

### Activity (history) matches block explorer

| Date | Build (commit) | Network | Address | Explorer | What was compared | Match | Checked by |
|---|---|---|---|---|---|---|---|
| 2026-11-02 | `5a51049` | TRON | third-party address (not recorded) | tronscan.org "Transfers" | USDT transfers: type, amount, counterparty | ✅ Yes | Owner |
| 2026-11-02 | `0452a4f` | TRON | third-party address (not recorded) | tronscan.org "Transactions" | Account transactions: type, amount, counterparty | ✅ Yes | Owner |

Still to do for this gate: Ethereum (compare with etherscan.io) and Bitcoin (compare with blockchair.com), and then each real wallet once it exists.

### Exit gate: other Phase 1 items

| Item | Status |
|---|---|
| Config hash identical on Windows and Linux | ✅ Fixed in `04a304a` (LF-normalised hash + `.gitattributes`). The hash changes with every reviewed config change: `dbc4204f…979f` (`7dc60d7`), `d2a17131…0134` (`5a51049`), `8b27e487…4ae5` (`0452a4f`), `34a37160…7b3d` (third Bitcoin source), `14fbbbbc…54f8` (Blockscout history indexer), `b2448ed0…bcd0` (signet test providers), `f09f459f…78b6` (TRON Nile test node and test USDT), `03222ec3…cdae` (Ethereum Sepolia test nodes and test USDT, current). |
| Test outgoing tx triggers an alert within 5 minutes with the PC off | ⏳ Set up per `docs/alerts-guide.md`, then record each test below |
| Monitor heartbeat on both channels | ⏳ Not built |
| Restoring an older `policy.db` is detected | ⏳ Not built |
| Allowance and permission baselines recorded | ⏳ Not built |
| Poisoning-style 0-value transfer detected and hidden | 🔧 Built for TRON (`5a51049`, `0452a4f`), **Ethereum** (Blockscout: token transfers + transactions; 0-value `transferFrom` poisoning, fake tokens, USDT/ETH dust, approvals incl. unlimited and set-for-all, USDT moved by someone else) and **Bitcoin** (Esplora per used address; dust < 1,000 sats hidden with a tracking warning, look-alikes vs own receive addresses and real counterparties). Unit-tested; not yet compared live with etherscan.io / a Bitcoin explorer. **Owner:** load Activity for a known Ethereum and Bitcoin address and compare with an explorer, as done for TRON. |
| No secret-handling code paths in the online app | ✅ By design; registry refuses seeds/private keys (tested) |
| Phase 2 signing on a test network: USDT on TRON Nile | ✅ 2026-11-09, owner: test USDT payments signed on the offline tablet (review on the tablet, last-6 approval) and broadcast from the PC, from two test wallets; confirmed on nile.tronscan.org. Found and fixed on the way: an address that only received USDT (never TRX) isn't an account yet; the PC now explains this before anything is signed (`afcc88d`). |
| Address book (§7.1, online copy) | 🔧 Built: verification method, tier permissions, 24 h waiting period in network time (fails closed), look-alike and own-wallet refusal, edit = remove + add, revocation list, paper confirmation, audit-log entries (id + network only). Tested. Not yet: monitor alerts and anti-rollback for the book (needs the external monitor), signer-side allowlist (Phase 2). |
| Audit log (hash-chained, §9.5) | 🔧 Built: logins, failed/blocked attempts, locks, wallet changes, check problems; verified at start, broken log kept and a new chain started; Log page + Checks entry. Tested (edit, removal, reorder, cut-off, change while running). Owner: review weekly; write the head on paper. External monitor checkpoints not built yet. |
| Third Bitcoin source (`emzy-mempool`, mempool.emzy.de) | 🔧 Added so one slow or rate-limited provider no longer leaves Bitcoin unverified (the other two must still agree exactly). Not reachable from the build environment: **owner to confirm it answers from the PC** (About page lists it; a refresh log line shows its timing). |
| Start-up checks and login (§9.8) | 🔧 Built: password + TOTP, encrypted store, lockout, idle lock, PC checks. Tested end-to-end on Linux (setup with migration, wrong code, login, lock, checks page). Windows-specific checks compiled for Windows and parser-tested; **first run on the owner's Windows PC still to do.** |

### Alert tests (docs/alerts-guide.md step 6)

| Date | Network | Service | Direction | PC off? | Minutes until email | Pass |
|---|---|---|---|---|---|---|

## Before real money: the final gates (owner)

Everything below is built and **off**. Real-network signing needs all three switches, each a deliberate act: a real-network tablet build, real wallets made by it, and real sending switched on in the PC app. Do the gates in this order and record each one here (date, result, what you saw).

### Gate 0: prerequisites (record when done)

| Item | How | Record |
|---|---|---|
| Signing key pinned | Compare the start-up check's "App signed with your key" fingerprint (or `signing-cert.txt` in the CI download) with `keytool -list -v` on your PC. When identical, commit `android/signing-cert.sha256` (one line, 64 hex). From then on CI refuses any other key and the app checks itself. | |
| Test-network practice done | TRON Nile USDT + TRX top-up, Ethereum Sepolia USDT, each signed on the tablet with the allowlist and limits in place; signing log numbers match the PC's audit log | |
| Tamper check passes on the OnePlus | Start-up checks all green except the optional ones | |

### Gate 1: recovery test

1. Factory-reset the tablet (Settings → System → Reset). Set it up offline: no Google account, no Wi-Fi, airplane mode on, no SIM.
2. Install the **real-network build** (below) with `adb install`, then switch USB debugging and developer options off.
3. Restore a wallet using **only your paper** (words + passphrase). The fingerprint and addresses on the confirmation step must match your paper record.
4. Record: date, fingerprint matched (yes/no). If it doesn't match, stop: the paper backup is wrong.

### Gate 2: real wallets

1. On the real-network build, create the real wallets **fresh**, with new dice rolls (at least 99). Never reuse a test wallet's words: wallets from test builds can't sign real payments anyway.
2. Write the words and passphrase on paper (two copies, two places). Run the word check.
3. Add each wallet to the PC (webcam scan of the export QR). Compare fingerprint and addresses on both screens.
4. On the tablet: Allowlist → add your recipients (typed from paper), then wait out the wallet's waiting period. Check the daily limits (start: 50 USDT / 50 TRX a day; raising also waits).
5. On the PC: add the same recipients to the address book (its waiting period, by network time).

**Waiting periods for trials.** When you create a real wallet you choose its waiting period: 10 minutes, 1 hour, 6 hours or 24 hours (sealed in its vault). Small trial wallets can use 10 minutes; wallets that will hold savings should use 24 hours. Later, Allowlist → Waiting period → Change: longer applies at once, shorter only after the current wait (so a stolen vault password can't remove it). The PC address book's waiting period is set on the Address book page (10 minutes to 24 hours, applies at once, audit-logged). Set both back to 24 hours before moving larger amounts.

### Gate 3: switch on real-network signing

1. **Tablet build:** GitHub → Actions → "Android signer (testnet)" → Run workflow → tick **REAL-NETWORK build**. The run refuses without the signing key secrets and `android/signing-cert.sha256`. The download is `wallet-signer-REAL-<commit>.apk`; check its SHA-256 and the signing certificate before installing. The app shows a red "REAL-NETWORK BUILD" line, and its signing-key check is critical (it won't run with another key).
2. **PC:** Test send → "Real-network sending" → type `I HAVE PASSED THE RELEASE GATES` → Switch on. It is recorded in the audit log; switch it off the same way.
3. What's enforced from then on:
   - Tablet: only wallets made by the real build sign real payments, only to its allowlist (24 h wait), within its daily limits; real USDT contracts pinned (TRON `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t`, Ethereum `0xdAC17F958D2ee523a2206206994597C13D831ec7`, chain id 1); fee caps 30 TRX / 0.005 ETH; TRX only to your own wallets (≤ 200 TRX); every signature logged with a receipt.
   - PC: real USDT only to address-book entries whose 24-hour wait is over; the TRON account's permissions must be the single-key baseline; the signature must recover to the wallet for exactly the transaction built; receipts checked for gaps; real payments logged as `real_payment_sent`.

### Gate 4: small real trial (≤ ₹500)

1. TRON first: fund one real wallet with a little TRX (activation + fees) and ≤ ₹500 of USDT. Send a small USDT amount to an allowlisted address you control. Check it on tronscan.org, and the tablet log number against the PC audit log.
2. Then Ethereum: a little ETH for gas and ≤ ₹500 of USDT; same check on etherscan.io.
3. Record: date, transaction IDs, fee paid, anything surprising. Only after both succeed, move larger amounts, gradually, within the limits.

| Gate | Date | Result | Notes |
|---|---|---|---|
| 0 Prerequisites | | | |
| 1 Recovery test | | | |
| 2 Real wallets | | | |
| 3 Switch on | | | |
| 4 Trial TRON | | | |
| 4 Trial Ethereum | | | |
