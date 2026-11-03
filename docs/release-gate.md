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
| Config hash identical on Windows and Linux | ✅ Fixed in `04a304a` (LF-normalised hash + `.gitattributes`). The hash changes with every reviewed config change: `dbc4204f…979f` (`7dc60d7`), `d2a17131…0134` (`5a51049`), `8b27e487…4ae5` (`0452a4f`), `34a37160…7b3d` (third Bitcoin source, current). |
| Test outgoing tx triggers an alert within 5 minutes with the PC off | ⏳ Set up per `docs/alerts-guide.md`, then record each test below |
| Monitor heartbeat on both channels | ⏳ Not built |
| Restoring an older `policy.db` is detected | ⏳ Not built |
| Allowance and permission baselines recorded | ⏳ Not built |
| Poisoning-style 0-value transfer detected and hidden | 🔧 Built for TRON (`5a51049`, `0452a4f`; unit-tested with a real Base58 look-alike address). Live check with a testnet 0-value transfer still to do. Ethereum and Bitcoin history not built yet. |
| No secret-handling code paths in the online app | ✅ By design; registry refuses seeds/private keys (tested) |
| Third Bitcoin source (`emzy-mempool`, mempool.emzy.de) | 🔧 Added so one slow or rate-limited provider no longer leaves Bitcoin unverified (the other two must still agree exactly). Not reachable from the build environment: **owner to confirm it answers from the PC** (About page lists it; a refresh log line shows its timing). |
| Start-up checks and login (§9.8) | 🔧 Built: password + TOTP, encrypted store, lockout, idle lock, PC checks. Tested end-to-end on Linux (setup with migration, wrong code, login, lock, checks page). Windows-specific checks compiled for Windows and parser-tested; **first run on the owner's Windows PC still to do.** |

### Alert tests (docs/alerts-guide.md step 6)

| Date | Network | Service | Direction | PC off? | Minutes until email | Pass |
|---|---|---|---|---|---|---|
