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

Still to do for this gate: Ethereum (compare with etherscan.io) and Bitcoin (compare with blockchair.com), and then each real wallet once it exists.

### Exit gate: other Phase 1 items

| Item | Status |
|---|---|
| Config hash identical on Windows and Linux | ✅ Fixed in `04a304a` (LF-normalised hash + `.gitattributes`). Expected `dbc4204f…979f` from `7dc60d7` on. |
| Test outgoing tx triggers an alert within 5 minutes with the PC off | ⏳ Needs the monitor / explorer alerts |
| Monitor heartbeat on both channels | ⏳ Not built |
| Restoring an older `policy.db` is detected | ⏳ Not built |
| Allowance and permission baselines recorded | ⏳ Not built |
| Poisoning-style 0-value transfer detected and hidden | ⏳ Not built (needs transaction history) |
| No secret-handling code paths in the online app | ✅ By design; registry refuses seeds/private keys (tested) |
