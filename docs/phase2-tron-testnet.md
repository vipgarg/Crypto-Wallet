# Phase 2: USDT on TRON, test network (Nile)

Nile coins and Nile USDT have **no value**. The tablet's test build signs **only** the Nile test USDT contract `TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf` (TRON wallet-cli token list for Nile, "official", 6 decimals), so mainnet USDT can't be signed by mistake. The PC's config pins the same value; a test checks they agree.

Sources: Nile node `nile.trongrid.io` and the Nile USDT contract are taken from TRON's own `tronprotocol/wallet-cli` docs (network table, `token list --network nile`). Only one public Nile operator is known, so Nile data is single-source (labelled in the app). Real (mainnet) balances keep using two providers.

## Flow

| Step | Where | What happens |
|---|---|---|
| ⓪ Allow | Tablet | Once per recipient: Test networks → Allowlist, limits and signing log → add the address (typed from paper, or scanned from the recipient's own device). Usable after **10 minutes** (test networks; 24 hours on real ones) |
| ① Build | PC | Checks the sender: activated, has TRX, and its **permissions are the single-key baseline** (owner and active: threshold 1, one key = this wallet's address, weight 1; no extra active or witness permission). Then reads the latest **solidified** block from the node (reference block, time). Builds the `TriggerSmartContract` USDT `transfer` **locally** (crates/tron-tx); no node endpoint builds anything that gets signed. Fee limit 30 TRX, valid 9 minutes. Shown with the first 8 characters of the transaction ID and a QR (`WTR1:`) |
| ② Check | Tablet | Decodes strictly and works everything out itself (below); the recipient must be on **this tablet's allowlist** (waited) and the amount within the **daily limit** |
| ③ Approve | Tablet | Shows network, token, recipient (grouped, bold ends), amount, fee limit, sender, transaction ID start. You type the recipient's **last 6 characters from paper**; **case-sensitive** for TRON |
| ④ Sign | Tablet | Logs the signature in the wallet's hash-chained signing log (saved before anything is shown), signs the transaction ID (SHA-256 of the raw transaction); shows `WTS1:` = transaction ID + 65-byte signature + receipt (log number, 8 bytes, and log head, 32 bytes) |
| ⑤ Verify, send | PC | The ID must equal the one of the transaction it built; the signature must recover to the wallet's own TRON address; then `/wallet/broadcasthex`. Errors from the node are shown in plain text. The receipt goes in the audit log; if the log number jumped, the PC warns that the tablet signed payments it didn't see |

## What the tablet checks (crates/signer-core/src/tron_sign.rs, crates/tron-tx)

- Exactly one contract, type `TriggerSmartContract` (31), `type_url` exact; unknown fields at any level, a memo, a second contract, or a non-zero `Permission_id` → refused.
- Contract = pinned **Nile** USDT; owner = this wallet's TRON address (derived on the tablet at `m/44'/195'/0'/0/0`, the same address as the watch-only export).
- Data = exactly 68 bytes `transfer(address,uint256)` with standard zero-padded words; amount > 0; recipient ≠ this wallet; no TRX or other token sent along.
- Fee limit 0 < x ≤ 30 TRX; validity (expiration − timestamp) ≤ 10 minutes; not long expired and not dated in the future by the tablet's clock (±10 minutes).

## TRX top-ups between your own wallets (§8.3b)

Sending USDT costs TRX, so each wallet needs a little. Test send → USDT on TRON Nile → **TRX top-up to my own wallet**: the recipient is chosen from your own wallets (the PC refuses anything else), at most 200 TRX. The transaction is a plain `TransferContract` (type 1), built locally, with no fee limit field. The tablet signs it only if the recipient is **another wallet on this tablet** and on its allowlist, within the daily TRX limit; a TRX transfer is never read as a USDT one or the other way round, and any other contract type (votes, freezing, permission updates…) is refused.

## Fee estimate

Before the QR is shown, the PC estimates the network cost, for display only: a dry-run of the USDT transfer gives the energy needed (`triggerconstantcontract`), the account's own energy and bandwidth come from `getaccountresource`, and the prices from `getchainparameters` (`getEnergyFee`, `getTransactionFee`). Shown as "about X TRX (energy N needed, M available; bandwidth …)". Nothing that gets signed depends on it; the fee limit (30 TRX) still caps the cost.

## The tablet's signing policy (crates/signer-core/src/policy.rs)

Holds even if the PC is fully compromised. One policy per wallet, saved next to its vault (`wallets/<id>.policy`), sealed with an HMAC whose key comes from the wallet's seed: it can be read or changed only after unlocking, and a file edited outside the app (or copied from another wallet) is refused. Deleting it gives an empty allowlist, so nothing can be signed until newly added addresses have waited.

- **Allowlist** per network (test and real networks are separate). New addresses wait 10 minutes on test networks, 24 hours on real ones, by the tablet's clock; removing is immediate. Ethereum addresses must be typed with their checksum capitals. This build requires the allowlist for every wallet tier (stricter than the plan, where Spending could pay any address within its limit).
- **Daily limits** per asset, rolling 24 hours: 1000 test USDT / test TRX, 0.01 test BTC to start. Lowering is immediate; raising waits like a new address. Signed-but-never-sent payments count.
- **Signing log**: number, time, asset, recipient, amount, transaction ID; each entry hashes the previous one, and the whole chain is checked on every open. A tablet clock earlier than the last signature (by more than 10 minutes) is refused.
- **Receipts**: the PC keeps the last log number per wallet in its encrypted store; a jump means signatures it never saw (cancelled ones, another PC, or an attacker) and is shown as a warning; a step back means the policy was reset or restored.

## Tests

- **Matches a real Nile transaction** from TRON's wallet-cli docs: our encoder produces the same bytes, our ID equals TRON's TxId, and signature recovery gives the documented sender.
- Strict decoding: memo, second contract, unknown field, truncated data, non-transfer call → refused.
- Tablet rules: mainnet USDT, another owner, fee limit 31 TRX, 24-hour validity, expired, zero amount, sending to itself → refused; same address as the export.
- PC: build from a block, signature from another key / for another transaction / truncated → refused; broadcast success and a hex-encoded refusal message.
- Through the tablet bridge: unlock → review → lowercase last-6 refused → sign → PC-side recovery gives the wallet's address.
- Policy: unknown and still-waiting addresses refused; rolling daily limit; raise waits, lower doesn't; edited file, other wallet's file, wrong key, re-sealed broken chain → refused; clock moved back refused; receipts round-trip; the PC warns on a jump or a step back.
- TRX: encode/decode round trip; a TRX transfer isn't read as USDT (and vice versa); fee-limit field, zero amount, other contract types refused; tablet refuses a recipient that isn't one of its own wallets and more than 200 TRX.
- Fee estimate: dry-run energy, own resources and chain prices combined (mock node).
- Account permissions: extra owner key, replaced active key, threshold 2, two active permissions, a witness permission → refused before building.

## Owner test

2026-11-09: test USDT payments from two test wallets signed on the tablet and confirmed on nile.tronscan.org. A sender address that had received only USDT failed with "account does not exist" (TRON accounts are activated by receiving TRX); the PC now checks the sender before building and explains it.

## Not yet

- A second independent Nile node (only TronGrid is known).
