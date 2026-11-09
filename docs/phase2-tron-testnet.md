# Phase 2: USDT on TRON, test network (Nile)

Nile coins and Nile USDT have **no value**. The tablet's test build signs **only** the Nile test USDT contract `TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf` (TRON wallet-cli token list for Nile, "official", 6 decimals), so mainnet USDT can't be signed by mistake. The PC's config pins the same value; a test checks they agree.

Sources: Nile node `nile.trongrid.io` and the Nile USDT contract are taken from TRON's own `tronprotocol/wallet-cli` docs (network table, `token list --network nile`). Only one public Nile operator is known, so Nile data is single-source (labelled in the app). Real (mainnet) balances keep using two providers.

## Flow

| Step | Where | What happens |
|---|---|---|
| ① Build | PC | Reads the latest **solidified** block from the node (reference block, time). Builds the `TriggerSmartContract` USDT `transfer` **locally** (crates/tron-tx); no node endpoint builds anything that gets signed. Fee limit 30 TRX, valid 9 minutes. Shown with the first 8 characters of the transaction ID and a QR (`WTR1:`) |
| ② Check | Tablet | Decodes strictly and works everything out itself (below) |
| ③ Approve | Tablet | Shows network, token, recipient (grouped, bold ends), amount, fee limit, sender, transaction ID start. You type the recipient's **last 6 characters from paper**; **case-sensitive** for TRON |
| ④ Sign | Tablet | Signs the transaction ID (SHA-256 of the raw transaction); shows `WTS1:` = transaction ID + 65-byte signature |
| ⑤ Verify, send | PC | The ID must equal the one of the transaction it built; the signature must recover to the wallet's own TRON address; then `/wallet/broadcasthex`. Errors from the node are shown in plain text |

## What the tablet checks (crates/signer-core/src/tron_sign.rs, crates/tron-tx)

- Exactly one contract, type `TriggerSmartContract` (31), `type_url` exact; unknown fields at any level, a memo, a second contract, or a non-zero `Permission_id` → refused.
- Contract = pinned **Nile** USDT; owner = this wallet's TRON address (derived on the tablet at `m/44'/195'/0'/0/0`, the same address as the watch-only export).
- Data = exactly 68 bytes `transfer(address,uint256)` with standard zero-padded words; amount > 0; recipient ≠ this wallet; no TRX or other token sent along.
- Fee limit 0 < x ≤ 30 TRX; validity (expiration − timestamp) ≤ 10 minutes; not long expired and not dated in the future by the tablet's clock (±10 minutes).

## Tests

- **Matches a real Nile transaction** from TRON's wallet-cli docs: our encoder produces the same bytes, our ID equals TRON's TxId, and signature recovery gives the documented sender.
- Strict decoding: memo, second contract, unknown field, truncated data, non-transfer call → refused.
- Tablet rules: mainnet USDT, another owner, fee limit 31 TRX, 24-hour validity, expired, zero amount, sending to itself → refused; same address as the export.
- PC: build from a block, signature from another key / for another transaction / truncated → refused; broadcast success and a hex-encoded refusal message.
- Through the tablet bridge: unlock → review → lowercase last-6 refused → sign → PC-side recovery gives the wallet's address.

## Not yet

- A second independent Nile node (only TronGrid is known).
- The account permission check before signing (§8.5) and the TRX top-up between own wallets (§8.3b).
- Energy estimate before signing (the fee limit caps the cost).
