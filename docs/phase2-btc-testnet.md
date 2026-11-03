# Phase 2, step 1: Bitcoin sending on the test network (signet)

Coins on **signet** have no value. Mainnet signing is not compiled into this build; it is enabled only after the Phase 2 gates (ARCHITECTURE-MOBILE.md §10, main plan §15).

## The flow

| Step | Where | What happens |
|---|---|---|
| ① Draft | PC | Choose wallet, recipient **from the address book** (waiting period over), amount, fee rate |
| ② Build | PC | Pick coins (largest first), add change to a fresh change address, build an **unsigned PSBT** that carries the full previous transaction of every coin, the key paths and the master fingerprint |
| ③ Show | PC | Shows amount, recipient, fee, change and the first 8 characters of the transaction ID; then the PSBT as a QR code |
| ④ Scan | Tablet | Scans the QR (camera, offline) |
| ⑤ Check | Tablet | Unlock the wallet, then **work everything out independently** (below). Anything unusual → refused |
| ⑥ Approve | Tablet | Shows network, recipient (grouped, bold ends), amount, fee, change, transaction ID start. You compare the recipient with your **paper** address book and type its **last 6 characters** |
| ⑦ Sign | Tablet | Signs only what was checked; shows the signed PSBT as a QR |
| ⑧ Verify | PC | Takes **only the signatures**, puts them on the transaction it built in ②, verifies each one; anything else that came back is ignored |
| ⑨ Send | PC | Broadcasts to the network through 2 providers; shows the transaction ID |

## What the tablet checks (crates/signer-core/src/btc_sign.rs)

- Every input is this wallet's coin: key derived on the tablet at `m/84'/1'/0'/{0,1}/i`, same master fingerprint, script = P2WPKH of that key.
- Every coin's amount and script come from its **full previous transaction**, whose id must match (stops the SegWit "fee lie" across signing sessions).
- Exactly **one recipient**, and at most **one change** output, which must really be this wallet's change address (derived on the tablet). Change claimed on the receive chain, at another wallet, or at an address that doesn't match → refused.
- Fee computed on the tablet: refused above 100,000 sats or 500 sat/vB, or if zero.
- Refused: lock time, unusual sequence numbers, more than 20 inputs, dust outputs, non-standard outputs, the same coin twice, signature types other than ALL, already-present signatures, scripts, Taproot fields, unknown or proprietary data, global xpubs.

## What the PC checks (crates/btc-send)

- Coins it uses really belong to the account (derived from the wallet's test-network public key).
- Only signet addresses are accepted as recipients.
- After signing: the returned transaction must be **identical** to the one built; each input must carry exactly one signature from the expected key, of type ALL, valid for that input. Signatures for any other transaction fail.

## Tests (crates/btc-send/tests/e2e.rs)

| Test | Result |
|---|---|
| Honest payment: PC plan = tablet review (recipient, amount, change, fee, transaction ID); signed, finalised; ID unchanged by signing | ✅ |
| Several coins; leftover below dust goes to the fee; not enough funds | ✅ |
| Recipient swapped in the QR channel → visible on the tablet (different address and ID); signatures not usable by the PC | ✅ |
| Amount changed on the way back → refused by the PC | ✅ |
| Signatures from another transaction grafted on / missing → refused | ✅ |
| Coin amount lie, swapped or missing previous transaction, another wallet's coin, wrong key path → refused by the tablet | ✅ |
| Fake change (attacker's address, receive chain), second recipient, huge fee, lock time, unknown data, unusual signature type → refused by the tablet | ✅ |
| Mainnet address as recipient → refused | ✅ |

## Built since

- **Test-network export** (`WWT1:`, separate from the mainnet `WWX1:` export; neither is accepted as the other). The tablet bridge has `test_export_string`, `review_btc` and `sign_btc` on an unlocked wallet; `sign_btc` signs only if the request still has the reviewed transaction ID **and** the typed last 6 characters match the recipient. Tested end to end through the bridge (vault → export → PC build → review → wrong last-6 refused → changed request refused → sign → PC finalise).
- **PSBT QR envelope** (`WPS1:` + base64 + checksum, up to 2,100 bytes in one QR).
- **Signet data on the PC** (`config/networks.v1.toml` → `signet_providers`: mempool.space and mempool.emzy.de, separate from the real providers): balances cross-checked, coins and previous transactions (checked to hash to the coin's id), broadcast to both providers.
- **PC commands** (27 reviewed): test wallets add / list / remove / scan (balance, fresh receive address, next change index), `prepare_test_send` (builds the payment, keeps its own copy, returns the QR), `finish_test_send` (only signatures taken; verified; broadcast; audit-log entry).

## Still to build for this step

1. ~~Test-network export~~ ✅
2. ~~Signet data on the PC~~ ✅
3. **Tablet camera QR scanner** (offline; CAMERA permission only, still no INTERNET) and the review/approve/sign screens, including "type the last 6 characters".
4. **PC Send page** (signet only): draft from the address book → QR → scan the signed QR with the webcam → verify → broadcast.
5. **Larger requests:** multi-part QR codes if a PSBT doesn't fit in one QR (many coins).
6. Then: the tablet's own allowlist and limits, and the signing log with receipts.

Getting test coins: a signet faucet (e.g. signetfaucet.com) pays to a receive address of the test wallet.
