# Phase 2: USDT on Ethereum, test network (Sepolia)

Sepolia ETH and Sepolia USDT have **no value**. The tablet's test build signs **only** chain id 11155111 and the test USDT contract `0xaA8E23Fb1079EA71e0a56F48a2aA51851D8433D0` (Aave V3 Sepolia market `USDT_UNDERLYING`, 6 decimals, from `bgd-labs/aave-address-book`, `AaveV3Sepolia.sol`). The PC's config pins the same value; a test checks they agree. Mainnet USDT or mainnet chain id → refused.

Nodes: the Sepolia endpoints of PublicNode and dRPC (the same operators as two mainnet Ethereum providers). As for the mainnet ones, confirm on your PC that they answer before relying on them. Test coins: test ETH from any Sepolia faucet (for fees); test USDT from Aave's faucet (Sepolia market).

## Flow

| Step | Where | What happens |
|---|---|---|
| ⓪ Allow | Tablet | Once per recipient: add it on the tablet's allowlist (Ethereum Sepolia), typed with its checksum capitals; usable after 10 minutes |
| ① Build | PC | Checks the chain id, the wallet's test USDT and test ETH, gets the nonce (pending), base fee and tip, and a gas estimate (+30 %, between 60,000 and 120,000). Builds the EIP-1559 transaction **locally** (crates/eth-tx). Shows recipient, amount, likely and worst-case fee, nonce, and the start of the request ID (signing hash); QR `WER1:` |
| ② Check | Tablet | Decodes strictly (below), checks the allowlist and daily limit |
| ③ Approve | Tablet | Shows network, token, recipient and its allowlist name, amount, worst-case fee, sender, nonce, request ID start. You type the recipient's last 6 characters from paper (hex: capitals don't matter) |
| ④ Sign | Tablet | Logs the signature (hash-chained), signs; QR `WES1:` = signature (r, s, y-parity) + receipt (log number, log head) |
| ⑤ Verify, send | PC | The signature must recover to this wallet's address **for the transaction built here**; then `eth_sendRawTransaction` to every Sepolia node (accepted if any accepts). Receipt recorded; a jump in log numbers is warned about |

## What the tablet checks (crates/signer-core/src/eth_sign.rs, crates/eth-tx)

- Type 2 (EIP-1559) only; canonical RLP (minimal integers and lengths, no trailing bytes); exactly the 9 unsigned fields.
- Chain id 11155111; `to` = pinned Sepolia test USDT; value 0 (no ETH sent along); empty access list; data exactly 68 bytes `transfer(address,uint256)` with standard words; amount > 0; recipient ≠ this wallet.
- Gas limit ≤ 120,000; priority fee ≤ max fee; gas limit × max fee ≤ 0.05 test ETH.
- The signer is this wallet's own key `m/44'/60'/0'/0/0` (same address as the watch-only export).
- An Ethereum transaction doesn't expire: a signed one stays valid until its nonce is used. If you cancel after signing, sending a new payment with the same nonce replaces it.

## Tests

- **Byte-exact against an independent library** (eth-account 0.14, Python): same signing hash, same signed transaction bytes and same transaction hash for the same transaction and key.
- Strict decoding: trailing byte, truncated, wrong type, signed form given as unsigned, non-minimal integer, ETH sent along, access list, `approve` instead of `transfer` → refused.
- Tablet rules: mainnet chain id, mainnet USDT, zero amount, to itself, gas limit 500,000, fee over 0.05 ETH, tip over max fee → refused; address matches the published BIP-44 vector.
- Through the tablet bridge: not allowlisted refused → allowlisted review shows the name → wrong last 6 refused → sign → the PC recovers this wallet's address.
- PC: build from mocked nodes (nonce, fees, gas with margin), not enough USDT refused, signature from another key / for another transaction / truncated refused, broadcast accepted by both nodes ("already known" counts).
