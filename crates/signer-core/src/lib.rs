//! Offline signer core (ARCHITECTURE-MOBILE.md, ARCHITECTURE.md §6).
//!
//! Runs only on the offline signer tablet. This crate has **no network code**
//! and no dependency that opens connections.
//!
//! - `entropy`: OS randomness mixed with ≥ 99 dice rolls (§6.1).
//! - `seed`: 24-word BIP-39 seeds, restore, word check, passphrase and
//!   master fingerprint.
//! - `accounts`: public data for each network (BTC zpub, ETH and TRON
//!   addresses) and receive addresses for "verify on signer".
//! - `vault`: one encrypted file per stored wallet (§6.4).
//! - `export`: the watch-only export the tablet shows as a QR code for the PC.
//!
//! Signing is **not** in this crate yet (later in Phase 2, testnets first).

pub mod accounts;
pub mod entropy;
pub mod export;
pub mod seed;
pub mod vault;
