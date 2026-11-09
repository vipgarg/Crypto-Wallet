//! The tablet's own signing policy (ARCHITECTURE.md P7): an allowlist of
//! recipients, daily limits, and a hash-chained log of everything signed.
//!
//! The PC's address book protects against a compromised *PC display*; this
//! protects against a compromised *PC*: even a fully controlled PC can only
//! get the tablet to sign payments to addresses the owner added **on the
//! tablet**, after a waiting period, and only up to a daily limit.
//!
//! - One policy per wallet, saved next to its vault. It is sealed with a MAC
//!   whose key comes from the wallet's seed, so it can be read and changed
//!   only after unlocking, and a file edited outside the app is refused.
//! - New addresses become usable only after the waiting period (10 minutes
//!   on test networks, 24 hours on real ones), by the tablet's clock.
//!   Removing an address is immediate.
//! - Lowering a limit is immediate; raising one waits the same period.
//! - Every signature is logged (sequence number, time, asset, recipient,
//!   amount, transaction ID), each entry hashing the one before. The
//!   sequence number and the log's head go back to the PC in the signature
//!   QR, so the PC notices if the tablet signed anything it didn't see.
//!   Signed-but-never-sent payments still count towards the limit.
//! - Deleting the file gives an empty allowlist: nothing can be signed until
//!   newly added addresses have waited.

use bitcoin::bip32::Xpriv;
use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use chain_eth::EthAddress;
use chain_tron::TronAddress;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

/// Waiting period on test networks.
pub const TEST_WAIT_MS: u64 = 10 * 60 * 1000;
/// Waiting period on real networks.
pub const REAL_WAIT_MS: u64 = 24 * 60 * 60 * 1000;
/// The limit window (rolling).
pub const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// How far the tablet clock may be behind the newest log entry.
pub const CLOCK_BACK_TOLERANCE_MS: u64 = 10 * 60 * 1000;
pub const MAX_ADDRESSES: usize = 200;
pub const MAX_LABEL: usize = 40;
const FORMAT: u32 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("refused: {0}")]
    Refused(String),
    #[error("{0}")]
    Invalid(String),
    #[error("this wallet's signing policy file was changed outside the app (or belongs to another wallet). Nothing can be signed with it")]
    Tampered,
}

fn refuse<T>(why: impl Into<String>) -> Result<T, PolicyError> {
    Err(PolicyError::Refused(why.into()))
}
fn invalid<T>(why: impl Into<String>) -> Result<T, PolicyError> {
    Err(PolicyError::Invalid(why.into()))
}

/// A network an address belongs to. Test and real networks are separate,
/// so a test allowlist never carries over to real money.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Net {
    TronNile,
    EthSepolia,
    BtcSignet,
    /// Real networks (real-networks builds only).
    Tron,
    Eth,
}

impl Net {
    pub const ALL: [Net; 5] = [
        Net::TronNile,
        Net::EthSepolia,
        Net::BtcSignet,
        Net::Tron,
        Net::Eth,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Net::TronNile => "tron-nile",
            Net::EthSepolia => "eth-sepolia",
            Net::BtcSignet => "btc-signet",
            Net::Tron => "tron",
            Net::Eth => "eth",
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Net::TronNile => "TRON Nile (test)",
            Net::EthSepolia => "Ethereum Sepolia (test)",
            Net::BtcSignet => "Bitcoin signet (test)",
            Net::Tron => "TRON (REAL MONEY)",
            Net::Eth => "Ethereum (REAL MONEY)",
        }
    }
    pub fn parse(code: &str) -> Result<Self, PolicyError> {
        Net::ALL
            .into_iter()
            .find(|n| n.code() == code)
            .map_or_else(|| invalid(format!("unknown network {code:?}")), Ok)
    }
    pub fn is_test(self) -> bool {
        matches!(self, Net::TronNile | Net::EthSepolia | Net::BtcSignet)
    }
    pub fn wait_ms(self) -> u64 {
        if self.is_test() {
            TEST_WAIT_MS
        } else {
            REAL_WAIT_MS
        }
    }
    /// Check an address and return its canonical spelling.
    pub fn canonical(self, address: &str) -> Result<String, PolicyError> {
        let a = address.trim();
        match self {
            Net::TronNile | Net::Tron => a
                .parse::<TronAddress>()
                .map(|t| t.to_base58())
                .map_err(|_| PolicyError::Invalid("that isn't a valid TRON address".into())),
            Net::EthSepolia | Net::Eth => a
                .parse::<EthAddress>()
                .map(|e| e.to_checksum())
                .map_err(|_| {
                    PolicyError::Invalid(
                        "that isn't a valid Ethereum address (0x + 40 hex characters, typed with its capitals exactly as shown)".into(),
                    )
                }),
            Net::BtcSignet => a
                .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
                .ok()
                .and_then(|x| x.require_network(bitcoin::Network::Signet).ok())
                .map(|x| x.to_string())
                .ok_or_else(|| {
                    PolicyError::Invalid("that isn't a valid Bitcoin test (tb1…) address".into())
                }),
        }
    }
}

/// What is being sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Asset {
    UsdtTronNile,
    TrxNile,
    UsdtEthSepolia,
    BtcSignet,
    /// Real networks (real-networks builds only).
    UsdtTron,
    Trx,
    UsdtEth,
}

impl Asset {
    pub const ALL: [Asset; 7] = [
        Asset::UsdtTronNile,
        Asset::TrxNile,
        Asset::UsdtEthSepolia,
        Asset::BtcSignet,
        Asset::UsdtTron,
        Asset::Trx,
        Asset::UsdtEth,
    ];
    pub fn code(self) -> &'static str {
        match self {
            Asset::UsdtTronNile => "usdt-tron-nile",
            Asset::TrxNile => "trx-nile",
            Asset::UsdtEthSepolia => "usdt-eth-sepolia",
            Asset::BtcSignet => "btc-signet",
            Asset::UsdtTron => "usdt-tron",
            Asset::Trx => "trx",
            Asset::UsdtEth => "usdt-eth",
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Asset::UsdtTronNile => "Test USDT on TRON Nile",
            Asset::TrxNile => "Test TRX on TRON Nile",
            Asset::UsdtEthSepolia => "Test USDT on Ethereum Sepolia",
            Asset::BtcSignet => "Test bitcoin (signet)",
            Asset::UsdtTron => "USDT on TRON (REAL)",
            Asset::Trx => "TRX (REAL)",
            Asset::UsdtEth => "USDT on Ethereum (REAL)",
        }
    }
    pub fn unit(self) -> &'static str {
        match self {
            Asset::UsdtTronNile | Asset::UsdtEthSepolia | Asset::UsdtTron | Asset::UsdtEth => {
                "USDT"
            }
            Asset::TrxNile | Asset::Trx => "TRX",
            Asset::BtcSignet => "BTC",
        }
    }
    pub fn parse(code: &str) -> Result<Self, PolicyError> {
        Asset::ALL
            .into_iter()
            .find(|a| a.code() == code)
            .map_or_else(|| invalid(format!("unknown asset {code:?}")), Ok)
    }
    pub fn net(self) -> Net {
        match self {
            Asset::UsdtTronNile | Asset::TrxNile => Net::TronNile,
            Asset::UsdtEthSepolia => Net::EthSepolia,
            Asset::BtcSignet => Net::BtcSignet,
            Asset::UsdtTron | Asset::Trx => Net::Tron,
            Asset::UsdtEth => Net::Eth,
        }
    }
    pub fn decimals(self) -> u32 {
        match self {
            Asset::BtcSignet => 8,
            _ => 6,
        }
    }
    /// The limit a new policy starts with, in base units.
    pub fn default_daily(self) -> u128 {
        match self {
            // 1000 test USDT / TRX; 0.01 test BTC.
            Asset::UsdtTronNile | Asset::TrxNile | Asset::UsdtEthSepolia => 1_000_000_000,
            Asset::BtcSignet => 1_000_000,
            // Real money starts small: 50 USDT / 50 TRX a day. Raising waits 24 h.
            Asset::UsdtTron | Asset::Trx | Asset::UsdtEth => 50_000_000,
        }
    }
    /// Base units as decimal text ("12.5").
    pub fn format(self, v: u128) -> String {
        let d = 10u128.pow(self.decimals());
        let (whole, frac) = (v / d, v % d);
        if frac == 0 {
            whole.to_string()
        } else {
            let f = format!("{frac:0w$}", w = self.decimals() as usize);
            format!("{whole}.{}", f.trim_end_matches('0'))
        }
    }
    /// Decimal text to base units (plain digits and one optional point).
    pub fn parse_amount(self, s: &str) -> Result<u128, PolicyError> {
        let s = s.trim();
        let bad = || PolicyError::Invalid(format!("{s:?} isn't an amount"));
        let (w, f) = s.split_once('.').unwrap_or((s, ""));
        let digits = |x: &str| x.chars().all(|c| c.is_ascii_digit());
        if w.is_empty() || !digits(w) || !digits(f) || w.len() > 15 {
            return Err(bad());
        }
        if f.len() > self.decimals() as usize {
            return invalid(format!(
                "at most {} decimal places for {}",
                self.decimals(),
                self.unit()
            ));
        }
        let scale = 10u128.pow(self.decimals());
        let whole: u128 = w.parse().map_err(|_| bad())?;
        let frac: u128 = if f.is_empty() {
            0
        } else {
            let pad = format!("{f:0<w$}", w = self.decimals() as usize);
            pad.parse().map_err(|_| bad())?
        };
        Ok(whole * scale + frac)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedAddress {
    pub net: Net,
    pub address: String,
    pub label: String,
    pub added_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limit {
    /// Base units per rolling 24 hours, as decimal text.
    pub daily: String,
    /// A raise waiting to take effect: (new daily limit, from when).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<(String, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogEntry {
    pub seq: u64,
    pub time_ms: u64,
    pub asset: Asset,
    pub recipient: String,
    /// Base units, decimal text.
    pub amount: String,
    pub txid: String,
    /// Hex hash of the previous entry (zeros for the first).
    pub prev: String,
    /// Hex hash of this entry.
    pub hash: String,
}

#[derive(Serialize)]
struct LogBody<'a> {
    seq: u64,
    time_ms: u64,
    asset: Asset,
    recipient: &'a str,
    amount: &'a str,
    txid: &'a str,
    prev: &'a str,
}

fn entry_hash(e: &LogEntry) -> String {
    let body = LogBody {
        seq: e.seq,
        time_ms: e.time_ms,
        asset: e.asset,
        recipient: &e.recipient,
        amount: &e.amount,
        txid: &e.txid,
        prev: &e.prev,
    };
    let json = serde_json::to_vec(&body).unwrap_or_default();
    hex::encode(Sha256::digest(&json))
}

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A payment the tablet is about to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    pub asset: Asset,
    pub recipient: String,
    /// Base units.
    pub amount: u128,
}

/// What goes back to the PC with the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    pub seq: u64,
    pub head: [u8; 32],
}

impl Receipt {
    pub const LEN: usize = 40;
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..8].copy_from_slice(&self.seq.to_be_bytes());
        out[8..].copy_from_slice(&self.head);
        out
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != Self::LEN {
            return None;
        }
        Some(Self {
            seq: u64::from_be_bytes(b[..8].try_into().ok()?),
            head: b[8..].try_into().ok()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub format: u32,
    pub wallet_id: String,
    pub created_ms: u64,
    pub allow: Vec<AllowedAddress>,
    pub limits: BTreeMap<Asset, Limit>,
    pub log: Vec<LogEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    policy: Policy,
    mac: String,
}

/// The key that seals a wallet's policy (never leaves the tablet).
pub fn mac_key(master: &Xpriv) -> [u8; 32] {
    let mut e = HmacEngine::<sha256::Hash>::new(&master.private_key.secret_bytes());
    e.input(b"wallet-signer policy mac v1");
    e.input(master.chain_code.as_bytes());
    Hmac::<sha256::Hash>::from_engine(e).to_byte_array()
}

fn mac(key: &[u8; 32], body: &[u8]) -> String {
    let mut e = HmacEngine::<sha256::Hash>::new(key);
    e.input(body);
    hex::encode(Hmac::<sha256::Hash>::from_engine(e).to_byte_array())
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |x, (p, q)| x | (p ^ q)) == 0
}

/// One address as the tablet shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressView {
    pub net: String,
    pub net_name: String,
    pub address: String,
    pub label: String,
    /// 0 when usable; otherwise when it becomes usable (tablet clock).
    pub usable_from_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LimitView {
    pub asset: String,
    pub name: String,
    pub unit: String,
    pub daily: String,
    pub used_24h: String,
    pub pending: Option<String>,
    pub pending_from_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogView {
    pub seq: u64,
    pub time_ms: u64,
    pub asset: String,
    pub recipient: String,
    pub amount: String,
    pub unit: String,
    pub txid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyView {
    pub addresses: Vec<AddressView>,
    pub limits: Vec<LimitView>,
    /// Newest first, at most 50.
    pub recent: Vec<LogView>,
    pub signed_total: u64,
    /// Hex head of the log ("" when empty).
    pub head: String,
}

impl Policy {
    pub fn new(wallet_id: &str, now_ms: u64) -> Self {
        Self {
            format: FORMAT,
            wallet_id: wallet_id.to_owned(),
            created_ms: now_ms,
            allow: Vec::new(),
            limits: Asset::ALL
                .into_iter()
                .map(|a| {
                    (
                        a,
                        Limit {
                            daily: a.default_daily().to_string(),
                            pending: None,
                        },
                    )
                })
                .collect(),
            log: Vec::new(),
        }
    }

    /// Open a saved policy; `None` (no file yet) gives a new, empty one.
    pub fn open(
        bytes: Option<&[u8]>,
        key: &[u8; 32],
        wallet_id: &str,
        now_ms: u64,
    ) -> Result<Self, PolicyError> {
        let Some(bytes) = bytes else {
            return Ok(Self::new(wallet_id, now_ms));
        };
        let s: Sealed = serde_json::from_slice(bytes).map_err(|_| PolicyError::Tampered)?;
        let body = serde_json::to_vec(&s.policy).map_err(|_| PolicyError::Tampered)?;
        if !ct_eq(&mac(key, &body), &s.mac)
            || s.policy.wallet_id != wallet_id
            || s.policy.format != FORMAT
        {
            return Err(PolicyError::Tampered);
        }
        s.policy.verify_log()?;
        Ok(s.policy)
    }

    pub fn seal(&self, key: &[u8; 32]) -> Vec<u8> {
        let body = serde_json::to_vec(self).unwrap_or_default();
        let sealed = Sealed {
            policy: self.clone(),
            mac: mac(key, &body),
        };
        serde_json::to_vec(&sealed).unwrap_or_default()
    }

    fn verify_log(&self) -> Result<(), PolicyError> {
        let mut prev = ZERO_HASH.to_owned();
        for (i, e) in self.log.iter().enumerate() {
            if e.seq != i as u64 + 1 || e.prev != prev || entry_hash(e) != e.hash {
                return Err(PolicyError::Tampered);
            }
            prev.clone_from(&e.hash);
        }
        Ok(())
    }

    pub fn head(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        if let Some(e) = self.log.last() {
            let _ = hex::decode_to_slice(&e.hash, &mut out);
        }
        out
    }

    pub fn add_address(
        &mut self,
        net: Net,
        address: &str,
        label: &str,
        now_ms: u64,
    ) -> Result<(), PolicyError> {
        let address = net.canonical(address)?;
        let label = label.trim();
        if label.is_empty()
            || label.chars().count() > MAX_LABEL
            || label.chars().any(char::is_control)
        {
            return invalid(format!("give it a name (1 to {MAX_LABEL} characters)"));
        }
        if self
            .allow
            .iter()
            .any(|a| a.net == net && a.address == address)
        {
            return invalid("that address is already on the allowlist");
        }
        if self.allow.len() >= MAX_ADDRESSES {
            return invalid("the allowlist is full; remove an address first");
        }
        self.allow.push(AllowedAddress {
            net,
            address,
            label: label.to_owned(),
            added_ms: now_ms,
        });
        Ok(())
    }

    pub fn remove_address(&mut self, net: Net, address: &str) -> Result<(), PolicyError> {
        let before = self.allow.len();
        let a = address.trim();
        self.allow.retain(|x| !(x.net == net && x.address == a));
        if self.allow.len() == before {
            return invalid("that address isn't on the allowlist");
        }
        Ok(())
    }

    /// Lowering takes effect now (and cancels a pending raise); raising
    /// takes effect after the waiting period.
    pub fn set_limit(&mut self, asset: Asset, daily: u128, now_ms: u64) -> Result<(), PolicyError> {
        self.settle(now_ms);
        let l = self.limits.entry(asset).or_insert_with(|| Limit {
            daily: asset.default_daily().to_string(),
            pending: None,
        });
        let current: u128 = l.daily.parse().unwrap_or(0);
        if daily <= current {
            l.daily = daily.to_string();
            l.pending = None;
        } else {
            l.pending = Some((daily.to_string(), now_ms + asset.net().wait_ms()));
        }
        Ok(())
    }

    /// Apply raises whose waiting period is over.
    fn settle(&mut self, now_ms: u64) {
        for l in self.limits.values_mut() {
            if let Some((v, from)) = &l.pending {
                if now_ms >= *from {
                    l.daily.clone_from(v);
                    l.pending = None;
                }
            }
        }
    }

    fn daily(&self, asset: Asset, now_ms: u64) -> u128 {
        self.limits.get(&asset).map_or(0, |l| match &l.pending {
            Some((v, from)) if now_ms >= *from => v.parse().unwrap_or(0),
            _ => l.daily.parse().unwrap_or(0),
        })
    }

    /// Signed in the last 24 hours (entries dated later than now count too).
    pub fn used_24h(&self, asset: Asset, now_ms: u64) -> u128 {
        let since = now_ms.saturating_sub(DAY_MS);
        self.log
            .iter()
            .filter(|e| e.asset == asset && e.time_ms > since)
            .map(|e| e.amount.parse::<u128>().unwrap_or(u128::MAX))
            .fold(0u128, u128::saturating_add)
    }

    /// May this payment be signed now?
    pub fn check(&self, p: &Payment, now_ms: u64) -> Result<(), PolicyError> {
        let net = p.asset.net();
        if let Some(last) = self.log.last() {
            if now_ms + CLOCK_BACK_TOLERANCE_MS < last.time_ms {
                return refuse("this tablet's clock is earlier than its last signature; check the tablet's date and time");
            }
        }
        let recipient = net.canonical(&p.recipient)?;
        let Some(entry) = self
            .allow
            .iter()
            .find(|a| a.net == net && a.address == recipient)
        else {
            return refuse(format!(
                "the recipient isn't on this tablet's allowlist for {}. Add it on the tablet (Allowlist), check it against your paper address book, then wait {} minutes",
                net.name(),
                net.wait_ms() / 60_000
            ));
        };
        let from = entry.added_ms + net.wait_ms();
        if now_ms < from {
            let mins = (from - now_ms).div_ceil(60_000);
            return refuse(format!(
                "\"{}\" was added to the allowlist recently; it can be used in {mins} minute(s)",
                entry.label
            ));
        }
        let limit = self.daily(p.asset, now_ms);
        let used = self.used_24h(p.asset, now_ms);
        if used.saturating_add(p.amount) > limit {
            return refuse(format!(
                "over the daily limit for {}: limit {} {u}, already signed {} {u} in the last 24 hours, this payment {} {u}",
                p.asset.name(),
                p.asset.format(limit),
                p.asset.format(used),
                p.asset.format(p.amount),
                u = p.asset.unit()
            ));
        }
        Ok(())
    }

    /// The label of the allowlisted recipient (for the review screen).
    pub fn label_of(&self, net: Net, recipient: &str) -> Option<String> {
        let r = net.canonical(recipient).ok()?;
        self.allow
            .iter()
            .find(|a| a.net == net && a.address == r)
            .map(|a| a.label.clone())
    }

    /// Check, then log the signature. Call before the signature is shown.
    pub fn record(&mut self, p: &Payment, txid: &str, now_ms: u64) -> Result<Receipt, PolicyError> {
        self.check(p, now_ms)?;
        self.settle(now_ms);
        let prev = self
            .log
            .last()
            .map_or_else(|| ZERO_HASH.to_owned(), |e| e.hash.clone());
        let mut e = LogEntry {
            seq: self.log.len() as u64 + 1,
            time_ms: now_ms,
            asset: p.asset,
            recipient: p.asset.net().canonical(&p.recipient)?,
            amount: p.amount.to_string(),
            txid: txid.to_owned(),
            prev,
            hash: String::new(),
        };
        e.hash = entry_hash(&e);
        let seq = e.seq;
        self.log.push(e);
        Ok(Receipt {
            seq,
            head: self.head(),
        })
    }

    pub fn view(&self, now_ms: u64) -> PolicyView {
        PolicyView {
            addresses: self
                .allow
                .iter()
                .map(|a| {
                    let from = a.added_ms + a.net.wait_ms();
                    AddressView {
                        net: a.net.code().into(),
                        net_name: a.net.name().into(),
                        address: a.address.clone(),
                        label: a.label.clone(),
                        usable_from_ms: if now_ms >= from { 0 } else { from },
                    }
                })
                .collect(),
            limits: Asset::ALL
                .into_iter()
                .map(|a| {
                    let pending = self
                        .limits
                        .get(&a)
                        .and_then(|l| l.pending.clone())
                        .filter(|(_, from)| now_ms < *from);
                    LimitView {
                        asset: a.code().into(),
                        name: a.name().into(),
                        unit: a.unit().into(),
                        daily: a.format(self.daily(a, now_ms)),
                        used_24h: a.format(self.used_24h(a, now_ms)),
                        pending: pending
                            .as_ref()
                            .map(|(v, _)| a.format(v.parse().unwrap_or(0))),
                        pending_from_ms: pending.map_or(0, |(_, f)| f),
                    }
                })
                .collect(),
            recent: self
                .log
                .iter()
                .rev()
                .take(50)
                .map(|e| LogView {
                    seq: e.seq,
                    time_ms: e.time_ms,
                    asset: e.asset.name().into(),
                    recipient: e.recipient.clone(),
                    amount: e.asset.format(e.amount.parse().unwrap_or(0)),
                    unit: e.asset.unit().into(),
                    txid: e.txid.clone(),
                })
                .collect(),
            signed_total: self.log.len() as u64,
            head: self.log.last().map(|e| e.hash.clone()).unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::NetworkKind;

    const T0: u64 = 1_800_000_000_000;
    const MIN: u64 = 60_000;
    const BOB: &str = "TXJ7MoQLNCGstqko8jQHEjXwAhhwYLh5aC";

    fn key() -> [u8; 32] {
        mac_key(&Xpriv::new_master(NetworkKind::Main, &[9u8; 64]).expect("m"))
    }

    fn usdt(amount: u128) -> Payment {
        Payment {
            asset: Asset::UsdtTronNile,
            recipient: BOB.into(),
            amount,
        }
    }

    fn with_bob() -> Policy {
        let mut p = Policy::new("w1", T0);
        p.add_address(Net::TronNile, BOB, "Bob", T0).expect("add");
        p
    }

    #[test]
    fn unknown_or_new_addresses_are_refused_until_the_wait_is_over() {
        let p = Policy::new("w1", T0);
        let e = p.check(&usdt(1), T0).expect_err("empty");
        assert!(e.to_string().contains("allowlist"), "{e}");
        let p = with_bob();
        let e = p.check(&usdt(1), T0 + 5 * MIN).expect_err("waiting");
        assert!(e.to_string().contains("5 minute"), "{e}");
        p.check(&usdt(1), T0 + 10 * MIN).expect("ready");
        // Same address on another network doesn't count.
        let other = Payment {
            asset: Asset::UsdtEthSepolia,
            recipient: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94".into(),
            amount: 1,
        };
        assert!(p.check(&other, T0 + 20 * MIN).is_err());
    }

    #[test]
    fn daily_limit_is_a_rolling_24_hours() {
        let mut p = with_bob();
        let t = T0 + 10 * MIN;
        p.set_limit(Asset::UsdtTronNile, 100_000_000, t)
            .expect("lower");
        p.record(&usdt(60_000_000), "aa", t).expect("first");
        let e = p.check(&usdt(50_000_000), t + MIN).expect_err("over");
        assert!(
            e.to_string()
                .contains("limit 100 USDT, already signed 60 USDT"),
            "{e}"
        );
        p.check(&usdt(40_000_000), t + MIN).expect("fits");
        p.check(&usdt(50_000_000), t + DAY_MS).expect("a day later");
        // Other assets have their own limit.
        assert_eq!(p.used_24h(Asset::TrxNile, t), 0);
    }

    #[test]
    fn raising_a_limit_waits_lowering_does_not() {
        let mut p = with_bob();
        let t = T0 + 10 * MIN;
        p.set_limit(Asset::UsdtTronNile, 2_000_000_000, t)
            .expect("raise");
        assert!(p.check(&usdt(1_500_000_000), t).is_err());
        p.check(&usdt(1_500_000_000), t + 10 * MIN)
            .expect("after wait");
        let v = p.view(t);
        assert_eq!(v.limits[0].daily, "1000");
        assert_eq!(v.limits[0].pending.as_deref(), Some("2000"));
        p.set_limit(Asset::UsdtTronNile, 5_000_000, t)
            .expect("lower");
        assert!(p.check(&usdt(6_000_000), t + 20 * MIN).is_err());
    }

    #[test]
    fn log_is_hash_chained_and_sealed() {
        let k = key();
        let mut p = with_bob();
        let t = T0 + 10 * MIN;
        let r1 = p.record(&usdt(1), "aa", t).expect("1");
        let r2 = p.record(&usdt(2), "bb", t + 1).expect("2");
        assert_eq!((r1.seq, r2.seq), (1, 2));
        assert_ne!(r1.head, r2.head);
        assert_eq!(Receipt::from_bytes(&r2.to_bytes()), Some(r2));
        let bytes = p.seal(&k);
        assert_eq!(Policy::open(Some(&bytes), &k, "w1", t).expect("open"), p);
        // Wrong wallet, wrong key, or any edit: refused.
        assert_eq!(
            Policy::open(Some(&bytes), &k, "w2", t),
            Err(PolicyError::Tampered)
        );
        assert_eq!(
            Policy::open(Some(&bytes), &[0; 32], "w1", t),
            Err(PolicyError::Tampered)
        );
        let edited = String::from_utf8(bytes.clone())
            .expect("utf8")
            .replace("\"amount\":\"2\"", "\"amount\":\"0\"");
        assert_eq!(
            Policy::open(Some(edited.as_bytes()), &k, "w1", t),
            Err(PolicyError::Tampered)
        );
        // A re-sealed but broken chain is refused too.
        let mut q = p.clone();
        q.log[0].amount = "0".into();
        assert_eq!(
            Policy::open(Some(&q.seal(&k)), &k, "w1", t),
            Err(PolicyError::Tampered)
        );
        // No file: a new, empty policy.
        assert!(Policy::open(None, &k, "w1", t)
            .expect("new")
            .allow
            .is_empty());
    }

    #[test]
    fn clock_moved_back_is_refused() {
        let mut p = with_bob();
        let t = T0 + 60 * MIN;
        p.record(&usdt(1), "aa", t).expect("1");
        assert!(p.check(&usdt(1), t - 30 * MIN).is_err());
    }

    #[test]
    fn addresses_are_checked_and_canonical() {
        let mut p = Policy::new("w1", T0);
        assert!(p.add_address(Net::TronNile, "Txj7", "x", T0).is_err());
        assert!(p.add_address(Net::TronNile, BOB, " ", T0).is_err());
        // Ethereum: typed addresses need their checksum capitals.
        assert!(p
            .add_address(
                Net::EthSepolia,
                "0x9858effd232b4033e47d90003d41ec34ecaeda94",
                "Eve",
                T0
            )
            .is_err());
        p.add_address(
            Net::EthSepolia,
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            "Eve",
            T0,
        )
        .expect("eth");
        assert_eq!(
            p.allow[0].address,
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
        assert!(p
            .add_address(
                Net::EthSepolia,
                "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
                "dup",
                T0
            )
            .is_err());
        assert!(p
            .add_address(
                Net::BtcSignet,
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                "main",
                T0
            )
            .is_err());
        p.add_address(
            Net::BtcSignet,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            "t",
            T0,
        )
        .expect("signet");
        p.remove_address(
            Net::EthSepolia,
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        )
        .expect("remove");
        assert_eq!(p.allow.len(), 1);
    }

    #[test]
    fn amounts_round_trip() {
        let a = Asset::UsdtTronNile;
        assert_eq!(a.parse_amount("12.5"), Ok(12_500_000));
        assert_eq!(a.format(12_500_000), "12.5");
        assert!(a.parse_amount("1.0000001").is_err());
        assert!(a.parse_amount("-1").is_err());
        assert!(a.parse_amount("").is_err());
        assert_eq!(Asset::BtcSignet.parse_amount("0.01"), Ok(1_000_000));
    }
}
