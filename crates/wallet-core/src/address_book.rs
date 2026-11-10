//! Address book of outside recipients (ARCHITECTURE.md §7.1, the online copy).
//!
//! This copy is a convenience and the online policy layer; it is **not**
//! trusted. The authoritative copies are the signer's own allowlist (later,
//! with signing) and your **paper** address book, which you compare against
//! on the signer screen before approving anything.
//!
//! Rules:
//! - Each entry: label, network, address, how it was verified, which of your
//!   tiers may pay it, and when it was added (in **network time**).
//! - A new entry is usable only after a **24-hour waiting period**, counted in
//!   network time (latest block times from several providers), so changing
//!   the PC clock can't shorten it. If network time can't be confirmed, the
//!   waiting period counts as **not** over.
//! - **Edit = remove + add.** Only the label can change in place; a new
//!   address, network or tier permission is a new entry with a new waiting
//!   period.
//! - **Look-alike block:** an address that shares the first 3 characters
//!   (after the fixed prefix) or the last 3 with an existing entry or one of
//!   your own wallets is refused, and both are shown.
//! - Removed addresses stay on a revocation list with the date.
//! - Your own wallets aren't entered here: they come from the wallet list.

use chain_btc::BtcAddress;
use chain_eth::EthAddress;
use chain_tron::TronAddress;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wallet_types::{Network, Tier};

use crate::activity::looks_alike;
use crate::btc_activity::btc_prefix_len;
use crate::registry::{cross_network_hint, looks_like_secret};

/// Waiting period before a new entry can be used.
pub const WAITING_SECS: u64 = 24 * 60 * 60;
pub const MAX_ENTRIES: usize = 200;
pub const MAX_LABEL: usize = 40;
pub const MAX_NOTE: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifiedBy {
    /// Read the address back to the recipient on a phone call.
    PhoneCall,
    /// Confirmed through a second, independent channel.
    SecondChannel,
    /// Sent a small test amount and the recipient confirmed receiving it.
    TestTransaction,
    /// One of your own addresses elsewhere (e.g. an exchange deposit address
    /// you checked in the exchange's app).
    OwnAccountElsewhere,
}

impl VerifiedBy {
    pub fn display_name(self) -> &'static str {
        match self {
            VerifiedBy::PhoneCall => "Phone call with the recipient",
            VerifiedBy::SecondChannel => "Confirmed through a second channel",
            VerifiedBy::TestTransaction => "Small test transaction, confirmed by the recipient",
            VerifiedBy::OwnAccountElsewhere => {
                "My own account elsewhere (checked in its official app)"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookEntry {
    /// Stable id, e.g. "ab-7". Never reused.
    pub id: String,
    pub label: String,
    pub network: Network,
    /// Normalised: BTC as parsed, ETH checksummed, TRON Base58.
    pub address: String,
    pub verified_by: VerifiedBy,
    #[serde(default)]
    pub note: String,
    /// Which of your tiers may pay this address (Spending and/or Savings;
    /// Vault never pays outside addresses).
    pub tiers: Vec<Tier>,
    /// Network time (Unix seconds) when it was added.
    pub added_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revoked {
    pub network: Network,
    pub address: String,
    pub label: String,
    pub removed_at: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressBook {
    pub entries: Vec<BookEntry>,
    #[serde(default)]
    pub revoked: Vec<Revoked>,
    /// Next number for entry ids.
    #[serde(default)]
    pub next_id: u64,
}

/// What the UI sends to add an entry (every field is checked again here).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewBookEntry {
    pub label: String,
    pub network: Network,
    pub address: String,
    pub verified_by: VerifiedBy,
    #[serde(default)]
    pub note: String,
    pub tiers: Vec<Tier>,
    /// The user confirmed they wrote label + full address on paper.
    pub written_on_paper: bool,
}

/// One of your own addresses, for the look-alike and "that's your own
/// wallet" checks.
#[derive(Debug, Clone)]
pub struct OwnAddress {
    pub network: Network,
    pub address: String,
    pub label: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BookError {
    #[error("label must be 1-{MAX_LABEL} characters with no control characters")]
    Label,
    #[error("the note can be at most {MAX_NOTE} characters")]
    Note,
    #[error("{0}")]
    Address(String),
    #[error("this looks like a seed phrase or private key. Never enter one here")]
    Secret,
    #[error("choose which of your tiers may pay this address (Spending and/or Savings). Vault never pays outside addresses")]
    Tiers,
    #[error(
        "confirm that you wrote the label and the full address in your paper address book first"
    )]
    Paper,
    #[error("this is your own wallet \"{0}\". Your own wallets come from the wallet list and don't need an entry here")]
    OwnWallet(String),
    #[error("this address is already in the address book as \"{0}\"")]
    Duplicate(String),
    #[error("refused: this address looks like {what} \"{label}\" ({existing}) but is different. This is how address poisoning works. Check both addresses character by character with the recipient. If it is genuinely a different address, remove the other entry first")]
    LookAlike {
        what: &'static str,
        label: String,
        existing: String,
    },
    #[error("the address book is full (max {MAX_ENTRIES})")]
    Full,
    #[error("no entry with id '{0}'")]
    NotFound(String),
}

fn clean_label(label: &str) -> Result<String, BookError> {
    let l = label.trim();
    if l.is_empty() || l.chars().count() > MAX_LABEL || l.chars().any(char::is_control) {
        return Err(BookError::Label);
    }
    Ok(l.to_owned())
}

/// Parse and normalise an address for `network`, with a helpful message
/// when it belongs to another network.
pub fn normalise(network: Network, raw: &str) -> Result<String, BookError> {
    let v = raw.trim();
    if looks_like_secret(v) {
        return Err(BookError::Secret);
    }
    let hint = || cross_network_hint(v);
    let err = |e: String| BookError::Address(hint().unwrap_or(e));
    match network {
        Network::Bitcoin => {
            if v.starts_with("xpub") || v.starts_with("zpub") || v.starts_with("ypub") {
                return Err(BookError::Address(
                    "enter a single Bitcoin address, not an account key".into(),
                ));
            }
            v.parse::<BtcAddress>()
                .map(|a| a.to_string())
                .map_err(|e| err(e.to_string()))
        }
        Network::Ethereum => v
            .parse::<EthAddress>()
            .map(|a| a.to_checksum())
            .map_err(|e| err(e.to_string())),
        Network::Tron => v
            .parse::<TronAddress>()
            .map(|a| a.to_base58())
            .map_err(|e| err(e.to_string())),
    }
}

fn prefix_len(network: Network, a: &str) -> usize {
    match network {
        Network::Bitcoin => btc_prefix_len(a),
        Network::Ethereum => 2,
        Network::Tron => 1,
    }
}

/// Look-alike comparison for `network` (Ethereum hex is case-insensitive).
pub fn similar(network: Network, a: &str, b: &str) -> bool {
    match network {
        Network::Ethereum => looks_alike(&a.to_lowercase(), &b.to_lowercase(), 2),
        _ => {
            prefix_len(network, a) == prefix_len(network, b)
                && looks_alike(a, b, prefix_len(network, a))
        }
    }
}

impl AddressBook {
    /// Check and add an entry. `now` is network time; `own` are your own
    /// wallet addresses.
    pub fn add(
        &mut self,
        input: &NewBookEntry,
        own: &[OwnAddress],
        now: u64,
    ) -> Result<BookEntry, BookError> {
        if self.entries.len() >= MAX_ENTRIES {
            return Err(BookError::Full);
        }
        let label = clean_label(&input.label)?;
        let note = input.note.trim().to_owned();
        if note.chars().count() > MAX_NOTE || note.chars().any(char::is_control) {
            return Err(BookError::Note);
        }
        let address = normalise(input.network, &input.address)?;
        let mut tiers: Vec<Tier> = input.tiers.clone();
        tiers.sort_by_key(|t| *t as u8);
        tiers.dedup();
        if tiers.is_empty()
            || tiers
                .iter()
                .any(|t| !matches!(t, Tier::Spending | Tier::Savings))
        {
            return Err(BookError::Tiers);
        }
        if !input.written_on_paper {
            return Err(BookError::Paper);
        }
        let net = input.network;
        for o in own.iter().filter(|o| o.network == net) {
            if o.address == address {
                return Err(BookError::OwnWallet(o.label.clone()));
            }
            if similar(net, &o.address, &address) {
                return Err(BookError::LookAlike {
                    what: "your own wallet",
                    label: o.label.clone(),
                    existing: o.address.clone(),
                });
            }
        }
        for e in self.entries.iter().filter(|e| e.network == net) {
            if e.address == address {
                return Err(BookError::Duplicate(e.label.clone()));
            }
            if similar(net, &e.address, &address) {
                return Err(BookError::LookAlike {
                    what: "the address book entry",
                    label: e.label.clone(),
                    existing: e.address.clone(),
                });
            }
        }
        self.next_id += 1;
        let entry = BookEntry {
            id: format!("ab-{}", self.next_id),
            label,
            network: net,
            address,
            verified_by: input.verified_by,
            note,
            tiers,
            added_at: now,
        };
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// Remove an entry; it goes on the revocation list.
    pub fn remove(&mut self, id: &str, now: u64) -> Result<BookEntry, BookError> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or_else(|| BookError::NotFound(id.to_owned()))?;
        let e = self.entries.remove(pos);
        self.revoked.push(Revoked {
            network: e.network,
            address: e.address.clone(),
            label: e.label.clone(),
            removed_at: now,
        });
        Ok(e)
    }

    /// Only the label can change without a new entry.
    pub fn rename(&mut self, id: &str, label: &str) -> Result<(), BookError> {
        let label = clean_label(label)?;
        let e = self
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| BookError::NotFound(id.to_owned()))?;
        e.label = label;
        Ok(())
    }

    /// When an address was removed before, if ever (shown when re-adding).
    pub fn was_revoked(&self, network: Network, address: &str) -> Option<&Revoked> {
        self.revoked
            .iter()
            .rev()
            .find(|r| r.network == network && r.address == address)
    }
}

/// Whether an entry can be used yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Usable {
    Yes,
    /// Waiting period not over; usable from this network time.
    Waiting {
        from: u64,
    },
    /// Network time couldn't be confirmed, so the waiting period is treated
    /// as not over.
    Unknown {
        from: u64,
    },
}

pub fn usable(entry: &BookEntry, network_now: Option<u64>) -> Usable {
    usable_after(entry, network_now, WAITING_SECS)
}

/// As `usable`, with the owner's chosen waiting period (seconds).
pub fn usable_after(entry: &BookEntry, network_now: Option<u64>, wait_secs: u64) -> Usable {
    let from = entry.added_at.saturating_add(wait_secs);
    match network_now {
        None => Usable::Unknown { from },
        Some(now) if now >= from => Usable::Yes,
        Some(_) => Usable::Waiting { from },
    }
}

/// Network time from several providers' latest block times: needs at least
/// two that agree within 5 minutes; returns the earliest of them (so a
/// waiting period never ends early). `None` if that can't be established.
pub fn network_time(block_times: &[(String, u64)]) -> Option<u64> {
    const AGREE_SECS: u64 = 300;
    let mut t: Vec<u64> = block_times.iter().map(|(_, s)| *s).collect();
    t.sort_unstable();
    // Best pair: two times within AGREE_SECS; take the earliest such group.
    t.windows(2)
        .find(|w| w[1] - w[0] <= AGREE_SECS)
        .map(|w| w[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    const ETH_A: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
    const ETH_MINE: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
    const TRON_A: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
    const BTC_A: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

    fn input(network: Network, address: &str, label: &str) -> NewBookEntry {
        NewBookEntry {
            label: label.into(),
            network,
            address: address.into(),
            verified_by: VerifiedBy::PhoneCall,
            note: String::new(),
            tiers: vec![Tier::Spending],
            written_on_paper: true,
        }
    }

    fn own() -> Vec<OwnAddress> {
        vec![OwnAddress {
            network: Network::Ethereum,
            address: ETH_MINE.into(),
            label: "Savings".into(),
        }]
    }

    #[test]
    fn adds_normalises_and_waits() {
        let mut b = AddressBook::default();
        let e = b
            .add(
                &input(Network::Tron, &format!("  {TRON_A} "), " Supplier "),
                &own(),
                1_000,
            )
            .expect("add");
        assert_eq!(
            (e.id.as_str(), e.label.as_str(), e.address.as_str()),
            ("ab-1", "Supplier", TRON_A)
        );
        assert_eq!(
            usable(&e, Some(1_000)),
            Usable::Waiting {
                from: 1_000 + WAITING_SECS
            }
        );
        assert_eq!(usable(&e, Some(1_000 + WAITING_SECS)), Usable::Yes);
        assert_eq!(
            usable(&e, None),
            Usable::Unknown {
                from: 1_000 + WAITING_SECS
            }
        );
        b.add(&input(Network::Bitcoin, BTC_A, "Friend BTC"), &own(), 1_000)
            .expect("btc");
        assert_eq!(b.entries[1].id, "ab-2");
    }

    #[test]
    fn refuses_bad_input() {
        let mut b = AddressBook::default();
        let mut i = input(Network::Ethereum, &ETH_A.to_lowercase(), "x");
        assert!(
            matches!(b.add(&i, &own(), 0), Err(BookError::Address(_))),
            "no checksum"
        );
        i.address = TRON_A.into();
        assert!(
            matches!(b.add(&i, &own(), 0), Err(BookError::Address(m)) if m.contains("TRON")),
            "wrong network explained"
        );
        i.address = ETH_A.into();
        i.tiers = vec![Tier::Vault];
        assert_eq!(b.add(&i, &own(), 0).err(), Some(BookError::Tiers));
        i.tiers = vec![];
        assert_eq!(b.add(&i, &own(), 0).err(), Some(BookError::Tiers));
        i.tiers = vec![Tier::Savings, Tier::Spending, Tier::Savings];
        i.written_on_paper = false;
        assert_eq!(b.add(&i, &own(), 0).err(), Some(BookError::Paper));
        i.written_on_paper = true;
        i.label = "a\u{7}".into();
        assert_eq!(b.add(&i, &own(), 0).err(), Some(BookError::Label));
        i.label = "ok".into();
        let e = b.add(&i, &own(), 0).expect("add");
        assert_eq!(e.tiers, vec![Tier::Savings, Tier::Spending], "deduplicated");
        assert!(matches!(b.add(&i, &own(), 0), Err(BookError::Duplicate(_))));
        let seed = input(Network::Ethereum, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "s");
        assert_eq!(b.add(&seed, &own(), 0).err(), Some(BookError::Secret));
        let mine = input(Network::Ethereum, ETH_MINE, "me");
        assert!(matches!(b.add(&mine, &own(), 0), Err(BookError::OwnWallet(l)) if l == "Savings"));
    }

    #[test]
    fn blocks_lookalikes_of_entries_and_own_wallets() {
        let mut b = AddressBook::default();
        b.add(&input(Network::Ethereum, ETH_A, "Supplier"), &own(), 0)
            .expect("add");
        // A checksummed address with the same "5aA" start and "eAed" end.
        let mut bytes = *ETH_A.parse::<EthAddress>().expect("a").as_bytes();
        bytes[8] ^= 0x55;
        let fake = EthAddress::parse_any_case(&format!("0x{}", hex::encode(bytes)))
            .expect("fake")
            .to_checksum();
        let r = b.add(&input(Network::Ethereum, &fake, "Supplier 2"), &own(), 0);
        assert!(matches!(r, Err(BookError::LookAlike { label, .. }) if label == "Supplier"));
        // Look-alike of your own wallet.
        let mut bytes = *ETH_MINE.parse::<EthAddress>().expect("a").as_bytes();
        bytes[9] ^= 0x11;
        let fake_mine = EthAddress::parse_any_case(&format!("0x{}", hex::encode(bytes)))
            .expect("fake")
            .to_checksum();
        let r = b.add(&input(Network::Ethereum, &fake_mine, "x"), &own(), 0);
        assert!(matches!(
            r,
            Err(BookError::LookAlike {
                what: "your own wallet",
                ..
            })
        ));
    }

    #[test]
    fn remove_keeps_a_revocation_record_and_rename_only_changes_the_label() {
        let mut b = AddressBook::default();
        let e = b
            .add(&input(Network::Tron, TRON_A, "Supplier"), &own(), 5)
            .expect("add");
        b.rename(&e.id, "Supplier (old)").expect("rename");
        assert_eq!(b.entries[0].label, "Supplier (old)");
        assert_eq!(b.entries[0].address, TRON_A);
        b.remove(&e.id, 99).expect("remove");
        assert!(b.entries.is_empty());
        assert_eq!(
            b.was_revoked(Network::Tron, TRON_A).map(|r| r.removed_at),
            Some(99)
        );
        // Re-adding gives a new id and a new waiting period.
        let again = b
            .add(&input(Network::Tron, TRON_A, "Supplier"), &own(), 200)
            .expect("re-add");
        assert_eq!((again.id.as_str(), again.added_at), ("ab-2", 200));
        assert!(matches!(b.remove("ab-9", 0), Err(BookError::NotFound(_))));
    }

    #[test]
    fn network_time_needs_two_agreeing_sources() {
        let t =
            |v: &[u64]| network_time(&v.iter().map(|s| ("p".to_owned(), *s)).collect::<Vec<_>>());
        assert_eq!(t(&[1_000]), None, "one source isn't enough");
        assert_eq!(t(&[1_000, 9_000]), None, "they disagree");
        assert_eq!(
            t(&[1_020, 1_000, 9_000]),
            Some(1_000),
            "earliest agreeing time"
        );
        assert_eq!(t(&[]), None);
    }
}
