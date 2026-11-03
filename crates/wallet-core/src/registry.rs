//! The list of watched wallets. Holds **public data only**: account xpubs and
//! addresses. Private keys and seeds are rejected at input.

use std::fs;
use std::io::Write;
use std::path::Path;

use chain_btc::{AccountXpub, BtcAddress, BtcError};
use chain_eth::EthAddress;
use chain_tron::TronAddress;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wallet_types::{Tier, WalletId};

pub const REGISTRY_VERSION: u32 = 1;
pub const MAX_WALLETS: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum BtcWatch {
    /// BIP-84 account key (m/84'/0'/account'): all receive and change addresses.
    AccountXpub(AccountXpubSer),
    /// A single address (e.g. an exchange deposit address).
    Address(BtcAddress),
}

/// Wrapper so `AccountXpub` can live in the enum with `PartialEq`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountXpubSer(pub AccountXpub);

impl PartialEq for AccountXpubSer {
    fn eq(&self, other: &Self) -> bool {
        self.0.xpub() == other.0.xpub()
    }
}
impl Eq for AccountXpubSer {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchWallet {
    pub id: WalletId,
    pub label: String,
    pub tier: Tier,
    #[serde(default)]
    pub btc: Option<BtcWatch>,
    #[serde(default)]
    pub eth: Option<EthAddress>,
    #[serde(default)]
    pub tron: Option<TronAddress>,
    /// Master fingerprint (8 hex characters) when the wallet was imported
    /// from the signer tablet's export QR. `None` for wallets typed by hand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_fingerprint: Option<String>,
}

/// What the UI sends when adding a wallet. Every field is re-validated here.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewWalletInput {
    pub id: String,
    pub label: String,
    pub tier: Tier,
    #[serde(default)]
    pub btc: Option<String>,
    #[serde(default)]
    pub eth: Option<String>,
    #[serde(default)]
    pub tron: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("{0}")]
    WalletId(String),
    #[error("label must be 1-40 characters with no control characters")]
    Label,
    #[error("add at least one of: Bitcoin, Ethereum or TRON")]
    Empty,
    #[error("a wallet with id '{0}' already exists")]
    DuplicateId(String),
    #[error("this {0} address is already watched in wallet '{1}'")]
    DuplicateAddress(&'static str, String),
    #[error("Bitcoin field: {0}")]
    Btc(String),
    #[error("Ethereum field: {0}")]
    Eth(String),
    #[error("TRON field: {0}")]
    Tron(String),
    #[error("this looks like a seed phrase or private key. Never enter one here: this app is watch-only")]
    SecretRejected,
    #[error("too many wallets (max {MAX_WALLETS})")]
    TooMany,
    #[error("no wallet with id '{0}'")]
    NotFound(String),
    #[error("wallet file: {0}")]
    Io(String),
    #[error("wallet file is corrupted or from an unknown version")]
    Corrupt,
    #[error("{0}")]
    Export(String),
}

/// Rough check for pasted secrets: many words (a mnemonic), a 64-hex private
/// key, or a WIF key. Fail closed: refuse and warn.
fn looks_like_secret(s: &str) -> bool {
    let t = s.trim();
    let words = t.split_whitespace().count();
    let hex64 = {
        let h = t.strip_prefix("0x").unwrap_or(t);
        h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())
    };
    let wif = (t.len() == 51 || t.len() == 52)
        && (t.starts_with('5') || t.starts_with('K') || t.starts_with('L'));
    words >= 6
        || hex64
        || wif
        || ["xprv", "yprv", "zprv", "tprv"]
            .iter()
            .any(|p| t.starts_with(p))
}

fn non_empty(s: &Option<String>) -> Option<&str> {
    s.as_deref().map(str::trim).filter(|v| !v.is_empty())
}

impl NewWalletInput {
    pub fn validate(&self) -> Result<WatchWallet, RegistryError> {
        for field in [&self.btc, &self.eth, &self.tron]
            .into_iter()
            .filter_map(non_empty)
        {
            if looks_like_secret(field) {
                return Err(RegistryError::SecretRejected);
            }
        }
        let id: WalletId = self
            .id
            .trim()
            .parse()
            .map_err(|e: wallet_types::InvalidWalletId| RegistryError::WalletId(e.to_string()))?;
        let label = self.label.trim().to_owned();
        if label.is_empty() || label.chars().count() > 40 || label.chars().any(char::is_control) {
            return Err(RegistryError::Label);
        }

        let btc = match non_empty(&self.btc) {
            None => None,
            Some(v) if v.starts_with("xpub") || v.starts_with("zpub") || v.starts_with("ypub") => {
                if v.starts_with("ypub") {
                    return Err(RegistryError::Btc(
                        "ypub (wrapped SegWit) isn't supported; use the BIP-84 zpub/xpub".into(),
                    ));
                }
                Some(BtcWatch::AccountXpub(AccountXpubSer(
                    v.parse()
                        .map_err(|e: BtcError| RegistryError::Btc(e.to_string()))?,
                )))
            }
            Some(v) => Some(BtcWatch::Address(v.parse().map_err(|e: BtcError| {
                RegistryError::Btc(cross_network_hint(v).unwrap_or_else(|| e.to_string()))
            })?)),
        };
        let eth = match non_empty(&self.eth) {
            None => None,
            Some(v) => Some(v.parse::<EthAddress>().map_err(|e| {
                RegistryError::Eth(cross_network_hint(v).unwrap_or_else(|| e.to_string()))
            })?),
        };
        let tron = match non_empty(&self.tron) {
            None => None,
            Some(v) => Some(v.parse::<TronAddress>().map_err(|e| {
                RegistryError::Tron(cross_network_hint(v).unwrap_or_else(|| e.to_string()))
            })?),
        };
        if btc.is_none() && eth.is_none() && tron.is_none() {
            return Err(RegistryError::Empty);
        }
        Ok(WatchWallet {
            id,
            label,
            tier: self.tier,
            btc,
            eth,
            tron,
            signer_fingerprint: None,
        })
    }
}

/// A wallet from the signer tablet's watch-only export (the `WWX1:` text in
/// its QR code). The export's checksum and every field are checked again
/// here; the result has the BIP-84 account key and both addresses.
pub fn from_signer_export(text: &str) -> Result<WatchWallet, RegistryError> {
    // A pasted seed phrase or key gets the strong warning, not "not an export".
    // (A real export starts with the prefix; its label may contain spaces.)
    if !text.trim().starts_with(watch_export::PREFIX) && looks_like_secret(text) {
        return Err(RegistryError::SecretRejected);
    }
    let e = watch_export::decode(text).map_err(|e| RegistryError::Export(e.to_string()))?;
    let bad = |what: &str| RegistryError::Export(format!("the export's {what} is invalid"));
    let xpub: AccountXpub = e.public.btc_zpub.parse().map_err(|_| bad("Bitcoin key"))?;
    Ok(WatchWallet {
        id: e.id,
        label: e.label,
        tier: e.tier,
        btc: Some(BtcWatch::AccountXpub(AccountXpubSer(xpub))),
        eth: Some(e.public.eth.parse().map_err(|_| bad("Ethereum address"))?),
        tron: Some(e.public.tron.parse().map_err(|_| bad("TRON address"))?),
        signer_fingerprint: Some(e.public.fingerprint),
    })
}

/// Wrong-network detection (§7 ②): explain when an address belongs elsewhere.
fn cross_network_hint(v: &str) -> Option<String> {
    if v.parse::<TronAddress>().is_ok() {
        return Some("that's a TRON address; put it in the TRON field".into());
    }
    if v.starts_with("0x") && v.len() == 42 {
        return Some(
            "that looks like an Ethereum address; put it in the Ethereum field (checksummed form)"
                .into(),
        );
    }
    if v.parse::<BtcAddress>().is_ok() {
        return Some("that's a Bitcoin address; put it in the Bitcoin field".into());
    }
    None
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub version: u32,
    pub wallets: Vec<WatchWallet>,
}

impl Registry {
    pub fn empty() -> Self {
        Self {
            version: REGISTRY_VERSION,
            wallets: Vec::new(),
        }
    }

    pub fn add(&mut self, w: WatchWallet) -> Result<(), RegistryError> {
        if self.wallets.len() >= MAX_WALLETS {
            return Err(RegistryError::TooMany);
        }
        for existing in &self.wallets {
            if existing.id == w.id {
                return Err(RegistryError::DuplicateId(w.id.to_string()));
            }
            let dup = |what| {
                Err(RegistryError::DuplicateAddress(
                    what,
                    existing.id.to_string(),
                ))
            };
            if w.btc.is_some() && w.btc == existing.btc {
                return dup("Bitcoin");
            }
            if w.eth.is_some() && w.eth == existing.eth {
                return dup("Ethereum");
            }
            if w.tron.is_some() && w.tron == existing.tron {
                return dup("TRON");
            }
        }
        self.wallets.push(w);
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> Result<WatchWallet, RegistryError> {
        let pos = self
            .wallets
            .iter()
            .position(|w| w.id.as_str() == id)
            .ok_or_else(|| RegistryError::NotFound(id.to_owned()))?;
        Ok(self.wallets.remove(pos))
    }

    /// Load from disk. A missing file means "no wallets yet"; a corrupted or
    /// unknown-version file is an error (never silently replaced, §9.7).
    pub fn load(path: &Path) -> Result<Self, RegistryError> {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::empty()),
            Err(e) => return Err(RegistryError::Io(e.kind().to_string())),
        };
        let reg: Registry = serde_json::from_str(&text).map_err(|_| RegistryError::Corrupt)?;
        if reg.version != REGISTRY_VERSION {
            return Err(RegistryError::Corrupt);
        }
        // Re-check invariants: ids unique.
        let mut check = Registry::empty();
        for w in reg.wallets.iter().cloned() {
            check.add(w).map_err(|_| RegistryError::Corrupt)?;
        }
        Ok(reg)
    }

    /// Atomic save: write a temp file, flush to disk, then rename over the old
    /// file, so a crash can't leave a half-written registry (§6.4).
    pub fn save(&self, path: &Path) -> Result<(), RegistryError> {
        let io = |e: std::io::Error| RegistryError::Io(e.kind().to_string());
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(io)?;
        }
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(self).map_err(|_| RegistryError::Corrupt)?;
        {
            let mut f = fs::File::create(&tmp).map_err(io)?;
            f.write_all(&json).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        fs::rename(&tmp, path).map_err(io)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    fn input(id: &str) -> NewWalletInput {
        NewWalletInput {
            id: id.into(),
            label: "Savings".into(),
            tier: Tier::Savings,
            btc: Some(ZPUB.into()),
            eth: Some("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".into()),
            tron: Some("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".into()),
        }
    }

    #[test]
    fn validates_and_adds() {
        let mut r = Registry::empty();
        r.add(input("savings-01").validate().expect("valid"))
            .expect("add");
        assert_eq!(r.wallets.len(), 1);
        assert!(matches!(r.wallets[0].btc, Some(BtcWatch::AccountXpub(_))));
        // Same id again.
        assert!(matches!(
            r.add(input("savings-01").validate().expect("v")),
            Err(RegistryError::DuplicateId(_))
        ));
        // Same addresses under a different id.
        assert!(matches!(
            r.add(input("savings-02").validate().expect("v")),
            Err(RegistryError::DuplicateAddress(..))
        ));
    }

    /// Made by the tablet code from the public test phrase "abandon … about".
    const EXPORT: &str = r#"WWX1:{"id":"test-01","label":"Test spending","tier":"spending","fingerprint":"73c5da0a","btc_zpub":"zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs","eth":"0x9858EfFD232B4033E47d90003D41EC34EcaEda94","tron":"TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"}#55971832"#;

    #[test]
    fn imports_a_signer_export() {
        let w = from_signer_export(EXPORT).expect("import");
        assert_eq!(w.id.as_str(), "test-01");
        assert_eq!(w.tier, Tier::Spending);
        assert_eq!(w.signer_fingerprint.as_deref(), Some("73c5da0a"));
        assert_eq!(
            w.eth.map(|a| a.to_checksum()).as_deref(),
            Some("0x9858EfFD232B4033E47d90003D41EC34EcaEda94")
        );
        assert!(matches!(w.btc, Some(BtcWatch::AccountXpub(_))));
        let mut r = Registry::empty();
        r.add(w.clone()).expect("add");
        // The same wallet again is refused.
        assert!(matches!(r.add(w), Err(RegistryError::DuplicateId(_))));

        // Survives a save/load round trip; old files without the field load too.
        let json = serde_json::to_string(&r).expect("json");
        assert!(json.contains("signer_fingerprint"));
        let back: Registry = serde_json::from_str(&json).expect("back");
        assert_eq!(back, r);

        assert!(matches!(
            from_signer_export(&EXPORT.replacen("spending", "savings", 1)),
            Err(RegistryError::Export(m)) if m.contains("scan it again")
        ));
        assert!(matches!(
            from_signer_export("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
            Err(RegistryError::SecretRejected)
        ));
        // A label with many words isn't mistaken for a seed phrase.
        let json = EXPORT
            .strip_prefix(watch_export::PREFIX)
            .and_then(|b| b.rsplit_once('#'))
            .map(|(j, _)| j.replacen("Test spending", "my long spending wallet for daily use", 1))
            .expect("json");
        let sum = {
            use sha2::{Digest, Sha256};
            hex::encode(&Sha256::digest(json.as_bytes())[..4])
        };
        let long = format!("{}{json}#{sum}", watch_export::PREFIX);
        assert!(from_signer_export(&long).is_ok());
        assert!(matches!(
            from_signer_export("0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
            Err(RegistryError::Export(_))
        ));
    }

    #[test]
    fn rejects_secrets() {
        let mut i = input("a");
        i.btc = Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into());
        assert_eq!(i.validate(), Err(RegistryError::SecretRejected));
        i.btc = Some(format!("0x{}", "ab".repeat(32)));
        assert_eq!(i.validate(), Err(RegistryError::SecretRejected));
        i.btc = Some("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi".into());
        assert_eq!(i.validate(), Err(RegistryError::SecretRejected));
    }

    #[test]
    fn explains_wrong_network() {
        let mut i = input("a");
        i.eth = Some("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".into());
        assert!(matches!(i.validate(), Err(RegistryError::Eth(m)) if m.contains("TRON field")));
        let mut j = input("a");
        j.tron = Some("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".into());
        assert!(
            matches!(j.validate(), Err(RegistryError::Tron(m)) if m.contains("Ethereum field"))
        );
    }

    #[test]
    fn requires_something_to_watch_and_a_sane_label() {
        let mut i = input("a");
        i.btc = None;
        i.eth = Some("  ".into());
        i.tron = None;
        assert_eq!(i.validate(), Err(RegistryError::Empty));
        let mut j = input("a");
        j.label = "x\u{0007}".into();
        assert_eq!(j.validate(), Err(RegistryError::Label));
    }

    #[test]
    fn save_and_load_round_trip_and_detect_corruption() {
        let dir = std::env::temp_dir().join(format!("wallet-core-test-{}", std::process::id()));
        let path = dir.join("wallets.json");
        let _ = fs::remove_file(&path);
        assert_eq!(Registry::load(&path), Ok(Registry::empty()));
        let mut r = Registry::empty();
        r.add(input("savings-01").validate().expect("v"))
            .expect("add");
        r.save(&path).expect("save");
        assert_eq!(Registry::load(&path), Ok(r));
        fs::write(&path, "{\"version\":1,\"wallets\":[{\"id\":\"x\",\"label\":\"y\",\"tier\":\"savings\",\"secret\":1}]}").expect("w");
        assert_eq!(Registry::load(&path), Err(RegistryError::Corrupt));
        let _ = fs::remove_dir_all(&dir);
    }
}
