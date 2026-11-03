//! Watch-only export: what the signer tablet shows as a QR code so the PC app
//! can add the wallet. Public data only (fingerprint, zpub, addresses).
//!
//! Shared by the tablet (`signer-core`, which encodes) and the PC app
//! (`wallet-core`, which decodes). This crate has no seed or key code.
//!
//! Format: `WWX1:` + compact JSON + `#` + first 8 hex characters of
//! SHA-256(JSON). The checksum catches scanning errors; it is **not** a
//! signature. The PC re-validates every field, and the user confirms the
//! receive addresses on the tablet screen (§7.2) before using them.

use chain_btc::AccountXpub;
use chain_eth::EthAddress;
use chain_tron::TronAddress;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use wallet_types::{Tier, WalletId};

pub const PREFIX: &str = "WWX1:";

/// Longest export accepted (a real one is under 500 characters).
pub const MAX_LEN: usize = 2000;

/// Everything the PC needs to watch a wallet. Public data only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletPublic {
    /// Master fingerprint (seed + passphrase), 8 hex characters.
    pub fingerprint: String,
    pub btc_zpub: String,
    pub eth: String,
    pub tron: String,
}

/// Re-validate the public data (catches a corrupted or forged record).
pub fn validate(public: &WalletPublic) -> bool {
    public.btc_zpub.starts_with("zpub")
        && public.btc_zpub.parse::<AccountXpub>().is_ok()
        && public.eth.parse::<EthAddress>().is_ok()
        && public.tron.parse::<TronAddress>().is_ok()
        && public.fingerprint.len() == 8
        && public
            .fingerprint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchOnlyExport {
    pub id: WalletId,
    pub label: String,
    pub tier: Tier,
    #[serde(flatten)]
    pub public: WalletPublic,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExportError {
    #[error("this isn't a wallet export from the signer")]
    NotAnExport,
    #[error("the export was scanned wrongly (checksum mismatch); scan it again")]
    Checksum,
    #[error("the export contains invalid data")]
    Invalid,
}

fn checksum(json: &str) -> String {
    hex::encode(&Sha256::digest(json.as_bytes())[..4])
}

pub fn encode(e: &WatchOnlyExport) -> Result<String, ExportError> {
    let json = serde_json::to_string(e).map_err(|_| ExportError::Invalid)?;
    Ok(format!("{PREFIX}{json}#{}", checksum(&json)))
}

pub fn decode(s: &str) -> Result<WatchOnlyExport, ExportError> {
    let s = s.trim();
    if s.len() > MAX_LEN {
        return Err(ExportError::NotAnExport);
    }
    let body = s.strip_prefix(PREFIX).ok_or(ExportError::NotAnExport)?;
    let (json, sum) = body.rsplit_once('#').ok_or(ExportError::NotAnExport)?;
    if sum != checksum(json) {
        return Err(ExportError::Checksum);
    }
    let e: WatchOnlyExport = serde_json::from_str(json).map_err(|_| ExportError::Invalid)?;
    let label_ok = !e.label.trim().is_empty()
        && e.label.chars().count() <= 40
        && !e.label.chars().any(char::is_control);
    if !label_ok || !validate(&e.public) {
        return Err(ExportError::Invalid);
    }
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Made by the tablet code from the public BIP-39 test phrase
    /// "abandon … about" (no passphrase). Test data only.
    const SAMPLE: &str = r#"WWX1:{"id":"test-01","label":"Test spending","tier":"spending","fingerprint":"73c5da0a","btc_zpub":"zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs","eth":"0x9858EfFD232B4033E47d90003D41EC34EcaEda94","tron":"TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"}#55971832"#;

    fn resign(json: &str) -> String {
        format!("{PREFIX}{json}#{}", checksum(json))
    }

    fn json_of(s: &str) -> &str {
        s.strip_prefix(PREFIX)
            .and_then(|b| b.rsplit_once('#'))
            .map(|(j, _)| j)
            .unwrap_or_default()
    }

    #[test]
    fn decodes_a_tablet_export() {
        let e = decode(&format!("  {SAMPLE}\n")).expect("decode");
        assert_eq!(e.id.as_str(), "test-01");
        assert_eq!(e.tier, Tier::Spending);
        assert_eq!(e.public.fingerprint, "73c5da0a");
        assert_eq!(e.public.eth, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        assert_eq!(encode(&e).as_deref(), Ok(SAMPLE), "round trip");
    }

    #[test]
    fn rejects_damage_forgery_and_extras() {
        assert_eq!(decode("hello"), Err(ExportError::NotAnExport));
        assert_eq!(decode(""), Err(ExportError::NotAnExport));
        assert_eq!(
            decode(&format!("{SAMPLE}{}", " ".repeat(MAX_LEN))),
            Ok(decode(SAMPLE).expect("ok")),
            "trailing spaces are trimmed first"
        );
        assert_eq!(
            decode(&format!("{PREFIX}{}", "x".repeat(MAX_LEN))),
            Err(ExportError::NotAnExport)
        );
        assert_eq!(
            decode(&SAMPLE.replacen("spending", "savings", 1)),
            Err(ExportError::Checksum)
        );
        let json = json_of(SAMPLE);
        // Valid checksum, but data that isn't valid public data.
        for bad in [
            json.replacen("0x9858EfFD", "0x9858effd", 1), // checksum case broken
            json.replacen("TUEZ", "TUEz", 1),             // TRON checksum broken
            json.replacen("zpub6rFR", "xpub6rFR", 1),     // not a zpub
            json.replacen("73c5da0a", "73C5DA0A", 1),     // fingerprint must be lowercase hex
            json.replacen("Test spending", "", 1),        // empty label
            json.replacen("Test spending", "a\\u0007b", 1),
            json.replacen("test-01", "Test 01", 1), // invalid id
            json.replacen("\"tier\":\"spending\"", "\"tier\":\"admin\"", 1),
            json.replacen('{', "{\"xprv\":\"x\",", 1), // smuggled field
        ] {
            assert_eq!(decode(&resign(&bad)), Err(ExportError::Invalid), "{bad}");
        }
    }
}
