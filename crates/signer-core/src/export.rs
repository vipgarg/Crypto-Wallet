//! Watch-only export: what the tablet shows as a QR code so the PC app can
//! add the wallet. Public data only (fingerprint, zpub, addresses).
//!
//! Format: `WWX1:` + compact JSON + `#` + first 8 hex characters of
//! SHA-256(JSON). The checksum catches scanning errors; it is **not** a
//! signature. The PC re-validates every field, and the user confirms the
//! receive addresses on the tablet screen (§7.2) before using them.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use wallet_types::{Tier, WalletId};

use crate::accounts::{self, WalletPublic};

pub const PREFIX: &str = "WWX1:";

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
    let body = s
        .trim()
        .strip_prefix(PREFIX)
        .ok_or(ExportError::NotAnExport)?;
    let (json, sum) = body.rsplit_once('#').ok_or(ExportError::NotAnExport)?;
    if sum != checksum(json) {
        return Err(ExportError::Checksum);
    }
    let e: WatchOnlyExport = serde_json::from_str(json).map_err(|_| ExportError::Invalid)?;
    let label_ok = !e.label.trim().is_empty()
        && e.label.chars().count() <= 40
        && !e.label.chars().any(char::is_control);
    if !label_ok || !accounts::validate(&e.public) {
        return Err(ExportError::Invalid);
    }
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::SeedMaterial;

    fn sample() -> WatchOnlyExport {
        let seed = SeedMaterial::from_entropy(&[5u8; 32]);
        WatchOnlyExport {
            id: "savings-01".parse().expect("id"),
            label: "Savings".into(),
            tier: Tier::Savings,
            public: accounts::derive_public(&seed, "pass phrase").expect("derive"),
        }
    }

    #[test]
    fn round_trip_and_fits_a_qr_code() {
        let e = sample();
        let s = encode(&e).expect("encode");
        assert!(s.starts_with(PREFIX));
        // Comfortably within a single QR code (version 40-L holds ~2900 bytes).
        assert!(s.len() < 500, "{}", s.len());
        assert_eq!(decode(&s), Ok(e));
    }

    #[test]
    fn rejects_damage_and_tampering() {
        let s = encode(&sample()).expect("encode");
        assert_eq!(decode("hello"), Err(ExportError::NotAnExport));
        // One character changed → checksum fails.
        let damaged = s.replacen("Savings", "Savingz", 1);
        assert_eq!(decode(&damaged), Err(ExportError::Checksum));
        // Valid checksum but an invalid (unchecksummed) address → rejected.
        let mut e = sample();
        e.public.eth = e.public.eth.to_lowercase();
        let json = serde_json::to_string(&e).expect("json");
        let forged = format!("{PREFIX}{json}#{}", checksum(&json));
        assert_eq!(decode(&forged), Err(ExportError::Invalid));
        // Unknown extra fields are refused (no smuggled data).
        let json =
            serde_json::to_string(&sample())
                .expect("json")
                .replacen('{', "{\"xprv\":\"x\",", 1);
        let smuggled = format!("{PREFIX}{json}#{}", checksum(&json));
        assert_eq!(decode(&smuggled), Err(ExportError::Invalid));
    }
}
