//! Watch-only export shown as a QR code for the PC app. The format lives in
//! the shared `watch-export` crate so the PC can read it without any seed
//! code; this module re-exports it.

pub use watch_export::{decode, encode, ExportError, WatchOnlyExport, PREFIX};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts;
    use crate::seed::SeedMaterial;
    use sha2::{Digest, Sha256};
    use wallet_types::Tier;

    fn checksum(json: &str) -> String {
        hex::encode(&Sha256::digest(json.as_bytes())[..4])
    }

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
