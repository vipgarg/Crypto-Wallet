//! BIP-39 seeds: create (24 words), restore (12 or 24 words, checksum
//! checked), the "write it down" word check, and the master fingerprint that
//! catches a mistyped passphrase (§6.1).

use bip39::{Language, Mnemonic};
use bitcoin::bip32::{Fingerprint, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::NetworkKind;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SeedError {
    #[error("the recovery phrase must be 12 or 24 words from the BIP-39 English list, with a valid checksum")]
    InvalidWords,
    #[error("key derivation failed")]
    Derivation,
}

/// The secret part of a wallet: the BIP-39 entropy. Wiped from memory when
/// dropped. Never printed (no `Debug`/`Display`).
pub struct SeedMaterial {
    entropy: Zeroizing<Vec<u8>>,
}

impl SeedMaterial {
    /// From 32 bytes of entropy (a new 24-word seed).
    pub fn from_entropy(entropy: &[u8; 32]) -> Self {
        Self {
            entropy: Zeroizing::new(entropy.to_vec()),
        }
    }

    /// Restore from words typed or scanned on the signer.
    pub fn from_words(words: &str) -> Result<Self, SeedError> {
        let normalized: Zeroizing<String> = Zeroizing::new(
            words
                .split_whitespace()
                .map(str::to_lowercase)
                .collect::<Vec<_>>()
                .join(" "),
        );
        let m = Mnemonic::parse_in(Language::English, normalized.as_str())
            .map_err(|_| SeedError::InvalidWords)?;
        let count = m.word_count();
        if count != 12 && count != 24 {
            return Err(SeedError::InvalidWords);
        }
        Ok(Self {
            entropy: Zeroizing::new(m.to_entropy()),
        })
    }

    /// Restore from stored entropy (the vault).
    pub fn from_entropy_bytes(entropy: &[u8]) -> Result<Self, SeedError> {
        Mnemonic::from_entropy(entropy).map_err(|_| SeedError::InvalidWords)?;
        Ok(Self {
            entropy: Zeroizing::new(entropy.to_vec()),
        })
    }

    pub fn entropy(&self) -> &[u8] {
        &self.entropy
    }

    /// The recovery words, for writing down once at creation.
    pub fn words(&self) -> Result<Zeroizing<Vec<String>>, SeedError> {
        let m = Mnemonic::from_entropy(&self.entropy).map_err(|_| SeedError::InvalidWords)?;
        Ok(Zeroizing::new(m.words().map(str::to_owned).collect()))
    }

    /// BIP-39 seed bytes for a passphrase ("" if none).
    pub fn bip39_seed(&self, passphrase: &str) -> Result<Zeroizing<[u8; 64]>, SeedError> {
        let m = Mnemonic::from_entropy(&self.entropy).map_err(|_| SeedError::InvalidWords)?;
        let mut s = m.to_seed_normalized(passphrase);
        let out = Zeroizing::new(s);
        s.zeroize();
        Ok(out)
    }

    /// BIP-32 master key for a passphrase. `Xpriv` is not zeroized by the
    /// bitcoin crate, so keep its lifetime short (one derivation).
    pub fn master(&self, passphrase: &str) -> Result<Xpriv, SeedError> {
        let seed = self.bip39_seed(passphrase)?;
        Xpriv::new_master(NetworkKind::Main, seed.as_ref()).map_err(|_| SeedError::Derivation)
    }

    /// Master fingerprint of seed + passphrase. Recorded when the wallet is
    /// created; a different value at signing time means a mistyped
    /// passphrase (which would silently open a different, empty wallet).
    pub fn fingerprint(&self, passphrase: &str) -> Result<Fingerprint, SeedError> {
        let secp = Secp256k1::signing_only();
        Ok(self.master(passphrase)?.fingerprint(&secp))
    }
}

/// Positions (1-based) the user must re-enter to prove they wrote the words
/// down: `count` distinct positions chosen at random.
pub fn word_check_positions(total: usize, count: usize) -> Result<Vec<usize>, getrandom::Error> {
    let count = count.min(total);
    let mut chosen = Vec::with_capacity(count);
    while chosen.len() < count {
        let mut b = [0u8; 2];
        auth::random_bytes(&mut b)?;
        // Rejection sampling: no modulo bias.
        let v = usize::from(u16::from_be_bytes(b));
        let limit = (usize::from(u16::MAX) + 1) / total * total;
        if v >= limit {
            continue;
        }
        let pos = v % total + 1;
        if !chosen.contains(&pos) {
            chosen.push(pos);
        }
    }
    chosen.sort_unstable();
    Ok(chosen)
}

/// Check the words the user re-entered for `positions`.
pub fn check_words(
    seed: &SeedMaterial,
    positions: &[usize],
    answers: &[String],
) -> Result<bool, SeedError> {
    let words = seed.words()?;
    if positions.len() != answers.len() {
        return Ok(false);
    }
    Ok(positions.iter().zip(answers).all(|(p, a)| {
        words
            .get(p.wrapping_sub(1))
            .is_some_and(|w| w.eq_ignore_ascii_case(a.trim()))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip39_zero_entropy_vector() {
        let s = SeedMaterial::from_entropy(&[0u8; 32]);
        let words = s.words().expect("words");
        assert_eq!(words.len(), 24);
        assert!(words[..23].iter().all(|w| w == "abandon"));
        assert_eq!(words[23], "art");
        // BIP-39 reference vector with passphrase "TREZOR".
        assert_eq!(
            hex::encode(&s.bip39_seed("TREZOR").expect("seed")[..]),
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
        );
        assert_eq!(
            s.master("TREZOR").expect("master").to_string(),
            "xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM"
        );
    }

    #[test]
    fn restore_checks_words() {
        let s = SeedMaterial::from_entropy(&[7u8; 32]);
        let words = s.words().expect("w").join(" ");
        let back = SeedMaterial::from_words(&words.to_uppercase()).expect("restore");
        assert_eq!(back.entropy(), s.entropy());
        // A wrong last word breaks the checksum.
        let mut w: Vec<String> = s.words().expect("w").to_vec();
        w[23] = if w[23] == "zoo" {
            "abandon".into()
        } else {
            "zoo".into()
        };
        assert_eq!(
            SeedMaterial::from_words(&w.join(" ")).map(|_| ()),
            Err(SeedError::InvalidWords)
        );
        assert!(SeedMaterial::from_words("hello world").is_err());
    }

    #[test]
    fn passphrase_changes_fingerprint() {
        let s = SeedMaterial::from_entropy(&[9u8; 32]);
        let a = s.fingerprint("").expect("a");
        let b = s.fingerprint("my passphrase").expect("b");
        assert_ne!(a, b);
        assert_eq!(b, s.fingerprint("my passphrase").expect("b2"));
    }

    #[test]
    fn word_check() {
        let s = SeedMaterial::from_entropy(&[3u8; 32]);
        let pos = word_check_positions(24, 4).expect("pos");
        assert_eq!(pos.len(), 4);
        assert!(pos.windows(2).all(|w| w[0] < w[1]) && pos.iter().all(|p| (1..=24).contains(p)));
        let words = s.words().expect("w");
        let right: Vec<String> = pos.iter().map(|p| words[p - 1].clone()).collect();
        assert_eq!(check_words(&s, &pos, &right), Ok(true));
        let mut wrong = right.clone();
        wrong[0] = "zzz".into();
        assert_eq!(check_words(&s, &pos, &wrong), Ok(false));
    }
}
