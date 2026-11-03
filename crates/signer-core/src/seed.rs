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
    #[error("{0} words entered: a recovery phrase has 12 or 24 words")]
    WrongWordCount(usize),
    #[error("word #{0} is empty")]
    EmptyWord(usize),
    #[error("word #{0} contains a space: put exactly one word in each box")]
    NotOneWord(usize),
    #[error("word #{0} is not in the BIP-39 English word list: check its spelling")]
    UnknownWord(usize),
    #[error("every word is in the word list, but the checksum doesn't match: a word is wrong (a different valid word) or two words are in the wrong order. Compare each word with your paper, in order")]
    BadChecksum,
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

    /// Restore from words typed or scanned on the signer, as one string
    /// separated by spaces.
    pub fn from_words(words: &str) -> Result<Self, SeedError> {
        let list: Zeroizing<Vec<String>> =
            Zeroizing::new(words.split_whitespace().map(str::to_owned).collect());
        Self::from_word_list(&list)
    }

    /// Restore from one word per entry (word #1 first). Errors name the word
    /// number but never the word itself.
    pub fn from_word_list(words: &[String]) -> Result<Self, SeedError> {
        if words.len() != 12 && words.len() != 24 {
            return Err(SeedError::WrongWordCount(words.len()));
        }
        let mut normalized: Zeroizing<Vec<String>> =
            Zeroizing::new(Vec::with_capacity(words.len()));
        for (i, w) in words.iter().enumerate() {
            let w = w.trim().to_lowercase();
            if w.is_empty() {
                return Err(SeedError::EmptyWord(i + 1));
            }
            if w.contains(char::is_whitespace) {
                return Err(SeedError::NotOneWord(i + 1));
            }
            if Language::English.find_word(&w).is_none() {
                return Err(SeedError::UnknownWord(i + 1));
            }
            normalized.push(w);
        }
        let joined = Zeroizing::new(normalized.join(" "));
        let m = Mnemonic::parse_in(Language::English, joined.as_str()).map_err(|e| match e {
            bip39::Error::InvalidChecksum => SeedError::BadChecksum,
            _ => SeedError::InvalidWords,
        })?;
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
            Err(SeedError::BadChecksum)
        );
        assert!(SeedMaterial::from_words("hello world").is_err());
    }

    #[test]
    fn restore_errors_name_the_word_number() {
        let s = SeedMaterial::from_entropy(&[5u8; 32]);
        let good: Vec<String> = s.words().expect("w").to_vec();
        assert!(SeedMaterial::from_word_list(&good).is_ok());

        let err = |w: &[String]| SeedMaterial::from_word_list(w).err();
        assert_eq!(err(&good[..23]), Some(SeedError::WrongWordCount(23)));
        let mut w = good.clone();
        w[4] = "  ".into();
        assert_eq!(err(&w), Some(SeedError::EmptyWord(5)));
        let mut w = good.clone();
        w[6] = "able about".into();
        assert_eq!(err(&w), Some(SeedError::NotOneWord(7)));
        let mut w = good.clone();
        w[9] = "bitcoinz".into();
        assert_eq!(err(&w), Some(SeedError::UnknownWord(10)));
        let mut w = good.clone();
        w.swap(0, 1);
        if w != good {
            assert_eq!(err(&w), Some(SeedError::BadChecksum));
        }
        let mut w = good.clone();
        w[2] = format!("  {}  ", w[2].to_uppercase());
        assert!(
            SeedMaterial::from_word_list(&w).is_ok(),
            "case and spaces don't matter"
        );
        // The message never contains the word itself.
        let mut w = good.clone();
        w[3] = "zzzzsecret".into();
        let msg = err(&w).expect("err").to_string();
        assert!(!msg.contains("zzzzsecret"));
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
