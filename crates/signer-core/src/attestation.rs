//! Tamper check from Android key attestation (ARCHITECTURE-MOBILE.md §5.1:
//! "verified boot green").
//!
//! The tablet asks its secure hardware (TEE or StrongBox) to create a key
//! and sign a certificate about it. That certificate carries a
//! `KeyDescription` (OID 1.3.6.1.4.1.11129.2.1.17) with the device's **root
//! of trust**: whether the bootloader is locked and whether the running
//! system passed verified boot. The Android side checks the certificate
//! chain up to one of Google's pinned attestation roots; this module reads
//! the description and decides.
//!
//! Passes only if: the attestation came from secure hardware (not
//! software), our fresh challenge is in it, the root of trust is in the
//! hardware-enforced list, the bootloader is **locked** and verified boot
//! is **Verified** (green). Limits: revocation of attestation keys can't be
//! checked offline; a fully compromised secure element could lie.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestError {
    #[error("the attestation data is malformed")]
    Malformed,
}

/// What the attestation says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// 0 = software, 1 = TEE, 2 = StrongBox.
    pub security_level: u64,
    pub challenge_matches: bool,
    /// Root of trust found in the hardware-enforced list.
    pub root_of_trust_in_hardware: bool,
    pub device_locked: bool,
    /// 0 Verified, 1 SelfSigned, 2 Unverified, 3 Failed.
    pub verified_boot_state: u64,
}

impl Attestation {
    /// (passed, plain explanation)
    pub fn verdict(&self) -> (bool, String) {
        let level = match self.security_level {
            1 => "secure processor area (TEE)",
            2 => "security chip (StrongBox)",
            _ => "software only",
        };
        if self.security_level == 0 {
            return (
                false,
                "The attestation came from software, not secure hardware, so it can't be trusted."
                    .into(),
            );
        }
        if !self.challenge_matches {
            return (
                false,
                "The attestation isn't fresh (challenge mismatch).".into(),
            );
        }
        if !self.root_of_trust_in_hardware {
            return (
                false,
                "The secure hardware didn't report the boot state.".into(),
            );
        }
        let boot = match self.verified_boot_state {
            0 => "Verified (green)",
            1 => "Self-signed (yellow: a custom system)",
            2 => "Unverified (orange: bootloader unlocked)",
            3 => "Failed (red)",
            _ => "unknown",
        };
        let ok = self.device_locked && self.verified_boot_state == 0;
        let detail = format!(
            "Boot: {boot}; bootloader {}; reported by the {level}.{}",
            if self.device_locked {
                "locked"
            } else {
                "UNLOCKED"
            },
            if ok {
                ""
            } else {
                " A modified or unlocked system could read your keys: don't use this tablet for real wallets."
            }
        );
        (ok, detail)
    }
}

/// DER tag: (class bits, constructed, tag number), header length, content length.
struct Tlv<'a> {
    class: u8,
    number: u64,
    content: &'a [u8],
}

fn read_tlv(b: &[u8]) -> Result<(Tlv<'_>, &[u8]), AttestError> {
    let first = *b.first().ok_or(AttestError::Malformed)?;
    let class = first >> 6;
    let mut i = 1;
    let mut number = u64::from(first & 0x1f);
    if number == 0x1f {
        number = 0;
        loop {
            let x = *b.get(i).ok_or(AttestError::Malformed)?;
            i += 1;
            number = number.checked_mul(128).ok_or(AttestError::Malformed)? | u64::from(x & 0x7f);
            if x & 0x80 == 0 {
                break;
            }
            if i > 6 {
                return Err(AttestError::Malformed);
            }
        }
    }
    let l0 = *b.get(i).ok_or(AttestError::Malformed)?;
    i += 1;
    let len = if l0 < 0x80 {
        usize::from(l0)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 4 {
            return Err(AttestError::Malformed);
        }
        let mut v = 0usize;
        for _ in 0..n {
            v = (v << 8) | usize::from(*b.get(i).ok_or(AttestError::Malformed)?);
            i += 1;
        }
        v
    };
    let end = i.checked_add(len).ok_or(AttestError::Malformed)?;
    let content = b.get(i..end).ok_or(AttestError::Malformed)?;
    Ok((
        Tlv {
            class,
            number,
            content,
        },
        &b[end..],
    ))
}

fn children(b: &[u8]) -> Result<Vec<Tlv<'_>>, AttestError> {
    let mut out = Vec::new();
    let mut rest = b;
    while !rest.is_empty() {
        let (t, r) = read_tlv(rest)?;
        out.push(t);
        rest = r;
    }
    Ok(out)
}

fn uint(t: &Tlv<'_>) -> Result<u64, AttestError> {
    if t.content.is_empty() || t.content.len() > 8 {
        return Err(AttestError::Malformed);
    }
    Ok(t.content.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x)))
}

/// Find the root of trust ([704] explicit) in an AuthorizationList.
fn root_of_trust(list: &Tlv<'_>) -> Result<Option<(bool, u64)>, AttestError> {
    for item in children(list.content)? {
        if item.class == 2 && item.number == 704 {
            let (seq, _) = read_tlv(item.content)?;
            let f = children(seq.content)?;
            // verifiedBootKey, deviceLocked, verifiedBootState, [verifiedBootHash]
            if f.len() < 3 {
                return Err(AttestError::Malformed);
            }
            let locked = f[1].content.first().is_some_and(|x| *x != 0);
            return Ok(Some((locked, uint(&f[2])?)));
        }
    }
    Ok(None)
}

/// Parse a `KeyDescription`. Accepts it as returned by Android's
/// `getExtensionValue` (wrapped in an OCTET STRING) or unwrapped.
pub fn parse(ext: &[u8], challenge: &[u8]) -> Result<Attestation, AttestError> {
    let (mut top, _) = read_tlv(ext)?;
    if top.class == 0 && top.number == 4 {
        top = read_tlv(top.content)?.0;
    }
    if !(top.class == 0 && top.number == 16) {
        return Err(AttestError::Malformed);
    }
    let f = children(top.content)?;
    // attestationVersion, attestationSecurityLevel, keyMintVersion,
    // keyMintSecurityLevel, attestationChallenge, uniqueId,
    // softwareEnforced, hardwareEnforced
    if f.len() < 8 {
        return Err(AttestError::Malformed);
    }
    let security_level = uint(&f[1])?;
    let challenge_matches = f[4].content == challenge;
    let hw = root_of_trust(&f[7])?;
    Ok(Attestation {
        security_level,
        challenge_matches,
        root_of_trust_in_hardware: hw.is_some(),
        device_locked: hw.is_some_and(|h| h.0),
        verified_boot_state: hw.map_or(u64::MAX, |h| h.1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNLOCKED: &[u8] = include_bytes!("../testdata/attest_unlocked_pixel.der");
    const LOCKED: &[u8] = include_bytes!("../testdata/attest_locked_pixel.der");

    #[test]
    fn locked_verified_device_passes() {
        let a = parse(LOCKED, b"d688d763-6118-4ca6-94b2-e6cd9ed7e4e4").expect("parse");
        assert_eq!(a.security_level, 1);
        assert!(a.challenge_matches && a.root_of_trust_in_hardware);
        assert!(a.device_locked);
        assert_eq!(a.verified_boot_state, 0);
        let (ok, detail) = a.verdict();
        assert!(ok, "{detail}");
    }

    #[test]
    fn unlocked_device_fails() {
        let a = parse(UNLOCKED, b"challenge").expect("parse");
        assert!(!a.device_locked);
        assert_eq!(a.verified_boot_state, 2);
        let (ok, detail) = a.verdict();
        assert!(!ok);
        assert!(detail.contains("UNLOCKED"), "{detail}");
    }

    #[test]
    fn stale_challenge_fails_and_wrapped_form_is_accepted() {
        let a = parse(LOCKED, b"another challenge").expect("parse");
        assert!(!a.verdict().0);
        // As returned by getExtensionValue: OCTET STRING around the SEQUENCE.
        let mut wrapped = vec![0x04, 0x82];
        wrapped.extend_from_slice(&u16::try_from(LOCKED.len()).expect("len").to_be_bytes());
        wrapped.extend_from_slice(LOCKED);
        let b = parse(&wrapped, b"d688d763-6118-4ca6-94b2-e6cd9ed7e4e4").expect("wrapped");
        assert!(b.verdict().0);
        // Garbage.
        assert!(parse(&[0x30, 0x05, 1, 2], b"x").is_err());
        assert!(parse(&LOCKED[..40], b"x").is_err());
    }
}
