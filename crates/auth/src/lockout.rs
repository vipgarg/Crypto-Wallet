//! Wrong-attempt delays (§9.8): 1, 2, 4, 8 s after the first failures, then a
//! 30-minute lock after 5 failures in a row. Kept in a small file so closing
//! and reopening the app doesn't reset it. (Someone with full access to the PC
//! could delete that file; the Argon2 cost still makes guessing slow.)

use serde::{Deserialize, Serialize};

pub const MAX_FAILURES: u32 = 5;
pub const LOCK_SECS: u64 = 30 * 60;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lockout {
    pub failures: u32,
    /// No attempt is accepted before this Unix time.
    pub not_before: u64,
}

impl Lockout {
    /// `Err(seconds to wait)` if an attempt isn't allowed yet.
    pub fn check(&self, now: u64) -> Result<(), u64> {
        if now < self.not_before {
            Err(self.not_before - now)
        } else {
            Ok(())
        }
    }

    pub fn record_failure(&mut self, now: u64) {
        self.failures = self.failures.saturating_add(1);
        let wait = if self.failures >= MAX_FAILURES {
            LOCK_SECS
        } else {
            1u64 << (self.failures - 1)
        };
        self.not_before = now.saturating_add(wait);
        if self.failures >= MAX_FAILURES {
            // Start counting again after the long lock.
            self.failures = 0;
        }
    }

    pub fn record_success(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delays_grow_then_lock() {
        let mut l = Lockout::default();
        let mut now = 1000;
        assert_eq!(l.check(now), Ok(()));
        for expected in [1u64, 2, 4, 8] {
            l.record_failure(now);
            assert_eq!(l.check(now), Err(expected));
            now += expected;
            assert_eq!(l.check(now), Ok(()));
        }
        l.record_failure(now);
        assert_eq!(l.check(now), Err(LOCK_SECS));
        l.record_success();
        assert_eq!(l, Lockout::default());
    }
}
