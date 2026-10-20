//! Slows down master-password guessing through the app (BRIEF §9, M6).
//!
//! One counter is shared by every password check: unlock, change password,
//! export, update install and restore. After `FREE_ATTEMPTS` wrong passwords,
//! each further failure doubles the wait (1s, 2s, 4s… capped at `MAX_WAIT`).
//! A correct password resets it. It lives in memory only: quitting the app
//! resets it, and it does nothing against someone holding a copy of
//! vault.enc. Argon2id is the defence there.

use std::time::{Duration, Instant};

pub const FREE_ATTEMPTS: u32 = 5;
pub const MAX_WAIT: Duration = Duration::from_secs(30);

#[derive(Debug, Default)]
pub struct Backoff {
    failures: u32,
    locked_until: Option<Instant>,
}

impl Backoff {
    /// Whole seconds left to wait (rounded up), or 0 if a check may run now.
    pub fn wait_secs(&self, now: Instant) -> u64 {
        match self.locked_until {
            Some(until) if until > now => (until - now).as_millis().div_ceil(1000) as u64,
            _ => 0,
        }
    }

    pub fn record_failure(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        if self.failures > FREE_ATTEMPTS {
            let exp = (self.failures - FREE_ATTEMPTS - 1).min(16);
            let wait = Duration::from_secs(1 << exp).min(MAX_WAIT);
            self.locked_until = Some(now + wait);
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
    fn free_attempts_have_no_wait() {
        let t = Instant::now();
        let mut b = Backoff::default();
        for _ in 0..FREE_ATTEMPTS {
            assert_eq!(b.wait_secs(t), 0);
            b.record_failure(t);
        }
        assert_eq!(b.wait_secs(t), 0, "5 wrong passwords are free");
    }

    #[test]
    fn waits_double_then_cap() {
        let t = Instant::now();
        let mut b = Backoff::default();
        for _ in 0..FREE_ATTEMPTS {
            b.record_failure(t);
        }
        let mut waits = Vec::new();
        for _ in 0..8 {
            b.record_failure(t);
            waits.push(b.wait_secs(t));
        }
        assert_eq!(waits, [1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[test]
    fn wait_runs_out() {
        let t = Instant::now();
        let mut b = Backoff::default();
        for _ in 0..FREE_ATTEMPTS + 3 {
            b.record_failure(t);
        }
        assert_eq!(b.wait_secs(t), 4);
        assert_eq!(b.wait_secs(t + Duration::from_millis(3_200)), 1, "rounds up");
        assert_eq!(b.wait_secs(t + Duration::from_secs(4)), 0);
    }

    #[test]
    fn success_resets_everything() {
        let t = Instant::now();
        let mut b = Backoff::default();
        for _ in 0..FREE_ATTEMPTS + 4 {
            b.record_failure(t);
        }
        b.record_success();
        assert_eq!(b.wait_secs(t), 0);
        b.record_failure(t);
        assert_eq!(b.wait_secs(t), 0, "free attempts are back");
    }

    #[test]
    fn huge_failure_counts_dont_overflow() {
        let t = Instant::now();
        let mut b = Backoff { failures: u32::MAX - 1, locked_until: None };
        b.record_failure(t);
        b.record_failure(t);
        assert_eq!(b.wait_secs(t), 30);
    }
}
