use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Tracks account lockouts encountered during an attack session.
///
/// Accounts move through two distinct states:
/// - **Locked** — temporarily locked with an optional cooldown before retry.
/// - **Disabled** — permanently disabled; always skipped.
pub struct LockoutTracker {
    /// username → timestamp when lockout was detected.
    locked_accounts: HashMap<String, Instant>,
    /// Usernames confirmed permanently disabled.
    disabled_accounts: HashSet<String>,
    /// How long to wait before retrying a locked account.
    /// `None` means skip the account permanently (no retry).
    cooldown: Option<Duration>,
    /// Running total of lockout events recorded.
    total_lockouts: u64,
}

impl LockoutTracker {
    /// Create a new tracker.
    ///
    /// * `cooldown` — if `Some(d)`, retry a locked account after `d` has elapsed.
    ///   If `None`, locked accounts are skipped for the remainder of the session.
    pub fn new(cooldown: Option<Duration>) -> Self {
        Self {
            locked_accounts: HashMap::new(),
            disabled_accounts: HashSet::new(),
            cooldown,
            total_lockouts: 0,
        }
    }

    /// Record a lockout for `username`.
    ///
    /// `hint` is a human-readable duration extracted from the server response
    /// (e.g. `"30 minutes"`).  It is logged for operator awareness only.
    pub fn mark_locked(&mut self, username: &str, hint: Option<String>) {
        self.total_lockouts += 1;
        self.locked_accounts
            .insert(username.to_string(), Instant::now());
        tracing::warn!("Account locked: {} (hint: {:?})", username, hint);
    }

    /// Mark `username` as permanently disabled, removing it from the locked set.
    pub fn mark_disabled(&mut self, username: &str) {
        self.disabled_accounts.insert(username.to_string());
        self.locked_accounts.remove(username);
    }

    /// Return `true` if `username` should be skipped for the current attempt.
    ///
    /// An account is skipped when:
    /// - It is disabled, **or**
    /// - It is locked and the cooldown has not yet expired (or there is no cooldown).
    pub fn should_skip(&self, username: &str) -> bool {
        if self.disabled_accounts.contains(username) {
            return true;
        }
        if let Some(locked_at) = self.locked_accounts.get(username) {
            return match self.cooldown {
                Some(cooldown) => locked_at.elapsed() < cooldown,
                // No cooldown configured → skip indefinitely.
                None => true,
            };
        }
        false
    }

    /// Return `true` if `username` has an active lockout entry (regardless of cooldown).
    pub fn is_locked(&self, username: &str) -> bool {
        self.locked_accounts.contains_key(username)
    }

    /// Number of accounts currently in the locked set.
    pub fn locked_count(&self) -> usize {
        self.locked_accounts.len()
    }

    /// Number of accounts marked as permanently disabled.
    pub fn disabled_count(&self) -> usize {
        self.disabled_accounts.len()
    }

    /// Running total of [`mark_locked`](Self::mark_locked) calls.
    pub fn total_lockouts(&self) -> u64 {
        self.total_lockouts
    }

    /// Remove entries whose cooldown has expired so memory does not grow unboundedly.
    ///
    /// Has no effect when `cooldown` is `None`.
    pub fn cleanup_expired(&mut self) {
        if let Some(cooldown) = self.cooldown {
            self.locked_accounts.retain(|_, t| t.elapsed() < cooldown);
        }
    }

    /// Human-readable summary of lockout statistics.
    pub fn summary(&self) -> String {
        format!(
            "Lockouts: {} total, {} active, {} disabled",
            self.total_lockouts,
            self.locked_accounts.len(),
            self.disabled_accounts.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn lockout_mark_and_skip() {
        let mut t = LockoutTracker::new(None);
        assert!(!t.should_skip("alice"));
        t.mark_locked("alice", None);
        assert!(t.should_skip("alice"));
        assert_eq!(t.locked_count(), 1);
    }

    #[test]
    fn lockout_disabled_always_skip() {
        let mut t = LockoutTracker::new(Some(Duration::from_secs(3600)));
        t.mark_disabled("bob");
        assert!(t.should_skip("bob"));
        // Disabled accounts bypass the cooldown mechanism entirely.
        assert_eq!(t.locked_count(), 0);
        assert_eq!(t.disabled_count(), 1);
    }

    #[test]
    fn lockout_cooldown_expired_not_skipped() {
        // Very short cooldown so it expires almost immediately.
        let mut t = LockoutTracker::new(Some(Duration::from_millis(1)));
        t.mark_locked("carol", None);
        assert!(t.is_locked("carol"));

        // Wait for the cooldown to elapse.
        thread::sleep(Duration::from_millis(10));

        // Cooldown expired → should NOT be skipped anymore.
        assert!(!t.should_skip("carol"));
    }

    #[test]
    fn lockout_no_cooldown_skip_forever() {
        let mut t = LockoutTracker::new(None);
        t.mark_locked("dave", None);
        // Sleep briefly to confirm elapsed time does not matter.
        thread::sleep(Duration::from_millis(5));
        assert!(
            t.should_skip("dave"),
            "no cooldown configured → should skip indefinitely"
        );
    }

    #[test]
    fn lockout_cleanup_expired() {
        let mut t = LockoutTracker::new(Some(Duration::from_millis(1)));
        t.mark_locked("eve", None);
        assert_eq!(t.locked_count(), 1);

        thread::sleep(Duration::from_millis(10));
        t.cleanup_expired();

        assert_eq!(
            t.locked_count(),
            0,
            "expired entry should have been removed"
        );
    }

    #[test]
    fn lockout_summary_format() {
        let mut t = LockoutTracker::new(None);
        t.mark_locked("frank", None);
        t.mark_locked("grace", Some("30 minutes".into()));
        t.mark_disabled("hank");

        let s = t.summary();
        assert!(s.contains("2 total"), "summary: {}", s);
        // "hank" was disabled, so locked_count should be 2 (frank + grace).
        assert!(s.contains("2 active"), "summary: {}", s);
        assert!(s.contains("1 disabled"), "summary: {}", s);
    }

    #[test]
    fn lockout_total_count() {
        let mut t = LockoutTracker::new(None);
        t.mark_locked("user1", None);
        t.mark_locked("user2", None);
        // Re-locking the same account still increments the counter.
        t.mark_locked("user1", None);
        assert_eq!(t.total_lockouts(), 3);
    }
}
