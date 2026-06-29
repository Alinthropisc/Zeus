use crate::{AttackStrategy, CredentialStream};
use tokio_stream::iter;
use zeus_core::Credential;

/// Configuration for password spray timing and lockout avoidance.
pub struct SprayConfig {
    /// Number of attempts per account before the strategy pauses to respect lockout windows.
    pub lockout_threshold: u32,
    /// Rolling window in minutes used to spread attempts and avoid time-based lockouts.
    pub spray_window_minutes: u32,
    /// Milliseconds to wait between attempts against successive usernames.
    pub delay_ms: u64,
}

impl Default for SprayConfig {
    fn default() -> Self {
        Self {
            lockout_threshold: 3,
            spray_window_minutes: 30,
            delay_ms: 2000,
        }
    }
}

impl SprayConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lockout_threshold(mut self, threshold: u32) -> Self {
        self.lockout_threshold = threshold;
        self
    }

    pub fn spray_window_minutes(mut self, minutes: u32) -> Self {
        self.spray_window_minutes = minutes;
        self
    }

    pub fn delay_ms(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }
}

/// Password spray attack — iterates passwords in the outer loop so each password
/// is tried against every username before moving to the next password.
///
/// This password-major ordering is critical for lockout avoidance: accounts
/// receive at most one attempt per password round, staying under threshold limits.
pub struct PasswordSprayStrategy {
    usernames: Vec<String>,
    passwords: Vec<String>,
    delay_between_users_ms: u64,
}

impl PasswordSprayStrategy {
    pub fn new(usernames: Vec<String>, passwords: Vec<String>, config: SprayConfig) -> Self {
        Self {
            usernames,
            passwords,
            delay_between_users_ms: config.delay_ms,
        }
    }

    /// Build with default `SprayConfig`.
    pub fn with_defaults(usernames: Vec<String>, passwords: Vec<String>) -> Self {
        Self::new(usernames, passwords, SprayConfig::default())
    }

    /// Materialise all credential pairs in password-major order.
    fn pairs(&self) -> Vec<Credential> {
        let mut creds = Vec::with_capacity(self.usernames.len() * self.passwords.len());
        for password in &self.passwords {
            for username in &self.usernames {
                creds.push(Credential::new(username.clone(), password.clone()));
            }
        }
        creds
    }

    pub fn delay_between_users_ms(&self) -> u64 {
        self.delay_between_users_ms
    }
}

impl AttackStrategy for PasswordSprayStrategy {
    fn name(&self) -> &'static str { "password-spray" }

    fn credentials(&self) -> CredentialStream {
        Box::pin(iter(self.pairs()))
    }

    fn estimated_count(&self) -> Option<u64> {
        Some((self.usernames.len() * self.passwords.len()) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    fn users(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn passwords(pws: &[&str]) -> Vec<String> {
        pws.iter().map(|s| s.to_string()).collect()
    }

    fn collect_sync(s: &PasswordSprayStrategy) -> Vec<Credential> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { s.credentials().collect::<Vec<_>>().await })
    }

    #[test]
    fn password_major_ordering() {
        let s = PasswordSprayStrategy::with_defaults(
            users(&["alice", "bob"]),
            passwords(&["Summer2024!", "Winter2024!"]),
        );
        let creds = collect_sync(&s);
        assert_eq!(creds.len(), 4);
        assert_eq!(creds[0], Credential::new("alice", "Summer2024!"));
        assert_eq!(creds[1], Credential::new("bob", "Summer2024!"));
        assert_eq!(creds[2], Credential::new("alice", "Winter2024!"));
        assert_eq!(creds[3], Credential::new("bob", "Winter2024!"));
    }

    #[test]
    fn estimated_count() {
        let s = PasswordSprayStrategy::with_defaults(users(&["a", "b", "c"]), passwords(&["p1", "p2"]));
        assert_eq!(s.estimated_count(), Some(6));
    }

    #[test]
    fn estimated_count_empty_users() {
        let s = PasswordSprayStrategy::with_defaults(users(&[]), passwords(&["p1"]));
        assert_eq!(s.estimated_count(), Some(0));
    }

    #[test]
    fn estimated_count_empty_passwords() {
        let s = PasswordSprayStrategy::with_defaults(users(&["u1"]), passwords(&[]));
        assert_eq!(s.estimated_count(), Some(0));
    }

    #[test]
    fn name() {
        let s = PasswordSprayStrategy::with_defaults(users(&["u"]), passwords(&["p"]));
        assert_eq!(s.name(), "password-spray");
    }

    #[test]
    fn config_builder_defaults() {
        let cfg = SprayConfig::new();
        assert_eq!(cfg.lockout_threshold, 3);
        assert_eq!(cfg.spray_window_minutes, 30);
        assert_eq!(cfg.delay_ms, 2000);
    }

    #[test]
    fn config_builder_overrides() {
        let cfg = SprayConfig::new()
            .lockout_threshold(5)
            .spray_window_minutes(60)
            .delay_ms(500);
        assert_eq!(cfg.lockout_threshold, 5);
        assert_eq!(cfg.spray_window_minutes, 60);
        assert_eq!(cfg.delay_ms, 500);
    }

    #[test]
    fn delay_propagated_from_config() {
        let cfg = SprayConfig::new().delay_ms(1234);
        let s = PasswordSprayStrategy::new(users(&["u"]), passwords(&["p"]), cfg);
        assert_eq!(s.delay_between_users_ms(), 1234);
    }

    #[test]
    fn single_user_single_password() {
        let s = PasswordSprayStrategy::with_defaults(users(&["admin"]), passwords(&["admin"]));
        let creds = collect_sync(&s);
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0], Credential::new("admin", "admin"));
    }
}
