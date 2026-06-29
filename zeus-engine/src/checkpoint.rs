//! Checkpoint / progress persistence — Memento pattern.
//!
//! `AttackCheckpoint` captures all state needed to resume an interrupted attack.
//! `CheckpointManager` auto-saves after every N attempts so data is never lost.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeus_core::Credential;

/// Serialisable snapshot of attack progress (the "memento").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackCheckpoint {
    /// Session identifier.
    pub session_id: String,
    /// Target descriptor: `"host:port:protocol"`.
    pub target: String,
    /// Strategy name (e.g. `"dictionary"`, `"brute_force"`).
    pub strategy: String,
    /// Number of credential attempts completed so far.
    pub attempts_done: u64,
    /// Last credential attempted — resume after this one.
    pub last_credential: Option<Credential>,
    /// Valid credentials discovered so far.
    pub found: Vec<Credential>,
    /// Unix timestamp of when this checkpoint was saved.
    pub saved_at: u64,
    /// Strategy-specific state (e.g. wordlist byte offset, mask position index).
    pub extra: HashMap<String, String>,
}

impl AttackCheckpoint {
    pub fn new(
        session_id: impl Into<String>,
        target: impl Into<String>,
        strategy: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            target: target.into(),
            strategy: strategy.into(),
            attempts_done: 0,
            last_credential: None,
            found: vec![],
            saved_at: now_secs(),
            extra: HashMap::new(),
        }
    }

    /// Record one credential attempt and update the timestamp.
    pub fn record_attempt(&mut self, cred: &Credential) {
        self.attempts_done += 1;
        self.last_credential = Some(cred.clone());
        self.saved_at = now_secs();
    }

    /// Record a successfully-cracked credential.
    pub fn record_found(&mut self, cred: Credential) {
        self.found.push(cred);
    }

    /// Persist this checkpoint to a JSON file.
    pub async fn save(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        tokio::fs::write(path, json).await
    }

    /// Load a checkpoint from a JSON file.
    pub async fn load(
        path: impl AsRef<Path>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let data = tokio::fs::read_to_string(path).await?;
        Ok(serde_json::from_str(&data)?)
    }

    /// Canonical path for a checkpoint identified by `session_id`.
    pub fn default_path(session_id: &str) -> PathBuf {
        PathBuf::from(format!("/tmp/zeus-{}.checkpoint.json", session_id))
    }

    /// How many seconds have elapsed since this checkpoint was saved.
    pub fn age_seconds(&self) -> u64 {
        now_secs().saturating_sub(self.saved_at)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// CheckpointManager — auto-saves every N attempts
// ---------------------------------------------------------------------------

/// Wraps an `AttackCheckpoint` and persists it automatically every `save_every_n`
/// attempts, so a crash loses at most that many credentials of work.
pub struct CheckpointManager {
    checkpoint: AttackCheckpoint,
    path: PathBuf,
    /// Save threshold: persist after this many new attempts since the last save.
    save_every_n: u64,
    /// `attempts_done` value at the time of the last save.
    last_save_at: u64,
}

impl CheckpointManager {
    pub fn new(
        checkpoint: AttackCheckpoint,
        path: impl Into<PathBuf>,
        save_every_n: u64,
    ) -> Self {
        let save_every_n = save_every_n.max(1);
        Self {
            last_save_at: checkpoint.attempts_done,
            checkpoint,
            path: path.into(),
            save_every_n,
        }
    }

    /// Call this after every attempt. Auto-saves when the threshold is reached.
    pub async fn on_attempt(&mut self, cred: &Credential) -> Result<(), std::io::Error> {
        self.checkpoint.record_attempt(cred);
        if self.checkpoint.attempts_done - self.last_save_at >= self.save_every_n {
            self.save().await?;
            self.last_save_at = self.checkpoint.attempts_done;
        }
        Ok(())
    }

    /// Record a found credential (does not trigger a save on its own).
    pub fn on_found(&mut self, cred: Credential) {
        self.checkpoint.record_found(cred);
    }

    /// Force an immediate save.
    pub async fn save(&self) -> Result<(), std::io::Error> {
        self.checkpoint.save(&self.path).await
    }

    /// Read-only access to the underlying checkpoint.
    pub fn checkpoint(&self) -> &AttackCheckpoint {
        &self.checkpoint
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use zeus_core::Credential;

    fn cred(u: &str, p: &str) -> Credential {
        Credential::new(u, p)
    }

    #[test]
    fn checkpoint_new() {
        let cp = AttackCheckpoint::new("sess-1", "host:22:ssh", "dictionary");
        assert_eq!(cp.session_id, "sess-1");
        assert_eq!(cp.target, "host:22:ssh");
        assert_eq!(cp.strategy, "dictionary");
        assert_eq!(cp.attempts_done, 0);
        assert!(cp.last_credential.is_none());
        assert!(cp.found.is_empty());
    }

    #[test]
    fn checkpoint_record_attempt_increments() {
        let mut cp = AttackCheckpoint::new("s", "t", "dict");
        let c = cred("admin", "pass");
        cp.record_attempt(&c);
        assert_eq!(cp.attempts_done, 1);
        assert_eq!(cp.last_credential.as_ref().unwrap().username, "admin");

        cp.record_attempt(&cred("root", "toor"));
        assert_eq!(cp.attempts_done, 2);
        assert_eq!(cp.last_credential.as_ref().unwrap().username, "root");
    }

    #[test]
    fn checkpoint_record_found() {
        let mut cp = AttackCheckpoint::new("s", "t", "dict");
        cp.record_found(cred("admin", "secret"));
        assert_eq!(cp.found.len(), 1);
        assert_eq!(cp.found[0].password, "secret");
    }

    #[test]
    fn checkpoint_age() {
        let cp = AttackCheckpoint::new("s", "t", "dict");
        // freshly created — age should be very small
        assert!(cp.age_seconds() <= 2);
    }

    #[test]
    fn checkpoint_default_path() {
        let p = AttackCheckpoint::default_path("abc-123");
        assert_eq!(p, PathBuf::from("/tmp/zeus-abc-123.checkpoint.json"));
    }

    #[tokio::test]
    async fn checkpoint_manager_auto_save_threshold() {
        use tokio::fs;

        let tmp = format!(
            "/tmp/zeus-test-checkpoint-{}.json",
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        );

        let cp = AttackCheckpoint::new("mgr-test", "h:80:http", "brute");
        let mut mgr = CheckpointManager::new(cp, tmp.clone(), 3);

        // First 2 attempts — should NOT have saved yet.
        mgr.on_attempt(&cred("u", "p1")).await.unwrap();
        mgr.on_attempt(&cred("u", "p2")).await.unwrap();
        assert!(!std::path::Path::new(&tmp).exists());

        // Third attempt triggers auto-save.
        mgr.on_attempt(&cred("u", "p3")).await.unwrap();
        assert!(std::path::Path::new(&tmp).exists());
        assert_eq!(mgr.checkpoint().attempts_done, 3);

        // Clean up.
        let _ = fs::remove_file(&tmp).await;
    }
}
