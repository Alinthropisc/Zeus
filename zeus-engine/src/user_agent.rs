/// Pool of realistic User-Agent strings
pub struct UserAgentPool {
    agents: Vec<String>,
    index: usize,
    rotate: bool,
}

impl UserAgentPool {
    pub fn new(agents: Vec<String>, rotate: bool) -> Self {
        Self { agents, index: 0, rotate }
    }

    /// Chrome + Firefox + Edge on Windows/Mac/Linux
    pub fn modern_browsers() -> Self {
        Self::new(vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0".into(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0".into(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15".into(),
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0".into(),
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1".into(),
        ], true)
    }

    pub fn single(ua: impl Into<String>) -> Self {
        Self::new(vec![ua.into()], false)
    }

    /// Get next User-Agent (round-robin if rotate=true)
    pub fn next(&mut self) -> &str {
        if self.agents.is_empty() {
            return "Zeus/1.0";
        }
        let ua = &self.agents[self.index % self.agents.len()];
        if self.rotate {
            self.index = (self.index + 1) % self.agents.len();
        }
        ua
    }

    pub fn len(&self) -> usize { self.agents.len() }
    pub fn is_empty(&self) -> bool { self.agents.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ua_pool_rotate() {
        let mut pool = UserAgentPool::modern_browsers();
        let len = pool.len();
        let first = pool.next().to_string();
        // Advance through all agents
        for _ in 1..len {
            pool.next();
        }
        // After len() calls, the next one should wrap back to first
        assert_eq!(pool.next(), first.as_str(), "pool should wrap around after len() calls");
    }

    #[test]
    fn ua_pool_no_rotate() {
        let mut pool = UserAgentPool::single("TestBot/1.0");
        let first = pool.next().to_string();
        for _ in 0..5 {
            assert_eq!(pool.next(), first.as_str(), "non-rotating pool should always return same UA");
        }
    }

    #[test]
    fn ua_pool_modern_browsers_not_empty() {
        let pool = UserAgentPool::modern_browsers();
        assert!(!pool.is_empty());
        assert!(pool.len() >= 4);
    }

    #[test]
    fn ua_pool_single() {
        let ua = "CustomAgent/2.0 (test)";
        let mut pool = UserAgentPool::single(ua);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.next(), ua);
    }

    #[test]
    fn ua_pool_empty_returns_default() {
        let mut pool = UserAgentPool::new(vec![], true);
        assert_eq!(pool.next(), "Zeus/1.0");
        assert!(pool.is_empty());
    }
}
