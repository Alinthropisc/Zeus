use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZeusError {
    #[error("network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),

    #[error("rate limited by remote")]
    RateLimit,

    #[error("authentication error: {0}")]
    Auth(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("wordlist error: {0}")]
    Wordlist(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn timeout_display() {
        let e = ZeusError::Timeout(Duration::from_secs(5));
        assert!(e.to_string().contains("timeout"));
    }

    #[test]
    fn protocol_error_display() {
        let e = ZeusError::Protocol("bad packet".to_string());
        assert!(e.to_string().contains("bad packet"));
    }

    #[test]
    fn rate_limit_display() {
        let e = ZeusError::RateLimit;
        assert!(e.to_string().contains("rate limit"));
    }

    #[test]
    fn wordlist_error_display() {
        let e = ZeusError::Wordlist("file not found".to_string());
        assert!(e.to_string().contains("wordlist"));
    }
}
