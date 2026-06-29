use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

impl Credential {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    pub fn from_colon_str(s: &str) -> Option<Self> {
        let (u, p) = s.split_once(':')?;
        Some(Self::new(u, p))
    }
}

impl fmt::Display for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.username, self.password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_colon_str() {
        let c = Credential::from_colon_str("admin:secret").unwrap();
        assert_eq!(c.username, "admin");
        assert_eq!(c.password, "secret");
    }

    #[test]
    fn parse_missing_colon() {
        assert!(Credential::from_colon_str("nocolon").is_none());
    }

    #[test]
    fn display_format() {
        let c = Credential::new("root", "toor");
        assert_eq!(c.to_string(), "root:toor");
    }
}
