use std::io::{self, BufRead, BufReader};
use std::path::Path;
use zeus_core::{Credential, ZeusError};

/// In-memory wordlist (passwords or user:pass pairs).
pub struct Wordlist {
    entries: Vec<String>,
}

impl Wordlist {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ZeusError> {
        let file = std::fs::File::open(path)
            .map_err(|e| ZeusError::Wordlist(e.to_string()))?;
        let reader = BufReader::new(file);
        let entries: Vec<String> = reader
            .lines()
            .filter_map(|l| l.ok())
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .collect();
        Ok(Self { entries })
    }

    pub async fn from_file_async(path: &str) -> anyhow::Result<Self> {
        use tokio::io::AsyncBufReadExt;
        let file = tokio::fs::File::open(path).await?;
        let reader = tokio::io::BufReader::new(file);
        let mut lines = reader.lines();
        let mut entries = Vec::new();
        while let Some(line) = lines.next_line().await? {
            let trimmed = line.trim().to_owned();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                entries.push(trimmed);
            }
        }
        Ok(Self { entries })
    }

    pub fn from_stdin() -> anyhow::Result<Self> {
        let stdin = io::stdin();
        let entries: Vec<String> = stdin
            .lock()
            .lines()
            .filter_map(|l| l.ok())
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .collect();
        Ok(Self { entries })
    }

    pub fn built_in(name: &str) -> Option<Self> {
        let entries: Vec<&str> = match name {
            "top10" => vec![
                "123456", "password", "admin", "root", "letmein",
                "qwerty", "abc123", "monkey", "1234567890", "password1",
            ],
            "top25" => vec![
                "123456", "password", "admin", "root", "letmein",
                "qwerty", "abc123", "monkey", "1234567890", "password1",
                "iloveyou", "111111", "dragon", "master", "sunshine",
                "princess", "welcome", "shadow", "superman", "michael",
                "football", "pass", "login", "654321", "mustang",
            ],
            "rockyou_top100" => vec![
                "123456", "12345", "123456789", "password", "iloveyou",
                "princess", "1234567", "rockyou", "12345678", "abc123",
                "nicole", "daniel", "babygirl", "monkey", "jessica",
                "lovely", "michael", "ashley", "654321", "qwerty",
                "password1", "111111", "iloveu", "000000", "michelle",
                "tigger", "sunshine", "chocolate", "password123", "donald",
                "soccer", "batman", "access", "shadow", "master",
                "michael1", "superman", "696969", "123123", "fuckyou",
                "fuckyou1", "password2", "trustno1", "ranger", "buster",
                "thomas", "robert", "hockey", "killer", "george",
                "charlie", "andrew", "michelle1", "love", "joshua",
                "lakers", "jessica1", "letmein", "whatever", "hello",
                "steven", "viking", "cheese", "pepper", "zxcvbn",
                "hannah", "victoria", "welcome", "enter", "christian",
                "james", "mother", "tiger", "danielle", "carlos",
                "linkinpark", "justin", "snoopy", "butter", "junior",
                "1234", "abc", "password3", "test", "12345679",
                "apple", "jennifer", "maverick", "secret", "pass",
                "passw0rd", "abcdef", "hello123", "1q2w3e", "biteme",
                "login", "ncc1701", "magic", "merlin", "princess1",
                "driver", "12qwaszx", "beer", "hunter",
            ],
            _ => return None,
        };
        Some(Self {
            entries: entries.iter().map(|s| s.to_string()).collect(),
        })
    }

    pub fn from_vec(entries: Vec<String>) -> Self {
        Self { entries }
    }

    pub fn passwords(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(String::as_str)
    }

    pub fn credentials(&self, username: &str) -> impl Iterator<Item = Credential> + '_ {
        let user = username.to_owned();
        self.entries.iter().map(move |p| Credential::new(user.clone(), p.clone()))
    }

    pub fn credential_pairs(&self) -> impl Iterator<Item = Credential> + '_ {
        self.entries.iter().filter_map(|s| Credential::from_colon_str(s))
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

impl IntoIterator for Wordlist {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_iter() {
        let wl = Wordlist::from_vec(vec!["pass1".into(), "pass2".into()]);
        let v: Vec<_> = wl.passwords().collect();
        assert_eq!(v, vec!["pass1", "pass2"]);
    }

    #[test]
    fn credential_pairs() {
        let wl = Wordlist::from_vec(vec!["admin:admin".into(), "root:toor".into()]);
        let pairs: Vec<_> = wl.credential_pairs().collect();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].username, "admin");
    }

    #[test]
    fn built_in_top10_has_ten_words() {
        let wl = Wordlist::built_in("top10").expect("top10 should exist");
        assert_eq!(wl.len(), 10);
        assert!(wl.passwords().any(|p| p == "123456"));
    }

    #[test]
    fn built_in_unknown_returns_none() {
        assert!(Wordlist::built_in("nonexistent_wordlist").is_none());
    }

    #[test]
    fn built_in_top25_has_twenty_five_words() {
        let wl = Wordlist::built_in("top25").expect("top25 should exist");
        assert_eq!(wl.len(), 25);
    }

    #[test]
    fn built_in_rockyou_top100_has_hundred_words() {
        let wl = Wordlist::built_in("rockyou_top100").expect("rockyou_top100 should exist");
        assert!(wl.len() >= 100);
    }
}
