//! OSINT-based wordlist generator.
//!
//! Uses public information about a target (domain, company name, keywords, year)
//! to generate a context-aware password wordlist. Implements the **Builder** pattern
//! for configuration and the **Strategy** pattern for pluggable data sources.

use crate::credential::Credential;

// ---------------------------------------------------------------------------
// TargetInfo
// ---------------------------------------------------------------------------

/// Publicly-available information about the target organisation used to
/// generate contextual passwords.
#[derive(Debug, Clone, Default)]
pub struct TargetInfo {
    /// Primary domain name (e.g. `"example.com"`).
    pub domain: Option<String>,
    /// Company or organisation name.
    pub company_name: Option<String>,
    /// Reference year for year-based mutations (defaults to `2024`).
    pub year: u32,
    /// Arbitrary keywords (product names, locations, nicknames, …).
    pub keywords: Vec<String>,
}

// ---------------------------------------------------------------------------
// OsintSource — Strategy pattern
// ---------------------------------------------------------------------------

/// Strategy interface for a single OSINT data source.
///
/// Each implementation extracts candidate password bases from the provided
/// [`TargetInfo`] and returns raw strings.  Mutations are applied later by
/// [`OsintWordlist`].
pub trait OsintSource: Send + Sync {
    /// Human-readable name of this source.
    fn name(&self) -> &'static str;
    /// Extract candidate base words from `target_info`.
    fn extract(&self, target_info: &TargetInfo) -> Vec<String>;
}

// ---------------------------------------------------------------------------
// Concrete sources
// ---------------------------------------------------------------------------

/// Derives base words from the target's domain name.
///
/// `"example.com"` → `["example"]`
pub struct DomainSource;

impl OsintSource for DomainSource {
    fn name(&self) -> &'static str { "domain" }

    fn extract(&self, info: &TargetInfo) -> Vec<String> {
        let Some(ref domain) = info.domain else { return vec![] };
        // Strip TLD — take the part before the first dot.
        let base = domain.split('.').next().unwrap_or(domain.as_str());
        vec![base.to_string()]
    }
}

/// Derives base words from the company or organisation name.
///
/// Handles multi-word names by also producing a concatenated form.
pub struct CompanyNameSource;

impl OsintSource for CompanyNameSource {
    fn name(&self) -> &'static str { "company_name" }

    fn extract(&self, info: &TargetInfo) -> Vec<String> {
        let Some(ref name) = info.company_name else { return vec![] };
        let mut bases = vec![name.clone()];
        // Also add a lowercase, whitespace-stripped concatenation.
        let compact: String = name.split_whitespace().collect::<String>().to_lowercase();
        if compact != name.to_lowercase() {
            bases.push(compact);
        }
        bases
    }
}

/// Produces base words from the caller-supplied keyword list.
pub struct KeywordSource;

impl OsintSource for KeywordSource {
    fn name(&self) -> &'static str { "keywords" }

    fn extract(&self, info: &TargetInfo) -> Vec<String> {
        info.keywords.clone()
    }
}

// ---------------------------------------------------------------------------
// Mutation helpers
// ---------------------------------------------------------------------------

/// Generate common password mutations from a single base word.
///
/// Mutations produced:
/// * lowercase original
/// * Capitalised
/// * UPPERCASE
/// * base + "123"
/// * base + year
/// * base + "!"
/// * base + "@" + year
/// * base + "#1"
/// * Capitalised + "123!"
/// * "_" + base + "_"
/// * base + "_admin"
fn mutate(base: &str, year: u32) -> Vec<String> {
    let lower = base.to_lowercase();
    let upper = base.to_uppercase();
    let capitalised = {
        let mut c = base.chars();
        match c.next() {
            None => String::new(),
            Some(f) => f.to_uppercase().to_string() + c.as_str(),
        }
    };

    vec![
        lower.clone(),
        capitalised.clone(),
        upper,
        format!("{}123", lower),
        format!("{}{}", lower, year),
        format!("{}!", lower),
        format!("{}@{}", lower, year),
        format!("{}#1", lower),
        format!("{}123!", capitalised),
        format!("_{}_", lower),
        format!("{}_admin", lower),
    ]
}

// ---------------------------------------------------------------------------
// OsintWordlist
// ---------------------------------------------------------------------------

/// An iterable password wordlist produced from OSINT sources.
#[derive(Debug, Default)]
pub struct OsintWordlist {
    words: Vec<String>,
}

impl OsintWordlist {
    /// Returns a slice of all generated words.
    pub fn words(&self) -> &[String] {
        &self.words
    }

    /// Combine each word with each username to create [`Credential`] pairs.
    pub fn to_credentials(&self, usernames: &[String]) -> Vec<Credential> {
        usernames
            .iter()
            .flat_map(|u| {
                self.words
                    .iter()
                    .map(move |p| Credential::new(u.clone(), p.clone()))
            })
            .collect()
    }

    /// Remove duplicate entries in-place and return the number of removed items.
    pub fn dedup(&mut self) -> usize {
        let before = self.words.len();
        self.words.sort_unstable();
        self.words.dedup();
        before - self.words.len()
    }
}

// ---------------------------------------------------------------------------
// OsintWordlistBuilder — Builder pattern
// ---------------------------------------------------------------------------

/// Fluent builder for configuring and constructing an [`OsintWordlist`].
///
/// # Example
/// ```
/// use zeus_core::osint_wordlist::OsintWordlistBuilder;
///
/// let mut list = OsintWordlistBuilder::new()
///     .with_domain("acme.com")
///     .with_company("Acme Corp")
///     .with_year(2024)
///     .with_keyword("rocket")
///     .build();
///
/// list.dedup();
/// assert!(!list.words().is_empty());
/// ```
pub struct OsintWordlistBuilder {
    info: TargetInfo,
    extra_sources: Vec<Box<dyn OsintSource>>,
}

impl OsintWordlistBuilder {
    /// Create a new builder with default built-in sources.
    pub fn new() -> Self {
        Self {
            info: TargetInfo {
                year: 2024,
                ..Default::default()
            },
            extra_sources: vec![],
        }
    }

    /// Set the target domain (e.g. `"example.com"`).
    pub fn with_domain(mut self, domain: &str) -> Self {
        self.info.domain = Some(domain.to_string());
        self
    }

    /// Set the company / organisation name.
    pub fn with_company(mut self, name: &str) -> Self {
        self.info.company_name = Some(name.to_string());
        self
    }

    /// Set the reference year used in mutations.
    pub fn with_year(mut self, year: u32) -> Self {
        self.info.year = year;
        self
    }

    /// Append an additional keyword.
    pub fn with_keyword(mut self, kw: &str) -> Self {
        self.info.keywords.push(kw.to_string());
        self
    }

    /// Register an additional [`OsintSource`] strategy.
    pub fn add_source(mut self, src: Box<dyn OsintSource>) -> Self {
        self.extra_sources.push(src);
        self
    }

    /// Build and return the [`OsintWordlist`].
    pub fn build(self) -> OsintWordlist {
        let mut words: Vec<String> = Vec::new();
        let year = self.info.year;

        // Built-in sources.
        let builtin: Vec<Box<dyn OsintSource>> = vec![
            Box::new(DomainSource),
            Box::new(CompanyNameSource),
            Box::new(KeywordSource),
        ];

        for source in builtin.iter().chain(self.extra_sources.iter()) {
            for base in source.extract(&self.info) {
                words.extend(mutate(&base, year));
            }
        }

        OsintWordlist { words }
    }
}

impl Default for OsintWordlistBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_source_strips_tld() {
        let src = DomainSource;
        let info = TargetInfo { domain: Some("acme.com".into()), year: 2024, ..Default::default() };
        let bases = src.extract(&info);
        assert_eq!(bases, vec!["acme"]);
    }

    #[test]
    fn company_source_produces_compact_form() {
        let src = CompanyNameSource;
        let info = TargetInfo {
            company_name: Some("Acme Corp".into()),
            year: 2024,
            ..Default::default()
        };
        let bases = src.extract(&info);
        assert!(bases.contains(&"Acme Corp".to_string()));
        assert!(bases.contains(&"acmecorp".to_string()));
    }

    #[test]
    fn keyword_source_returns_all_keywords() {
        let src = KeywordSource;
        let info = TargetInfo {
            keywords: vec!["rocket".into(), "falcon".into()],
            year: 2024,
            ..Default::default()
        };
        let bases = src.extract(&info);
        assert_eq!(bases, vec!["rocket", "falcon"]);
    }

    #[test]
    fn builder_generates_mutations_for_domain() {
        let list = OsintWordlistBuilder::new()
            .with_domain("example.com")
            .with_year(2025)
            .build();

        let words = list.words();
        assert!(words.contains(&"example".to_string()));
        assert!(words.contains(&"example2025".to_string()));
        assert!(words.contains(&"example!".to_string()));
        assert!(words.contains(&"example@2025".to_string()));
        assert!(words.contains(&"example_admin".to_string()));
    }

    #[test]
    fn dedup_removes_duplicates() {
        let mut list = OsintWordlistBuilder::new()
            .with_keyword("admin")
            .with_keyword("admin") // duplicate keyword → duplicate mutations
            .build();
        let before = list.words().len();
        let removed = list.dedup();
        assert!(removed > 0);
        assert_eq!(list.words().len(), before - removed);
    }

    #[test]
    fn to_credentials_cross_product() {
        let list = OsintWordlistBuilder::new()
            .with_keyword("pass")
            .build();
        let usernames = vec!["admin".to_string(), "root".to_string()];
        let creds = list.to_credentials(&usernames);
        // Each username × each word.
        assert_eq!(creds.len(), usernames.len() * list.words().len());
    }

    #[test]
    fn custom_source_plugged_in_via_add_source() {
        struct StaticSource;
        impl OsintSource for StaticSource {
            fn name(&self) -> &'static str { "static" }
            fn extract(&self, _: &TargetInfo) -> Vec<String> {
                vec!["custom_base".to_string()]
            }
        }

        let list = OsintWordlistBuilder::new()
            .add_source(Box::new(StaticSource))
            .build();

        assert!(list.words().contains(&"custom_base".to_string()));
    }

    #[test]
    fn capitalised_mutation_is_generated() {
        let list = OsintWordlistBuilder::new().with_keyword("hello").build();
        assert!(list.words().contains(&"Hello123!".to_string()));
    }
}
