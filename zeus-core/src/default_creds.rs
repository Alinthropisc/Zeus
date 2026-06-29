//! Default credentials database.
//!
//! Provides a searchable in-memory repository of well-known vendor default
//! credentials.  Implements the **Repository** pattern for storage and the
//! **Specification** pattern for querying.

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Service identifier with an optional version pattern.
#[derive(Debug, Clone)]
pub struct ServiceVersion {
    /// Service name, lower-case (e.g. `"ssh"`, `"tomcat"`).
    pub service: String,
    /// Optional glob-style version pattern.
    ///
    /// * `Some("7.*")` — matches any 7.x version.
    /// * `Some("8.0")` — exact match.
    /// * `None` — matches any version.
    pub version_pattern: Option<String>,
}

impl ServiceVersion {
    /// Returns `true` if `version` matches this entry's pattern.
    pub fn matches_version(&self, version: Option<&str>) -> bool {
        match (&self.version_pattern, version) {
            (None, _) => true,
            (Some(_), None) => true, // pattern present but no version supplied → assume match
            (Some(pat), Some(ver)) => {
                if pat.ends_with(".*") {
                    let prefix = pat.trim_end_matches(".*");
                    ver.starts_with(prefix)
                } else {
                    pat == ver
                }
            }
        }
    }
}

/// A single default credential entry.
#[derive(Debug, Clone)]
pub struct DefaultCredEntry {
    /// Service this credential applies to.
    pub service_version: ServiceVersion,
    /// Default username.
    pub username: String,
    /// Default password.
    pub password: String,
    /// Where this credential was documented.
    pub source: &'static str,
    /// CVSS v3 score if a CVE exists for this default credential.
    pub cvss_score: Option<f32>,
}

impl DefaultCredEntry {
    fn new(
        service: &str,
        version_pattern: Option<&str>,
        username: &str,
        password: &str,
        source: &'static str,
        cvss_score: Option<f32>,
    ) -> Self {
        Self {
            service_version: ServiceVersion {
                service: service.to_lowercase(),
                version_pattern: version_pattern.map(str::to_string),
            },
            username: username.to_string(),
            password: password.to_string(),
            source,
            cvss_score,
        }
    }
}

// ---------------------------------------------------------------------------
// Repository trait
// ---------------------------------------------------------------------------

/// Repository interface for accessing the default credentials database.
pub trait DefaultCredsRepository: Send + Sync {
    /// Look up credentials by service name and optional version string.
    fn lookup(&self, service: &str, version: Option<&str>) -> Vec<&DefaultCredEntry>;

    /// Look up credentials by matching service name against a banner string.
    fn lookup_by_banner(&self, banner: &str) -> Vec<&DefaultCredEntry>;

    /// Return every entry in the repository.
    fn all(&self) -> &[DefaultCredEntry];
}

// ---------------------------------------------------------------------------
// InMemoryDefaultCredsRepo
// ---------------------------------------------------------------------------

/// In-memory repository pre-loaded with 50+ real-world default credentials.
pub struct InMemoryDefaultCredsRepo {
    entries: Vec<DefaultCredEntry>,
}

impl InMemoryDefaultCredsRepo {
    /// Create a repository loaded with built-in default credentials.
    pub fn with_builtin() -> Self {
        let e = DefaultCredEntry::new;
        let vd = "vendor_docs";
        let _cv = "cve";
        let cm = "community";

        let entries = vec![
            // SSH
            e("ssh", None, "root", "root", vd, None),
            e("ssh", None, "root", "", vd, None),
            e("ssh", None, "admin", "admin", vd, None),
            e("ssh", None, "admin", "password", vd, None),
            e("ssh", None, "ubnt", "ubnt", vd, Some(9.8)),
            e("ssh", None, "pi", "raspberry", vd, Some(9.8)),
            // FTP
            e("ftp", None, "anonymous", "", vd, None),
            e("ftp", None, "anonymous", "anonymous", vd, None),
            e("ftp", None, "admin", "admin", vd, None),
            e("ftp", None, "ftp", "ftp", vd, None),
            // HTTP / admin panels
            e("http", None, "admin", "admin", vd, None),
            e("http", None, "admin", "password", vd, None),
            e("http", None, "admin", "", vd, None),
            e("http", None, "admin", "1234", vd, None),
            e("http", None, "admin", "admin123", cm, None),
            e("http", None, "user", "user", vd, None),
            e("http", None, "guest", "guest", vd, None),
            // MySQL
            e("mysql", None, "root", "", vd, None),
            e("mysql", None, "root", "root", vd, None),
            e("mysql", None, "root", "mysql", vd, None),
            // PostgreSQL
            e("postgresql", None, "postgres", "postgres", vd, None),
            e("postgresql", None, "postgres", "", vd, None),
            e("postgresql", None, "admin", "admin", vd, None),
            // Redis
            e("redis", None, "", "", vd, Some(9.8)),
            e("redis", None, "default", "", vd, Some(9.8)),
            // MongoDB
            e("mongodb", None, "", "", vd, Some(9.8)),
            e("mongodb", None, "admin", "admin", vd, None),
            // Telnet
            e("telnet", None, "admin", "admin", vd, None),
            e("telnet", None, "root", "root", vd, None),
            e("telnet", None, "", "", vd, None),
            // SNMP (community strings as passwords)
            e("snmp", None, "public", "public", vd, None),
            e("snmp", None, "private", "private", vd, None),
            e("snmp", None, "manager", "manager", vd, None),
            // RDP
            e("rdp", None, "administrator", "password", vd, None),
            e("rdp", None, "administrator", "Password123", cm, None),
            e("rdp", None, "admin", "admin", vd, None),
            // VNC
            e("vnc", None, "", "password", vd, None),
            e("vnc", None, "", "1234", vd, None),
            e("vnc", None, "", "", vd, None),
            // Apache Tomcat
            e("tomcat", Some("9.*"), "tomcat", "tomcat", vd, Some(7.5)),
            e("tomcat", Some("8.*"), "admin", "admin", vd, Some(7.5)),
            e("tomcat", None, "admin", "tomcat", vd, None),
            e("tomcat", None, "manager", "manager", vd, None),
            // Jenkins
            e("jenkins", None, "admin", "admin", vd, None),
            e("jenkins", None, "jenkins", "jenkins", cm, None),
            e("jenkins", None, "admin", "password", cm, None),
            // Cisco IOS / IOS-XE
            e("cisco", None, "cisco", "cisco", vd, None),
            e("cisco", None, "admin", "cisco", vd, None),
            e("cisco", None, "cisco", "Cisco", vd, None),
            e("cisco", None, "enable", "enable", vd, None),
            // MikroTik RouterOS
            e("mikrotik", None, "admin", "", vd, Some(9.8)),
            e("mikrotik", None, "admin", "admin", vd, None),
            // Netgear
            e("netgear", None, "admin", "password", vd, None),
            e("netgear", None, "admin", "1234", vd, None),
            // D-Link
            e("dlink", None, "admin", "", vd, Some(9.8)),
            e("dlink", None, "admin", "admin", vd, None),
            e("dlink", None, "Admin", "Admin", vd, None),
            // Generic admin panel fall-backs
            e("panel", None, "admin", "admin", cm, None),
            e("panel", None, "root", "toor", cm, None),
        ];

        Self { entries }
    }
}

impl DefaultCredsRepository for InMemoryDefaultCredsRepo {
    fn lookup(&self, service: &str, version: Option<&str>) -> Vec<&DefaultCredEntry> {
        let service_lower = service.to_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                e.service_version.service == service_lower
                    && e.service_version.matches_version(version)
            })
            .collect()
    }

    fn lookup_by_banner(&self, banner: &str) -> Vec<&DefaultCredEntry> {
        let banner_lower = banner.to_lowercase();
        self.entries
            .iter()
            .filter(|e| banner_lower.contains(&e.service_version.service))
            .collect()
    }

    fn all(&self) -> &[DefaultCredEntry] {
        &self.entries
    }
}

// ---------------------------------------------------------------------------
// Specification pattern
// ---------------------------------------------------------------------------

/// Query specification for filtering default credential entries.
#[derive(Debug, Default)]
pub struct DefaultCredsSpec {
    /// Restrict to entries for this service name (case-insensitive).
    pub service: Option<String>,
    /// Exclude entries with CVSS score below this threshold.
    pub min_cvss: Option<f32>,
    /// Restrict to entries from these source labels.
    pub source_filter: Option<Vec<&'static str>>,
}

impl DefaultCredsSpec {
    /// Returns `true` if `entry` satisfies all constraints in this specification.
    pub fn matches(&self, entry: &DefaultCredEntry) -> bool {
        if let Some(ref svc) = self.service
            && entry.service_version.service != svc.to_lowercase()
        {
            return false;
        }
        if let Some(min) = self.min_cvss {
            match entry.cvss_score {
                None => return false,
                Some(score) if score < min => return false,
                _ => {}
            }
        }
        if let Some(ref sources) = self.source_filter
            && !sources.contains(&entry.source)
        {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> InMemoryDefaultCredsRepo {
        InMemoryDefaultCredsRepo::with_builtin()
    }

    #[test]
    fn builtin_has_at_least_40_entries() {
        assert!(repo().all().len() >= 40);
    }

    #[test]
    fn lookup_ssh_returns_entries() {
        let r = repo();
        let hits = r.lookup("ssh", None);
        assert!(!hits.is_empty());
        assert!(
            hits.iter()
                .any(|e| e.username == "root" && e.password == "root")
        );
    }

    #[test]
    fn lookup_by_banner_matches_service_substring() {
        let r = repo();
        let hits = r.lookup_by_banner("OpenSSH 8.4 running on Linux");
        assert!(!hits.is_empty());
    }

    #[test]
    fn spec_filters_by_min_cvss() {
        let r = repo();
        let spec = DefaultCredsSpec {
            min_cvss: Some(9.0),
            ..Default::default()
        };
        let matching: Vec<_> = r.all().iter().filter(|e| spec.matches(e)).collect();
        assert!(matching.iter().all(|e| e.cvss_score.unwrap_or(0.0) >= 9.0));
        assert!(!matching.is_empty());
    }

    #[test]
    fn spec_filters_by_service() {
        let r = repo();
        let spec = DefaultCredsSpec {
            service: Some("tomcat".into()),
            ..Default::default()
        };
        let matching: Vec<_> = r.all().iter().filter(|e| spec.matches(e)).collect();
        assert!(
            matching
                .iter()
                .all(|e| e.service_version.service == "tomcat")
        );
        assert!(!matching.is_empty());
    }

    #[test]
    fn spec_filters_by_source() {
        let r = repo();
        let spec = DefaultCredsSpec {
            source_filter: Some(vec!["cve"]),
            ..Default::default()
        };
        let matching: Vec<_> = r.all().iter().filter(|e| spec.matches(e)).collect();
        assert!(matching.iter().all(|e| e.source == "cve"));
    }

    #[test]
    fn version_pattern_wildcard_matches() {
        let sv = ServiceVersion {
            service: "tomcat".into(),
            version_pattern: Some("9.*".into()),
        };
        assert!(sv.matches_version(Some("9.0.65")));
        assert!(!sv.matches_version(Some("8.5.1")));
    }

    #[test]
    fn version_pattern_none_matches_any() {
        let sv = ServiceVersion {
            service: "ssh".into(),
            version_pattern: None,
        };
        assert!(sv.matches_version(None));
        assert!(sv.matches_version(Some("7.4")));
    }

    #[test]
    fn lookup_redis_empty_password() {
        let r = repo();
        let hits = r.lookup("redis", None);
        assert!(hits.iter().any(|e| e.password.is_empty()));
    }
}
