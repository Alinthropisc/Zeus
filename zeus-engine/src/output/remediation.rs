//! Static remediation database keyed by [`FindingCategory`].

use std::collections::HashMap;

use crate::finding::FindingCategory;

/// Provides pre-built remediation advice for every known finding category.
pub struct RemediationDb {
    map: HashMap<FindingCategory, &'static str>,
}

impl RemediationDb {
    /// Construct the database with all known remediations pre-filled.
    pub fn new() -> Self {
        let mut map = HashMap::new();

        map.insert(
            FindingCategory::TimingSideChannel,
            "Enforce constant-time comparisons in auth code. \
             Replace variable-time string equality checks with a \
             HMAC-based or constant-time library function (e.g. \
             `subtle::ConstantTimeEq`). Apply to password, token, \
             and CSRF comparisons.",
        );

        map.insert(
            FindingCategory::WeakAuthentication,
            "Add device fingerprint and geo-velocity checks to the \
             authentication pipeline. Implement account lockout with \
             progressive backoff (e.g. 5 failures → 30-second cooldown). \
             Enforce MFA for privileged accounts. Consider adaptive risk \
             scoring (IP reputation, user-agent anomaly).",
        );

        map.insert(
            FindingCategory::ProtocolWeakness,
            "Upgrade the protocol to the latest secure version \
             (TLS 1.3, SSH v2, HTTP/2 with HSTS). Disable deprecated \
             cipher suites, export-grade ciphers, and NULL/anonymous \
             key-exchange. Enforce certificate pinning for mobile clients.",
        );

        map.insert(
            FindingCategory::WafBypass,
            "Harden WAF rule sets to cover Unicode normalisation \
             and double-URL-encoding bypass vectors. Enable anomaly \
             scoring mode instead of rule-match-only mode. Supplement \
             the WAF with server-side input validation and parameterised \
             queries to ensure defence in depth.",
        );

        map.insert(
            FindingCategory::NetworkExposure,
            "Remove or restrict publicly exposed administrative interfaces \
             (e.g. management APIs, debug endpoints, internal health \
             checks). Apply network segmentation and firewall rules to \
             allow access only from known management CIDR ranges. \
             Implement mTLS for service-to-service communication.",
        );

        map.insert(
            FindingCategory::MisconfiguredService,
            "Review service configuration against the vendor security \
             baseline or CIS benchmark. Disable default credentials, \
             unnecessary features, and open CORS policies. Ensure \
             secrets are not present in environment dumps, debug pages, \
             or error messages. Automate configuration drift detection.",
        );

        Self { map }
    }

    /// Look up the remediation advice for a given category.
    ///
    /// Returns a generic fallback string if no specific advice is registered.
    pub fn suggest(&self, category: &FindingCategory) -> &'static str {
        self.map.get(category).copied().unwrap_or(
            "Apply vendor security hardening guidelines and review the \
             finding against OWASP/NIST recommendations.",
        )
    }
}

impl Default for RemediationDb {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_categories_have_advice() {
        let db = RemediationDb::new();
        let categories = [
            FindingCategory::TimingSideChannel,
            FindingCategory::WeakAuthentication,
            FindingCategory::ProtocolWeakness,
            FindingCategory::WafBypass,
            FindingCategory::NetworkExposure,
            FindingCategory::MisconfiguredService,
        ];

        for cat in &categories {
            let advice = db.suggest(cat);
            assert!(
                !advice.is_empty(),
                "expected non-empty advice for {cat:?}"
            );
        }
    }
}
