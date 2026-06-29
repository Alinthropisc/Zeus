use crate::{AttackStrategy, CredentialStream};
use tokio_stream::iter;
use zeus_core::Credential;

#[derive(Debug, Clone, Default)]
pub struct TargetContext {
    pub company: Option<String>,
    pub domain: Option<String>,
    pub year: u32,
    pub employee_names: Vec<String>,
    pub keywords: Vec<String>,
}

impl TargetContext {
    pub fn new() -> Self {
        Self {
            year: 2024,
            ..Default::default()
        }
    }
}

pub trait MutationRule: Send + Sync {
    fn name(&self) -> &'static str;
    fn apply(&self, base: &str, ctx: &TargetContext) -> Vec<String>;
}

// ─── Concrete rules ────────────────────────────────────────────────────────────

pub struct YearSuffixRule;

impl MutationRule for YearSuffixRule {
    fn name(&self) -> &'static str { "year-suffix" }

    fn apply(&self, base: &str, ctx: &TargetContext) -> Vec<String> {
        let y = ctx.year;
        vec![
            format!("{}{}", base, y),
            format!("{}{}", base, y.saturating_sub(1)),
            format!("{}{}", base, y + 1),
        ]
    }
}

pub struct SpecialCharRule;

impl MutationRule for SpecialCharRule {
    fn name(&self) -> &'static str { "special-char" }

    fn apply(&self, base: &str, _ctx: &TargetContext) -> Vec<String> {
        let cap = capitalize(base);
        let upper = base.to_uppercase();
        vec![
            format!("{}!", base),
            format!("{}@", base),
            format!("{}#", base),
            format!("{}!", cap),
            format!("{}!", upper),
        ]
    }
}

pub struct LeetSpeakRule;

impl MutationRule for LeetSpeakRule {
    fn name(&self) -> &'static str { "leet-speak" }

    fn apply(&self, base: &str, _ctx: &TargetContext) -> Vec<String> {
        // a→@, e→3, i→1, o→0, s→$
        let mut results = std::collections::HashSet::new();

        // single-substitution variants
        let subs: &[(char, char)] = &[('a', '@'), ('e', '3'), ('i', '1'), ('o', '0'), ('s', '$')];
        for &(from, to) in subs {
            let variant = base
                .chars()
                .map(|c| if c.to_ascii_lowercase() == from { to } else { c })
                .collect::<String>();
            if variant != base {
                results.insert(variant);
            }
        }

        // all-at-once substitution
        let all = base
            .chars()
            .map(|c| match c.to_ascii_lowercase() {
                'a' => '@',
                'e' => '3',
                'i' => '1',
                'o' => '0',
                's' => '$',
                _ => c,
            })
            .collect::<String>();
        if all != base {
            results.insert(all);
        }

        results.into_iter().collect()
    }
}

pub struct CompanyContextRule;

impl MutationRule for CompanyContextRule {
    fn name(&self) -> &'static str { "company-context" }

    fn apply(&self, base: &str, ctx: &TargetContext) -> Vec<String> {
        let Some(company) = &ctx.company else {
            return Vec::new();
        };
        let co = company.to_lowercase();
        let co_cap = capitalize(company);
        vec![
            format!("{}{}", co, base),
            format!("{}_{}", base, co),
            format!("{}_{}", co_cap, base),
            format!("{}@{}", base, co_cap),
        ]
    }
}

pub struct KeyboardWalkRule;

impl MutationRule for KeyboardWalkRule {
    fn name(&self) -> &'static str { "keyboard-walk" }

    fn apply(&self, base: &str, _ctx: &TargetContext) -> Vec<String> {
        vec![
            format!("{}123", base),
            format!("{}1234", base),
            format!("{}12345", base),
            format!("{}!@#", base),
        ]
    }
}

pub struct CaseMixRule;

impl MutationRule for CaseMixRule {
    fn name(&self) -> &'static str { "case-mix" }

    fn apply(&self, base: &str, _ctx: &TargetContext) -> Vec<String> {
        let cap = capitalize(base);
        let upper = base.to_uppercase();
        // bASE: first char lower, rest upper
        let inverted = {
            let mut chars = base.chars();
            match chars.next() {
                None => String::new(),
                Some(f) => {
                    let rest: String = chars.collect::<String>().to_uppercase();
                    format!("{}{}", f.to_lowercase(), rest)
                }
            }
        };
        // BasE: first + last cap, middle lower
        let first_last = {
            let chars: Vec<char> = base.chars().collect();
            if chars.len() < 2 {
                cap.clone()
            } else {
                let mut s = String::with_capacity(chars.len());
                for (i, &c) in chars.iter().enumerate() {
                    if i == 0 || i == chars.len() - 1 {
                        s.extend(c.to_uppercase());
                    } else {
                        s.extend(c.to_lowercase());
                    }
                }
                s
            }
        };
        vec![cap, upper, inverted, first_last]
    }
}

// ─── Engine ────────────────────────────────────────────────────────────────────

pub struct MutationEngineV2 {
    bases: Vec<String>,
    rules: Vec<Box<dyn MutationRule>>,
    ctx: TargetContext,
    max_mutations: usize,
    usernames: Vec<String>,
}

impl MutationEngineV2 {
    pub fn generate(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut out: Vec<String> = Vec::new();

        'outer: for base in &self.bases {
            for rule in &self.rules {
                for mutation in rule.apply(base, &self.ctx) {
                    if seen.insert(mutation.clone()) {
                        out.push(mutation);
                        if out.len() >= self.max_mutations {
                            break 'outer;
                        }
                    }
                }
            }
        }

        out
    }
}

impl AttackStrategy for MutationEngineV2 {
    fn name(&self) -> &'static str { "mutation-v2" }

    fn credentials(&self) -> CredentialStream {
        let mutations = self.generate();
        let usernames = self.usernames.clone();

        let mut creds: Vec<Credential> = Vec::with_capacity(usernames.len() * mutations.len());
        for username in &usernames {
            for pw in &mutations {
                creds.push(Credential::new(username.clone(), pw.clone()));
            }
        }

        Box::pin(iter(creds))
    }

    fn estimated_count(&self) -> Option<u64> {
        let bases = self.bases.len() as u64;
        let rules = self.rules.len() as u64;
        // rough upper bound: ~5 outputs per rule per base
        let mutations = bases.saturating_mul(rules).saturating_mul(5);
        let users = self.usernames.len() as u64;
        Some(mutations.saturating_mul(users.max(1)))
    }
}

// ─── Builder ───────────────────────────────────────────────────────────────────

pub struct MutationEngineV2Builder {
    bases: Vec<String>,
    rules: Vec<Box<dyn MutationRule>>,
    ctx: TargetContext,
    max_mutations: usize,
    usernames: Vec<String>,
}

impl Default for MutationEngineV2Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl MutationEngineV2Builder {
    pub fn new() -> Self {
        Self {
            bases: Vec::new(),
            rules: Vec::new(),
            ctx: TargetContext::new(),
            max_mutations: 10_000,
            usernames: Vec::new(),
        }
    }

    pub fn with_base(mut self, base: &str) -> Self {
        self.bases.push(base.to_owned());
        self
    }

    pub fn with_bases(mut self, bases: Vec<String>) -> Self {
        self.bases.extend(bases);
        self
    }

    pub fn with_company(mut self, name: &str) -> Self {
        self.ctx.company = Some(name.to_owned());
        self
    }

    pub fn with_domain(mut self, domain: &str) -> Self {
        self.ctx.domain = Some(domain.to_owned());
        self
    }

    pub fn with_year(mut self, year: u32) -> Self {
        self.ctx.year = year;
        self
    }

    pub fn with_keyword(mut self, kw: &str) -> Self {
        self.ctx.keywords.push(kw.to_owned());
        self
    }

    pub fn with_employee(mut self, name: &str) -> Self {
        self.ctx.employee_names.push(name.to_owned());
        self
    }

    pub fn with_username(mut self, username: &str) -> Self {
        self.usernames.push(username.to_owned());
        self
    }

    pub fn add_rule(mut self, rule: Box<dyn MutationRule>) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn max_mutations(mut self, n: usize) -> Self {
        self.max_mutations = n;
        self
    }

    pub fn build(mut self) -> MutationEngineV2 {
        // If no rules specified, install all defaults.
        if self.rules.is_empty() {
            self.rules.push(Box::new(YearSuffixRule));
            self.rules.push(Box::new(SpecialCharRule));
            self.rules.push(Box::new(LeetSpeakRule));
            self.rules.push(Box::new(CompanyContextRule));
            self.rules.push(Box::new(KeyboardWalkRule));
            self.rules.push(Box::new(CaseMixRule));
        }

        MutationEngineV2 {
            bases: self.bases,
            rules: self.rules,
            ctx: self.ctx,
            max_mutations: self.max_mutations,
            usernames: self.usernames,
        }
    }
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(f) => {
            let upper: String = f.to_uppercase().collect();
            upper + &chars.as_str().to_lowercase()
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_company(company: &str, year: u32) -> TargetContext {
        TargetContext {
            company: Some(company.to_owned()),
            year,
            ..Default::default()
        }
    }

    #[test]
    fn year_suffix_rule_generates_year_variants() {
        let rule = YearSuffixRule;
        let ctx = TargetContext { year: 2024, ..Default::default() };
        let results = rule.apply("pass", &ctx);
        assert!(results.contains(&"pass2024".to_owned()));
        assert!(results.contains(&"pass2023".to_owned()));
        assert!(results.contains(&"pass2025".to_owned()));
    }

    #[test]
    fn leet_speak_rule_substitutes_characters() {
        let rule = LeetSpeakRule;
        let ctx = TargetContext::default();
        let results = rule.apply("base", &ctx);
        // b@se (a→@) or b4s3 (all-at-once) should be present
        assert!(results.iter().any(|r| r.contains('@') || r.contains('3') || r.contains('$')));
    }

    #[test]
    fn company_context_rule_uses_target_info() {
        let rule = CompanyContextRule;
        let ctx = ctx_with_company("Acme", 2024);
        let results = rule.apply("pass", &ctx);
        assert!(results.contains(&"acmepass".to_owned()));
        assert!(results.contains(&"pass_acme".to_owned()));
        assert!(results.contains(&"Acme_pass".to_owned()));
        assert!(results.contains(&"pass@Acme".to_owned()));
    }

    #[test]
    fn company_context_rule_empty_without_company() {
        let rule = CompanyContextRule;
        let ctx = TargetContext::default();
        let results = rule.apply("pass", &ctx);
        assert!(results.is_empty());
    }

    #[test]
    fn builder_applies_all_default_rules() {
        let engine = MutationEngineV2Builder::new()
            .with_base("admin")
            .with_company("Corp")
            .with_year(2024)
            .build();
        let mutations = engine.generate();
        // Year suffix
        assert!(mutations.contains(&"admin2024".to_owned()));
        // Special char
        assert!(mutations.contains(&"admin!".to_owned()));
        // Keyboard walk
        assert!(mutations.contains(&"admin123".to_owned()));
        // Company context
        assert!(mutations.contains(&"corpAdmin".to_owned()) || mutations.contains(&"corpadmin".to_owned()));
    }

    #[test]
    fn dedup_removes_duplicate_mutations() {
        // Two rules that would produce the same output get deduplicated.
        struct ConstRule;
        impl MutationRule for ConstRule {
            fn name(&self) -> &'static str { "const" }
            fn apply(&self, _base: &str, _ctx: &TargetContext) -> Vec<String> {
                vec!["duplicate".to_owned(), "duplicate".to_owned()]
            }
        }

        let engine = MutationEngineV2Builder::new()
            .with_base("x")
            .add_rule(Box::new(ConstRule))
            .add_rule(Box::new(ConstRule))
            .build();
        let mutations = engine.generate();
        let count = mutations.iter().filter(|m| m.as_str() == "duplicate").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn max_mutations_cap_respected() {
        let engine = MutationEngineV2Builder::new()
            .with_base("pass")
            .with_year(2024)
            .max_mutations(2)
            .build();
        let mutations = engine.generate();
        assert!(mutations.len() <= 2);
    }

    #[test]
    fn custom_rule_plugged_in() {
        struct PrefixRule;
        impl MutationRule for PrefixRule {
            fn name(&self) -> &'static str { "prefix" }
            fn apply(&self, base: &str, _ctx: &TargetContext) -> Vec<String> {
                vec![format!("custom_{}", base)]
            }
        }

        let engine = MutationEngineV2Builder::new()
            .with_base("word")
            .add_rule(Box::new(PrefixRule))
            .build();
        let mutations = engine.generate();
        assert!(mutations.contains(&"custom_word".to_owned()));
    }

    #[test]
    fn case_mix_rule_produces_variants() {
        let rule = CaseMixRule;
        let ctx = TargetContext::default();
        let results = rule.apply("hello", &ctx);
        assert!(results.contains(&"Hello".to_owned()));
        assert!(results.contains(&"HELLO".to_owned()));
        assert!(results.contains(&"hELLO".to_owned()));
        assert!(results.contains(&"HellO".to_owned()));
    }

    #[test]
    fn keyboard_walk_rule_appends_sequences() {
        let rule = KeyboardWalkRule;
        let ctx = TargetContext::default();
        let results = rule.apply("pass", &ctx);
        assert!(results.contains(&"pass123".to_owned()));
        assert!(results.contains(&"pass1234".to_owned()));
        assert!(results.contains(&"pass12345".to_owned()));
        assert!(results.contains(&"pass!@#".to_owned()));
    }

    #[test]
    fn attack_strategy_cross_products_users_mutations() {
        use futures::StreamExt;

        let engine = MutationEngineV2Builder::new()
            .with_base("pw")
            .with_username("alice")
            .with_username("bob")
            .add_rule(Box::new(KeyboardWalkRule))
            .build();

        let mutation_count = engine.generate().len();
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        let creds = rt.block_on(async { engine.credentials().collect::<Vec<_>>().await });
        // 2 users × mutation_count
        assert_eq!(creds.len(), 2 * mutation_count);
    }
}
