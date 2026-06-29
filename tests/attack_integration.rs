//! Integration tests for zeus-attack public API.
//!
//! These tests exercise each attack strategy from the outside (crate boundary),
//! complementing the unit tests that live inside each module.

#![cfg(test)]

use futures::StreamExt;
use zeus_attack::{
    AttackStrategy, BruteForceStrategy, CheckpointStrategy, CombinatorStrategy,
    DeduplicateStrategy, DictionaryStrategy, MaskStrategy, Rule, RuleSet, RulesStrategy, Wordlist,
};
use zeus_core::Credential;

// ── helpers ──────────────────────────────────────────────────────────────────

fn collect_blocking(strategy: &dyn AttackStrategy) -> Vec<Credential> {
    let rt =
        tokio::runtime::Runtime::new().expect("tokio runtime must build for blocking collection");
    rt.block_on(async { strategy.credentials().collect::<Vec<_>>().await })
}

fn words(ws: &[&str]) -> Vec<String> {
    ws.iter().map(|s| s.to_string()).collect()
}

fn wl(ws: &[&str]) -> Wordlist {
    Wordlist::from_vec(ws.iter().map(|s| s.to_string()).collect())
}

// ── mod brute_force ───────────────────────────────────────────────────────────

mod brute_force {
    use super::*;

    #[test]
    fn test_brute_force_strategy_name() {
        let bf = BruteForceStrategy::new("admin", "ab", 1, 1);
        assert_eq!(
            bf.name(),
            "brute-force",
            "BruteForceStrategy must report name 'brute-force'"
        );
    }

    #[test]
    fn test_brute_force_generates_correct_count_single_length() {
        // charset "ab", length 1 → 2 candidates
        let bf = BruteForceStrategy::new("admin", "ab", 1, 1);
        assert_eq!(
            bf.estimated_count(),
            Some(2),
            "charset size 2, length 1 should produce exactly 2 candidates"
        );
    }

    #[test]
    fn test_brute_force_generates_correct_count_range() {
        // charset "ab", length 1–2 → 2 + 4 = 6 candidates
        let bf = BruteForceStrategy::new("admin", "ab", 1, 2);
        assert_eq!(
            bf.estimated_count(),
            Some(6),
            "charset size 2, lengths 1-2 should produce 2+4=6 candidates"
        );
    }

    #[tokio::test]
    async fn test_brute_force_stream_length_matches_estimate() {
        let bf = BruteForceStrategy::new("admin", "abc", 1, 1);
        let expected = bf.estimated_count().expect("estimate must be Some");
        let creds: Vec<_> = bf.credentials().collect().await;
        assert_eq!(
            creds.len() as u64,
            expected,
            "collected stream length must equal estimated_count"
        );
    }

    #[test]
    fn test_brute_force_passwords_contain_all_charset_chars() {
        let bf = BruteForceStrategy::new("u", "xy", 1, 1);
        let creds = collect_blocking(&bf);
        let passwords: Vec<&str> = creds.iter().map(|c| c.password.as_str()).collect();
        assert!(
            passwords.contains(&"x"),
            "charset 'xy' at length 1 must include password 'x'"
        );
        assert!(
            passwords.contains(&"y"),
            "charset 'xy' at length 1 must include password 'y'"
        );
    }

    #[test]
    fn test_brute_force_username_propagated_to_all_credentials() {
        let bf = BruteForceStrategy::new("root", "ab", 1, 1);
        let creds = collect_blocking(&bf);
        assert!(
            creds.iter().all(|c| c.username == "root"),
            "every credential must carry the configured username"
        );
    }

    #[test]
    fn test_brute_force_alphanumeric_constructor_has_nonzero_estimate() {
        let bf = BruteForceStrategy::alphanumeric("admin", 1);
        // 36 chars (a-z + 0-9), length 1 → 36 candidates
        assert_eq!(
            bf.estimated_count(),
            Some(36),
            "alphanumeric charset (36 chars) at length 1 should produce 36 candidates"
        );
    }
}

// ── mod dictionary ────────────────────────────────────────────────────────────

mod dictionary {
    use super::*;

    #[test]
    fn test_dictionary_strategy_name() {
        let s = DictionaryStrategy::new(vec!["u".into()], wl(&["p"]));
        assert_eq!(s.name(), "dictionary");
    }

    #[test]
    fn test_dictionary_username_assigned_to_each_credential() {
        let s = DictionaryStrategy::new(vec!["alice".into()], wl(&["pass1", "pass2"]));
        let creds = collect_blocking(&s);
        assert!(
            creds.iter().all(|c| c.username == "alice"),
            "all credentials must have the configured username"
        );
    }

    #[test]
    fn test_dictionary_passwords_match_wordlist() {
        let s = DictionaryStrategy::new(vec!["u".into()], wl(&["alpha", "beta", "gamma"]));
        let creds = collect_blocking(&s);
        let passwords: Vec<&str> = creds.iter().map(|c| c.password.as_str()).collect();
        assert_eq!(
            passwords,
            vec!["alpha", "beta", "gamma"],
            "passwords must appear in wordlist order"
        );
    }

    #[test]
    fn test_dictionary_multiple_usernames_produce_cross_product() {
        // 2 users × 3 words = 6 credentials
        let s = DictionaryStrategy::new(vec!["alice".into(), "bob".into()], wl(&["a", "b", "c"]));
        assert_eq!(
            s.estimated_count(),
            Some(6),
            "2 usernames × 3 words must yield 6 total credentials"
        );
        assert_eq!(
            collect_blocking(&s).len(),
            6,
            "stream must produce exactly 6 credentials"
        );
    }

    #[test]
    fn test_dictionary_colon_pair_mode_splits_username_and_password() {
        // credential_pairs mode: each entry is "user:pass"
        let s = DictionaryStrategy::credential_pairs(wl(&["root:toor", "admin:admin"]));
        let creds = collect_blocking(&s);
        assert_eq!(
            creds.len(),
            2,
            "two colon-separated pairs must yield two credentials"
        );
        let root_cred = creds
            .iter()
            .find(|c| c.username == "root")
            .expect("credential for 'root' must be present");
        assert_eq!(
            root_cred.password, "toor",
            "password after colon must be 'toor'"
        );
    }

    #[test]
    fn test_dictionary_estimated_count_single_user() {
        let s = DictionaryStrategy::new(vec!["u".into()], wl(&["a", "b", "c", "d"]));
        assert_eq!(
            s.estimated_count(),
            Some(4),
            "single username × 4-word list must estimate 4"
        );
    }
}

// ── mod mask ─────────────────────────────────────────────────────────────────

mod mask {
    use super::*;

    #[test]
    fn test_mask_strategy_name() {
        let m = MaskStrategy::new("u", "?l");
        assert_eq!(m.name(), "mask");
    }

    #[test]
    fn test_mask_triple_lower_estimated_count() {
        // ?l?l?l → 26^3 = 17 576
        let m = MaskStrategy::new("admin", "?l?l?l");
        assert_eq!(
            m.estimated_count(),
            Some(26 * 26 * 26),
            "?l?l?l must estimate 26^3 = 17576 candidates"
        );
    }

    #[tokio::test]
    async fn test_mask_triple_lower_stream_count_matches_estimate() {
        let m = MaskStrategy::new("admin", "?l?l?l");
        let expected = m.estimated_count().expect("estimate must be Some");
        let count = m.credentials().count().await;
        assert_eq!(
            count as u64, expected,
            "collected stream must contain exactly estimated_count items"
        );
    }

    #[tokio::test]
    async fn test_mask_triple_lower_all_passwords_are_lowercase_alpha() {
        let m = MaskStrategy::new("admin", "?l?l?l");
        let creds: Vec<_> = m.credentials().collect().await;
        for cred in &creds {
            assert!(
                cred.password.chars().all(|c| c.is_ascii_lowercase()),
                "password '{}' must contain only lowercase ASCII letters",
                cred.password
            );
            assert_eq!(
                cred.password.len(),
                3,
                "each ?l?l?l password must be exactly 3 chars long"
            );
        }
    }

    #[test]
    fn test_mask_digit_placeholder_generates_ten_candidates() {
        let m = MaskStrategy::new("admin", "?d");
        assert_eq!(
            m.estimated_count(),
            Some(10),
            "?d must estimate exactly 10 candidates (0-9)"
        );
    }

    #[test]
    fn test_mask_digit_passwords_are_zero_through_nine() {
        let m = MaskStrategy::new("admin", "?d");
        let creds = collect_blocking(&m);
        let passwords: std::collections::HashSet<&str> =
            creds.iter().map(|c| c.password.as_str()).collect();
        for d in '0'..='9' {
            let s = d.to_string();
            assert!(
                passwords.contains(s.as_str()),
                "digit mask must include password '{}'",
                d
            );
        }
    }

    #[test]
    fn test_mask_literal_prefix_with_digit_placeholder() {
        // "pw?d" → literal p, literal w, digit charset → 10 candidates all starting with "pw"
        let m = MaskStrategy::new("u", "pw?d");
        let creds = collect_blocking(&m);
        assert_eq!(creds.len(), 10, "pw?d must produce 10 candidates");
        assert!(
            creds.iter().all(|c| c.password.starts_with("pw")),
            "all candidates must start with literal 'pw'"
        );
    }

    #[test]
    fn test_mask_username_propagated() {
        let m = MaskStrategy::new("testuser", "?d");
        let creds = collect_blocking(&m);
        assert!(
            creds.iter().all(|c| c.username == "testuser"),
            "all mask credentials must carry the configured username"
        );
    }
}

// ── mod combinator ────────────────────────────────────────────────────────────

mod combinator {
    use super::*;

    #[test]
    fn test_combinator_strategy_name() {
        let s = CombinatorStrategy::new("u", words(&["a"]), words(&["b"]));
        assert_eq!(s.name(), "combinator");
    }

    #[test]
    fn test_combinator_estimated_count_is_cartesian_product() {
        let s = CombinatorStrategy::new("u", words(&["a", "b"]), words(&["x", "y", "z"]));
        assert_eq!(
            s.estimated_count(),
            Some(6),
            "2 × 3 words must estimate 6 candidates"
        );
    }

    #[tokio::test]
    async fn test_combinator_all_pairs_present_in_stream() {
        let s = CombinatorStrategy::new("u", words(&["foo", "bar"]), words(&["1", "2"]));
        let creds: Vec<_> = s.credentials().collect().await;
        let passwords: Vec<&str> = creds.iter().map(|c| c.password.as_str()).collect();
        for expected in &["foo1", "foo2", "bar1", "bar2"] {
            assert!(
                passwords.contains(expected),
                "password '{}' must be present in combinator output",
                expected
            );
        }
    }

    #[tokio::test]
    async fn test_combinator_separator_inserted_between_words() {
        let s =
            CombinatorStrategy::new("u", words(&["pass"]), words(&["word"])).with_separator("-");
        let creds: Vec<_> = s.credentials().collect().await;
        assert_eq!(creds.len(), 1, "one pair must yield one credential");
        assert_eq!(
            creds[0].password, "pass-word",
            "separator '-' must appear between the two words"
        );
    }

    #[test]
    fn test_combinator_empty_first_list_yields_zero_candidates() {
        let s = CombinatorStrategy::new("u", words(&[]), words(&["x", "y"]));
        assert_eq!(
            s.estimated_count(),
            Some(0),
            "empty first list must produce zero candidates"
        );
        assert!(
            collect_blocking(&s).is_empty(),
            "stream must be empty when first list is empty"
        );
    }

    #[test]
    fn test_combinator_username_propagated() {
        let s = CombinatorStrategy::new("zeus", words(&["a"]), words(&["b"]));
        let creds = collect_blocking(&s);
        assert!(
            creds.iter().all(|c| c.username == "zeus"),
            "all credentials must carry the configured username"
        );
    }
}

// ── mod dedup ─────────────────────────────────────────────────────────────────

mod dedup {
    use super::*;
    use tokio_stream::iter;
    use zeus_attack::CredentialStream;

    struct FixedStrategy(Vec<Credential>);

    impl AttackStrategy for FixedStrategy {
        fn name(&self) -> &'static str {
            "fixed"
        }
        fn credentials(&self) -> CredentialStream {
            Box::pin(iter(self.0.clone()))
        }
        fn estimated_count(&self) -> Option<u64> {
            Some(self.0.len() as u64)
        }
    }

    fn cred(u: &str, p: &str) -> Credential {
        Credential::new(u.to_string(), p.to_string())
    }

    #[test]
    fn test_dedup_strategy_name() {
        let s = DeduplicateStrategy::new(Box::new(FixedStrategy(vec![])));
        assert_eq!(s.name(), "dedup");
    }

    #[test]
    fn test_dedup_estimated_count_is_always_none() {
        let s = DeduplicateStrategy::new(Box::new(FixedStrategy(vec![cred("u", "p")])));
        assert_eq!(
            s.estimated_count(),
            None,
            "DeduplicateStrategy cannot know final count without materialising the stream"
        );
    }

    #[test]
    fn test_dedup_removes_exact_credential_duplicates() {
        let inner = FixedStrategy(vec![
            cred("u", "alpha"),
            cred("u", "beta"),
            cred("u", "alpha"), // duplicate
            cred("u", "gamma"),
            cred("u", "beta"), // duplicate
        ]);
        let s = DeduplicateStrategy::new(Box::new(inner));
        let creds = collect_blocking(&s);
        assert_eq!(
            creds.len(),
            3,
            "five items with two duplicates must yield three unique credentials"
        );
    }

    #[test]
    fn test_dedup_preserves_insertion_order() {
        let inner = FixedStrategy(vec![
            cred("u", "z"),
            cred("u", "a"),
            cred("u", "m"),
            cred("u", "z"),
        ]);
        let s = DeduplicateStrategy::new(Box::new(inner));
        let creds = collect_blocking(&s);
        let passwords: Vec<&str> = creds.iter().map(|c| c.password.as_str()).collect();
        assert_eq!(
            passwords,
            vec!["z", "a", "m"],
            "dedup must preserve the first-occurrence order"
        );
    }

    #[test]
    fn test_dedup_same_password_different_users_both_kept() {
        // Dedup key is "username\x00password", so alice:pass and bob:pass are distinct.
        let inner = FixedStrategy(vec![cred("alice", "pass"), cred("bob", "pass")]);
        let s = DeduplicateStrategy::new(Box::new(inner));
        let creds = collect_blocking(&s);
        assert_eq!(
            creds.len(),
            2,
            "same password for different usernames must not be deduplicated"
        );
    }

    #[test]
    fn test_dedup_empty_stream_stays_empty() {
        let s = DeduplicateStrategy::new(Box::new(FixedStrategy(vec![])));
        assert!(
            collect_blocking(&s).is_empty(),
            "dedup of empty stream must remain empty"
        );
    }
}

// ── mod checkpoint ────────────────────────────────────────────────────────────

mod checkpoint {
    use super::*;
    use tokio_stream::iter;
    use zeus_attack::CredentialStream;

    struct FixedStrategy(Vec<Credential>);

    impl AttackStrategy for FixedStrategy {
        fn name(&self) -> &'static str {
            "fixed"
        }
        fn credentials(&self) -> CredentialStream {
            Box::pin(iter(self.0.clone()))
        }
        fn estimated_count(&self) -> Option<u64> {
            Some(self.0.len() as u64)
        }
    }

    fn numbered_creds(n: usize) -> Vec<Credential> {
        (0..n)
            .map(|i| Credential::new("u".to_string(), format!("pass{}", i)))
            .collect()
    }

    #[test]
    fn test_checkpoint_strategy_name() {
        let s = CheckpointStrategy::new(Box::new(FixedStrategy(vec![])));
        assert_eq!(s.name(), "checkpoint");
    }

    #[test]
    fn test_checkpoint_skip_zero_passes_all_credentials() {
        let s = CheckpointStrategy::new(Box::new(FixedStrategy(numbered_creds(5))));
        assert_eq!(
            collect_blocking(&s).len(),
            5,
            "skip_first=0 must pass all five credentials through"
        );
    }

    #[test]
    fn test_checkpoint_resume_skips_correct_number() {
        let s = CheckpointStrategy::resume_from(Box::new(FixedStrategy(numbered_creds(10))), 3);
        let creds = collect_blocking(&s);
        assert_eq!(creds.len(), 7, "skipping 3 of 10 must leave 7 credentials");
        assert_eq!(
            creds[0].password, "pass3",
            "first credential after skip must be the fourth (index 3)"
        );
    }

    #[test]
    fn test_checkpoint_estimated_count_decrements_by_skip() {
        let s = CheckpointStrategy::resume_from(Box::new(FixedStrategy(numbered_creds(10))), 4);
        assert_eq!(
            s.estimated_count(),
            Some(6),
            "estimated_count must subtract skipped credentials from inner estimate"
        );
    }

    #[test]
    fn test_checkpoint_skip_beyond_total_yields_empty_stream() {
        let s = CheckpointStrategy::resume_from(Box::new(FixedStrategy(numbered_creds(5))), 100);
        assert!(
            collect_blocking(&s).is_empty(),
            "skipping more than total must yield an empty stream"
        );
    }

    #[test]
    fn test_checkpoint_estimated_count_saturates_at_zero() {
        let s = CheckpointStrategy::resume_from(Box::new(FixedStrategy(numbered_creds(5))), 100);
        assert_eq!(
            s.estimated_count(),
            Some(0),
            "estimated_count must saturate at 0 when skip exceeds total"
        );
    }
}

// ── mod rules ─────────────────────────────────────────────────────────────────

mod rules {
    use super::*;
    use zeus_attack::parse_rule;

    // ── Rule enum ────────────────────────────────────────────────────────────

    #[test]
    fn test_rule_to_upper_uppercases_all_chars() {
        assert_eq!(
            Rule::ToUpper.apply("hello"),
            "HELLO",
            "ToUpper must uppercase every character"
        );
    }

    #[test]
    fn test_rule_to_lower_lowercases_all_chars() {
        assert_eq!(
            Rule::ToLower.apply("HELLO"),
            "hello",
            "ToLower must lowercase every character"
        );
    }

    #[test]
    fn test_rule_reverse_reverses_string() {
        assert_eq!(
            Rule::Reverse.apply("abcd"),
            "dcba",
            "Reverse must produce the string in reverse order"
        );
    }

    #[test]
    fn test_rule_append_char_appends_to_end() {
        assert_eq!(
            Rule::Append('!').apply("pass"),
            "pass!",
            "Append('!') must concatenate '!' to the end"
        );
    }

    #[test]
    fn test_rule_prepend_char_prepends_to_start() {
        assert_eq!(
            Rule::Prepend('^').apply("pass"),
            "^pass",
            "Prepend('^') must place '^' at the start"
        );
    }

    #[test]
    fn test_rule_append_year_appends_four_digit_year() {
        assert_eq!(
            Rule::AppendYear(2025).apply("pass"),
            "pass2025",
            "AppendYear(2025) must append the year string"
        );
    }

    #[test]
    fn test_rule_l33t_speak_substitutes_target_chars() {
        // e→3, a→4, o→0, i→1, s→5, t→7
        assert_eq!(
            Rule::L33tSpeak.apply("password"),
            "p455w0rd",
            "L33tSpeak must replace a→4, s→5, o→0"
        );
    }

    #[test]
    fn test_rule_duplicate_doubles_input() {
        assert_eq!(
            Rule::Duplicate.apply("abc"),
            "abcabc",
            "Duplicate must concatenate the string with itself"
        );
    }

    #[test]
    fn test_rule_truncate_to_clips_at_n_chars() {
        assert_eq!(
            Rule::TruncateTo(4).apply("abcdefgh"),
            "abcd",
            "TruncateTo(4) must return only the first 4 characters"
        );
    }

    #[test]
    fn test_rule_truncate_to_shorter_than_n_returns_full() {
        assert_eq!(
            Rule::TruncateTo(10).apply("abc"),
            "abc",
            "TruncateTo(10) on a 3-char string must return the full string"
        );
    }

    #[test]
    fn test_rule_append_str_appends_full_suffix() {
        assert_eq!(
            Rule::AppendStr("123!".into()).apply("pass"),
            "pass123!",
            "AppendStr must append the full suffix string"
        );
    }

    // ── RuleSet ───────────────────────────────────────────────────────────────

    #[test]
    fn test_ruleset_chains_rules_left_to_right() {
        // Capitalize then AppendYear — produces "Password2024"
        let rs = RuleSet::new(vec![Rule::Capitalize, Rule::AppendYear(2024)]);
        assert_eq!(
            rs.apply("password"),
            "Password2024",
            "RuleSet must apply rules left-to-right: Capitalize then AppendYear"
        );
    }

    #[test]
    fn test_ruleset_empty_ruleset_is_identity() {
        let rs = RuleSet::new(vec![]);
        assert_eq!(
            rs.apply("unchanged"),
            "unchanged",
            "Empty RuleSet must return the input unchanged"
        );
    }

    #[test]
    fn test_ruleset_apply_all_maps_over_every_word() {
        let rs = RuleSet::new(vec![Rule::ToUpper]);
        let result = rs.apply_all(&["hello".to_string(), "world".to_string()]);
        assert_eq!(
            result,
            vec!["HELLO", "WORLD"],
            "apply_all must apply the ruleset to every word in the slice"
        );
    }

    // ── parse_rule / hashcat-style rules ─────────────────────────────────────

    #[test]
    fn test_parse_rule_uppercase_u() {
        let rule = parse_rule("u");
        assert_eq!(
            rule("hello"),
            "HELLO",
            "hashcat rule 'u' must uppercase the entire string"
        );
    }

    #[test]
    fn test_parse_rule_append_dollar_sign() {
        let rule = parse_rule("$1");
        assert_eq!(
            rule("pass"),
            "pass1",
            "hashcat rule '$1' must append the char '1'"
        );
    }

    #[test]
    fn test_parse_rule_prepend_caret() {
        let rule = parse_rule("^0");
        assert_eq!(
            rule("pass"),
            "0pass",
            "hashcat rule '^0' must prepend the char '0'"
        );
    }

    #[test]
    fn test_parse_rule_substitute_sxy() {
        // sae → replace 'a' with 'e'
        let rule = parse_rule("sae");
        assert_eq!(
            rule("banana"),
            "benene",
            "hashcat rule 'sae' must substitute all 'a' chars with 'e'"
        );
    }

    #[test]
    fn test_parse_rule_reverse_r() {
        let rule = parse_rule("r");
        assert_eq!(
            rule("zeus"),
            "suez",
            "hashcat rule 'r' must reverse the string"
        );
    }

    // ── RulesStrategy ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_rules_strategy_applies_hashcat_rules_to_each_word() {
        // Rule chain: uppercase ("u") then append '!' ("$!")
        let s = RulesStrategy::new("admin", words(&["alpha", "beta"]), &["u", "$!"]);
        let creds: Vec<_> = s.credentials().collect().await;
        assert_eq!(creds.len(), 2, "two words must produce two credentials");
        assert_eq!(
            creds[0].password, "ALPHA!",
            "first word 'alpha' uppercased then '!' appended must be 'ALPHA!'"
        );
        assert_eq!(
            creds[1].password, "BETA!",
            "second word 'beta' uppercased then '!' appended must be 'BETA!'"
        );
    }

    #[test]
    fn test_rules_strategy_name() {
        let s = RulesStrategy::new("u", words(&["p"]), &["l"]);
        assert_eq!(s.name(), "rules");
    }

    #[test]
    fn test_rules_strategy_estimated_count_equals_wordlist_length() {
        let s = RulesStrategy::new("u", words(&["a", "b", "c"]), &["u", "$1"]);
        assert_eq!(
            s.estimated_count(),
            Some(3),
            "estimated_count must equal the wordlist length regardless of rule count"
        );
    }
}

// ── mod wordlist ──────────────────────────────────────────────────────────────

mod wordlist {
    use super::*;

    #[test]
    fn test_wordlist_from_vec_len_matches_input() {
        let list = Wordlist::from_vec(words(&["a", "b", "c", "d"]));
        assert_eq!(list.len(), 4, "from_vec must store all provided entries");
    }

    #[test]
    fn test_wordlist_is_empty_on_empty_input() {
        let list = Wordlist::from_vec(vec![]);
        assert!(
            list.is_empty(),
            "empty from_vec must report is_empty = true"
        );
    }

    #[test]
    fn test_wordlist_credentials_all_have_correct_username() {
        let list = Wordlist::from_vec(words(&["pass1", "pass2"]));
        let creds: Vec<_> = list.credentials("sysadmin").collect();
        assert!(
            creds.iter().all(|c| c.username == "sysadmin"),
            "every credential from Wordlist::credentials must carry the provided username"
        );
    }

    #[test]
    fn test_wordlist_credential_pairs_splits_colon_entries() {
        let list = Wordlist::from_vec(words(&["alice:wonderland", "bob:builder"]));
        let pairs: Vec<_> = list.credential_pairs().collect();
        assert_eq!(
            pairs.len(),
            2,
            "two colon entries must yield two credential pairs"
        );
        assert_eq!(pairs[0].username, "alice");
        assert_eq!(pairs[0].password, "wonderland");
    }

    #[test]
    fn test_wordlist_built_in_top10_has_ten_entries() {
        let list = Wordlist::built_in("top10").expect("built-in 'top10' must exist");
        assert_eq!(
            list.len(),
            10,
            "top10 built-in wordlist must contain exactly 10 entries"
        );
    }

    #[test]
    fn test_wordlist_built_in_unknown_name_returns_none() {
        assert!(
            Wordlist::built_in("does_not_exist").is_none(),
            "unknown built-in name must return None"
        );
    }

    #[test]
    fn test_wordlist_from_file_temp_path() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().expect("temp file must be created");
        writeln!(tmp, "# comment line").expect("write comment");
        writeln!(tmp, "secret1").expect("write entry 1");
        writeln!(tmp, "").expect("write blank line");
        writeln!(tmp, "secret2").expect("write entry 2");

        let list = Wordlist::from_file(tmp.path()).expect("from_file must succeed on a valid file");
        assert_eq!(
            list.len(),
            2,
            "from_file must skip comment lines and blank lines, keeping 2 entries"
        );
        let passwords: Vec<&str> = list.passwords().collect();
        assert!(
            passwords.contains(&"secret1"),
            "first entry must be 'secret1'"
        );
        assert!(
            passwords.contains(&"secret2"),
            "second entry must be 'secret2'"
        );
    }
}
