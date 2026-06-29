//! Integration tests for zeus-services public API.
//!
//! Covers ProtocolRegistry, FactoryRegistry, ProbeOutcome, ProtocolInfo,
//! and ProbeCommand from the outside (crate boundary).

#![cfg(test)]

use async_trait::async_trait;
use std::sync::Arc;
use zeus_core::{AttackConfig, AttackResult, Credential, Protocol, Target, ZeusError};
use zeus_services::registry::{
    FactoryRegistry, ProbeCommand, ProbeHandler, ProbeOutcome, ProtocolRegistry,
};

// ── mock types ────────────────────────────────────────────────────────────────

/// Minimal Protocol stub — always returns Failure.
struct StubProtocol {
    name: &'static str,
    port: u16,
    description: &'static str,
}

#[async_trait]
impl Protocol for StubProtocol {
    fn name(&self) -> &'static str {
        self.name
    }
    fn default_port(&self) -> u16 {
        self.port
    }
    fn description(&self) -> &'static str {
        self.description
    }
    async fn authenticate(
        &self,
        _target: &Target,
        _cred: &Credential,
        _config: &AttackConfig,
    ) -> Result<AttackResult, ZeusError> {
        Ok(AttackResult::Failure)
    }
}

/// Minimal ProbeHandler stub — used to populate FactoryRegistry without needing
/// the private ProtocolProbeHandler type.
struct StubHandler {
    protocol: &'static str,
    port: u16,
    description: &'static str,
}

#[async_trait]
impl ProbeHandler for StubHandler {
    fn protocol(&self) -> &'static str {
        self.protocol
    }
    fn default_port(&self) -> u16 {
        self.port
    }
    fn description(&self) -> &'static str {
        self.description
    }
    async fn probe(&self, _target: &Target, _cred: &Credential) -> ProbeOutcome {
        ProbeOutcome::Failure {
            reason: "stub always fails".into(),
        }
    }
}

fn stub_protocol(name: &'static str, port: u16) -> Arc<dyn Protocol> {
    Arc::new(StubProtocol {
        name,
        port,
        description: "stub protocol",
    })
}

// ── mod protocol_registry ─────────────────────────────────────────────────────

mod protocol_registry {
    use super::*;

    #[test]
    fn test_new_registry_is_empty() {
        let reg = ProtocolRegistry::new();
        assert!(
            reg.is_empty(),
            "a freshly constructed ProtocolRegistry must be empty"
        );
    }

    #[test]
    fn test_register_then_get_returns_some() {
        let reg = ProtocolRegistry::new();
        reg.register(stub_protocol("mock", 9999));
        assert!(
            reg.get("mock").is_some(),
            "a registered protocol must be retrievable by name"
        );
    }

    #[test]
    fn test_get_unregistered_name_returns_none() {
        let reg = ProtocolRegistry::new();
        assert!(
            reg.get("nonexistent").is_none(),
            "get on an unregistered name must return None"
        );
    }

    #[test]
    fn test_registry_not_empty_after_registration() {
        let reg = ProtocolRegistry::new();
        reg.register(stub_protocol("mock", 1));
        assert!(
            !reg.is_empty(),
            "registry must not be empty after a protocol is registered"
        );
    }

    #[test]
    fn test_list_returns_sorted_names() {
        let reg = ProtocolRegistry::new();
        reg.register(stub_protocol("zebra", 1));
        reg.register(stub_protocol("apple", 2));
        reg.register(stub_protocol("mango", 3));
        let list = reg.list();
        let mut expected = list.clone();
        expected.sort();
        assert_eq!(
            list, expected,
            "list() must return protocol names in sorted order"
        );
    }

    #[test]
    fn test_list_contains_all_registered_names() {
        let reg = ProtocolRegistry::new();
        reg.register(stub_protocol("alpha", 10));
        reg.register(stub_protocol("beta", 20));
        let list = reg.list();
        assert!(
            list.contains(&"alpha".to_string()),
            "'alpha' must appear in list()"
        );
        assert!(
            list.contains(&"beta".to_string()),
            "'beta' must appear in list()"
        );
    }

    #[test]
    fn test_list_protocols_returns_info_sorted_by_name() {
        let reg = ProtocolRegistry::new();
        reg.register(stub_protocol("zzz", 1));
        reg.register(stub_protocol("aaa", 2));
        let infos = reg.list_protocols();
        let names: Vec<&str> = infos.iter().map(|i| i.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(
            names, sorted,
            "list_protocols() must return ProtocolInfo entries sorted by name"
        );
    }

    #[test]
    fn test_list_protocols_info_fields_populated() {
        let reg = ProtocolRegistry::new();
        reg.register(Arc::new(StubProtocol {
            name: "testproto",
            port: 4242,
            description: "test description",
        }));
        let infos = reg.list_protocols();
        let info = infos
            .iter()
            .find(|i| i.name == "testproto")
            .expect("ProtocolInfo for 'testproto' must be present");
        assert_eq!(
            info.name, "testproto",
            "ProtocolInfo.name must match registered name"
        );
        assert_eq!(
            info.default_port, 4242,
            "ProtocolInfo.default_port must match registered port"
        );
        assert!(
            !info.description.is_empty(),
            "ProtocolInfo.description must not be empty"
        );
    }

    #[test]
    fn test_get_or_default_port_returns_correct_port_for_registered_protocol() {
        let reg = ProtocolRegistry::new();
        reg.register(stub_protocol("myproto", 7777));
        assert_eq!(
            reg.get_or_default_port("myproto"),
            Some(7777),
            "get_or_default_port must return the registered protocol's default port"
        );
    }

    #[test]
    fn test_get_or_default_port_returns_none_for_unknown_protocol() {
        let reg = ProtocolRegistry::new();
        assert_eq!(
            reg.get_or_default_port("unknown"),
            None,
            "get_or_default_port must return None for an unregistered protocol"
        );
    }

    #[test]
    fn test_registering_same_name_twice_overwrites() {
        let reg = ProtocolRegistry::new();
        reg.register(stub_protocol("proto", 100));
        reg.register(stub_protocol("proto", 200));
        // After overwrite the registry still contains exactly one entry for "proto"
        assert_eq!(
            reg.list().iter().filter(|n| n.as_str() == "proto").count(),
            1,
            "registering under the same name twice must not create duplicate entries"
        );
    }
}

// ── mod factory_registry ──────────────────────────────────────────────────────

mod factory_registry {
    use super::*;

    fn make_handler(name: &'static str, port: u16) -> Box<dyn ProbeHandler> {
        Box::new(StubHandler {
            protocol: name,
            port,
            description: "stub",
        })
    }

    #[test]
    fn test_factory_registry_create_on_empty_returns_none() {
        let reg = FactoryRegistry::new();
        assert!(
            reg.create("anything").is_none(),
            "create on an empty FactoryRegistry must return None"
        );
    }

    #[test]
    fn test_factory_registry_register_and_create_returns_handler() {
        let reg = FactoryRegistry::new();
        reg.register("stub", || make_handler("stub", 1234));
        let handler = reg
            .create("stub")
            .expect("create must return Some after registering 'stub'");
        assert_eq!(
            handler.protocol(),
            "stub",
            "created handler must report protocol 'stub'"
        );
        assert_eq!(
            handler.default_port(),
            1234,
            "created handler must report port 1234"
        );
    }

    #[test]
    fn test_factory_registry_create_unregistered_returns_none() {
        let reg = FactoryRegistry::new();
        reg.register("one", || make_handler("one", 1));
        assert!(
            reg.create("two").is_none(),
            "create for an unregistered protocol must return None"
        );
    }

    #[test]
    fn test_factory_registry_each_create_call_returns_independent_handler() {
        let reg = FactoryRegistry::new();
        reg.register("p", || make_handler("p", 9));
        let h1 = reg.create("p").expect("first create must succeed");
        let h2 = reg.create("p").expect("second create must succeed");
        // Both are independent objects with the same metadata.
        assert_eq!(
            h1.default_port(),
            h2.default_port(),
            "both handlers must report the same port"
        );
        assert_eq!(
            h1.protocol(),
            h2.protocol(),
            "both handlers must report the same protocol name"
        );
    }

    #[test]
    fn test_factory_registry_protocols_list_is_sorted() {
        let reg = FactoryRegistry::new();
        reg.register("zzz", || make_handler("zzz", 3));
        reg.register("aaa", || make_handler("aaa", 1));
        reg.register("mmm", || make_handler("mmm", 2));
        let list = reg.protocols();
        let mut sorted = list.clone();
        sorted.sort_unstable();
        assert_eq!(
            list, sorted,
            "protocols() must return names in sorted order"
        );
    }

    #[test]
    fn test_factory_registry_protocols_contains_registered_names() {
        let reg = FactoryRegistry::new();
        reg.register("foo", || make_handler("foo", 1));
        reg.register("bar", || make_handler("bar", 2));
        let list = reg.protocols();
        assert!(list.contains(&"foo"), "'foo' must appear in protocols()");
        assert!(list.contains(&"bar"), "'bar' must appear in protocols()");
    }

    #[test]
    fn test_factory_registry_handler_description_non_empty() {
        let reg = FactoryRegistry::new();
        reg.register("with-desc", || {
            Box::new(StubHandler {
                protocol: "with-desc",
                port: 42,
                description: "a real description",
            })
        });
        let handler = reg.create("with-desc").expect("handler must be created");
        assert!(
            !handler.description().is_empty(),
            "handler description must not be empty"
        );
    }
}

// ── mod probe_outcome ─────────────────────────────────────────────────────────

mod probe_outcome {
    use super::*;

    #[test]
    fn test_probe_outcome_success_variant_is_success() {
        let outcome = ProbeOutcome::Success {
            message: "authenticated".into(),
        };
        assert!(
            outcome.is_success(),
            "ProbeOutcome::Success must report is_success() = true"
        );
    }

    #[test]
    fn test_probe_outcome_failure_variant_is_not_success() {
        let outcome = ProbeOutcome::Failure {
            reason: "wrong password".into(),
        };
        assert!(
            !outcome.is_success(),
            "ProbeOutcome::Failure must report is_success() = false"
        );
    }

    #[test]
    fn test_probe_outcome_timeout_variant_is_not_success() {
        assert!(
            !ProbeOutcome::Timeout.is_success(),
            "ProbeOutcome::Timeout must report is_success() = false"
        );
    }

    #[test]
    fn test_probe_outcome_error_variant_is_not_success() {
        let outcome = ProbeOutcome::Error {
            detail: "connection refused".into(),
        };
        assert!(
            !outcome.is_success(),
            "ProbeOutcome::Error must report is_success() = false"
        );
    }

    #[test]
    fn test_probe_outcome_equality_same_success() {
        let a = ProbeOutcome::Success {
            message: "ok".into(),
        };
        let b = ProbeOutcome::Success {
            message: "ok".into(),
        };
        assert_eq!(
            a, b,
            "two Success outcomes with the same message must be equal"
        );
    }

    #[test]
    fn test_probe_outcome_equality_different_variants() {
        assert_ne!(
            ProbeOutcome::Timeout,
            ProbeOutcome::Failure {
                reason: "bad cred".into()
            },
            "Timeout and Failure outcomes must not be equal"
        );
    }
}

// ── mod probe_command ─────────────────────────────────────────────────────────

mod probe_command {
    use super::*;

    fn make_factory_registry() -> FactoryRegistry {
        let reg = FactoryRegistry::new();
        reg.register("stub", || {
            Box::new(StubHandler {
                protocol: "stub",
                port: 9999,
                description: "stub",
            })
        });
        reg
    }

    #[test]
    fn test_probe_command_from_registry_known_protocol_returns_some() {
        let reg = make_factory_registry();
        let cmd = ProbeCommand::from_registry(
            &reg,
            Target::new("127.0.0.1", 9999, "stub"),
            Credential::new("u", "p"),
        );
        assert!(
            cmd.is_some(),
            "from_registry must return Some for a registered protocol"
        );
    }

    #[test]
    fn test_probe_command_from_registry_unknown_protocol_returns_none() {
        let reg = FactoryRegistry::new(); // empty
        let cmd = ProbeCommand::from_registry(
            &reg,
            Target::new("127.0.0.1", 1234, "missing"),
            Credential::new("u", "p"),
        );
        assert!(
            cmd.is_none(),
            "from_registry must return None when the protocol is not registered"
        );
    }

    #[tokio::test]
    async fn test_probe_command_execute_returns_outcome() {
        let reg = make_factory_registry();
        let cmd = ProbeCommand::from_registry(
            &reg,
            Target::new("127.0.0.1", 9999, "stub"),
            Credential::new("u", "p"),
        )
        .expect("command must be constructable for 'stub' protocol");

        // StubHandler always returns Failure — we just verify execute() completes.
        let outcome = cmd.execute().await;
        assert!(
            matches!(outcome, ProbeOutcome::Failure { .. }),
            "stub handler must produce a Failure outcome"
        );
    }
}
