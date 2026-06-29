//! GraphQL WAF blind-spot probes — Template Method pattern.
//!
//! Many WAFs parse HTTP bodies as form or URL-encoded data and have poor
//! coverage of GraphQL semantics.  This module surfaces three common gaps:
//!
//! 1. **Introspection leakage** — schema dump reveals every type & field.
//! 2. **Batch amplification** — one HTTP request carries N queries, bypassing
//!    per-request rate limits.
//! 3. **Alias amplification** — a single query aliases the same resolver N
//!    times, multiplying server-side work without multiplying HTTP requests.
//!
//! # Design
//! **Template Method** — [`GraphQLProbe`] defines the fixed pipeline
//! (`run` → `build_query` → HTTP POST → `interpret_response`).  Concrete
//! probes override `build_query` and `interpret_response` only.

use crate::http_client::HttpClient;
use anyhow::Result;
use serde_json::{json, Value};
use thiserror::Error;
use tracing::{debug, warn};

// ──────────────────────────────────────────────────────────────────────────────
// Error type
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum GraphQLError {
    #[error("HTTP transport error: {0}")]
    Transport(#[from] anyhow::Error),

    #[error("unexpected content-type from GraphQL endpoint: {0}")]
    UnexpectedContentType(String),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

// ──────────────────────────────────────────────────────────────────────────────
// Probe result
// ──────────────────────────────────────────────────────────────────────────────

/// Outcome of a GraphQL probe run.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    /// Whether the probe found a WAF bypass or information leak.
    pub bypassed: bool,
    /// Human-readable description of what was found.
    pub description: String,
    /// Raw response body (truncated to 4 KiB for safety).
    pub raw_body: String,
    /// HTTP status returned by the endpoint.
    pub http_status: u16,
}

impl ProbeResult {
    fn new(bypassed: bool, description: impl Into<String>, raw_body: String, status: u16) -> Self {
        let truncated = if raw_body.len() > 4096 {
            format!("{}…[truncated]", &raw_body[..4096])
        } else {
            raw_body
        };
        Self {
            bypassed,
            description: description.into(),
            raw_body: truncated,
            http_status: status,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Template Method trait
// ──────────────────────────────────────────────────────────────────────────────

/// Template Method — fixed pipeline; subclasses override `build_query` and
/// `interpret_response`.
#[async_trait::async_trait]
pub trait GraphQLProbe: Send + Sync {
    /// The GraphQL endpoint path (e.g. `"/graphql"`).
    fn endpoint(&self) -> &str;

    /// Build the JSON body to POST.
    fn build_query(&self) -> Value;

    /// Interpret the raw response body into a [`ProbeResult`].
    fn interpret_response(&self, body: &str, status: u16) -> ProbeResult;

    /// Fixed pipeline — sends `build_query()` as `application/json` POST,
    /// inspects `Content-Type`, then calls `interpret_response`.
    async fn run(&self, client: &HttpClient) -> Result<ProbeResult, GraphQLError> {
        let query = self.build_query();
        debug!(endpoint = self.endpoint(), "GraphQLProbe: sending query");

        let (status, body) = client
            .post_json(self.endpoint(), query)
            .await
            .map_err(GraphQLError::Transport)?;

        // WAF bypass indicator: a real GraphQL server always returns
        // application/json; text/html means a WAF intercepted the response.
        if body.trim_start().starts_with('<') {
            warn!(
                endpoint = self.endpoint(),
                "GraphQLProbe: response looks like HTML — possible WAF block"
            );
        }

        Ok(self.interpret_response(&body, status))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Concrete probe: IntrospectionProbe
// ──────────────────────────────────────────────────────────────────────────────

/// Sends the standard GraphQL introspection query and checks whether the server
/// leaks its full schema.
///
/// Bypasses WAFs that only block keywords in URL query strings, not JSON bodies.
#[derive(Debug)]
pub struct IntrospectionProbe {
    pub endpoint: String,
}

#[async_trait::async_trait]
impl GraphQLProbe for IntrospectionProbe {
    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn build_query(&self) -> Value {
        json!({
            "query": "{ __schema { types { name kind fields { name type { name kind } } } } }"
        })
    }

    fn interpret_response(&self, body: &str, status: u16) -> ProbeResult {
        // Presence of "__schema" in the response body indicates introspection
        // is enabled and not filtered.
        let leaked = body.contains("__schema") || body.contains("\"types\"");
        ProbeResult::new(
            leaked,
            if leaked {
                "Schema introspection enabled — full type system exposed"
            } else {
                "Introspection blocked or not a GraphQL endpoint"
            },
            body.to_string(),
            status,
        )
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Concrete probe: BatchQueryProbe
// ──────────────────────────────────────────────────────────────────────────────

/// Sends `batch_size` queries in a single HTTP request using the GraphQL
/// batch-query extension (array of operation objects).
///
/// Per-request rate limiting is bypassed because only one HTTP request is
/// sent, but `batch_size` resolver invocations occur on the server.
#[derive(Debug)]
pub struct BatchQueryProbe {
    pub endpoint: String,
    /// How many operations to batch into the single POST body.
    pub batch_size: usize,
}

#[async_trait::async_trait]
impl GraphQLProbe for BatchQueryProbe {
    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn build_query(&self) -> Value {
        let ops: Vec<Value> = (0..self.batch_size)
            .map(|i| {
                json!({
                    "operationName": format!("Op{}", i),
                    "query": format!(
                        "query Op{i} {{ __typename }}"
                    )
                })
            })
            .collect();
        Value::Array(ops)
    }

    fn interpret_response(&self, body: &str, status: u16) -> ProbeResult {
        // A JSON array response with `batch_size` entries means the server
        // processed all operations; single-object response means batching
        // was rejected.
        let is_array = body.trim_start().starts_with('[');
        let bypassed = is_array && status == 200;
        ProbeResult::new(
            bypassed,
            if bypassed {
                format!(
                    "Batch query accepted: {} operations in 1 HTTP request — rate-limit bypass",
                    self.batch_size
                )
            } else {
                "Batch query rejected or endpoint returned non-array".into()
            },
            body.to_string(),
            status,
        )
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Concrete probe: AliasAmplificationProbe
// ──────────────────────────────────────────────────────────────────────────────

/// Aliases the same resolver N times in a single query, amplifying server-side
/// computation without changing the HTTP request count or size significantly.
///
/// Useful for identifying resolvers that bypass per-field rate limiting.
#[derive(Debug)]
pub struct AliasAmplificationProbe {
    pub endpoint: String,
    /// Number of aliases to generate.
    pub alias_count: usize,
}

impl AliasAmplificationProbe {
    /// Create a new probe with a default alias count of 20.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            alias_count: 20,
        }
    }
}

#[async_trait::async_trait]
impl GraphQLProbe for AliasAmplificationProbe {
    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn build_query(&self) -> Value {
        // Build: query { a1: __typename  a2: __typename  ... aN: __typename }
        let aliases: Vec<String> = (0..self.alias_count)
            .map(|i| format!("  a{}: __typename", i))
            .collect();
        let query = format!("{{ {} }}", aliases.join("\n"));
        json!({ "query": query })
    }

    fn interpret_response(&self, body: &str, status: u16) -> ProbeResult {
        // Each alias produces a field in "data"; count them.
        let alias_responses = (0..self.alias_count)
            .filter(|i| body.contains(&format!("\"a{}\"", i)))
            .count();

        let bypassed = alias_responses == self.alias_count && status == 200;
        ProbeResult::new(
            bypassed,
            if bypassed {
                format!(
                    "Alias amplification: {} resolver invocations via 1 HTTP request — \
                     per-field rate limit bypass",
                    self.alias_count
                )
            } else {
                format!(
                    "Alias amplification partially/fully blocked ({}/{} aliases returned)",
                    alias_responses, self.alias_count
                )
            },
            body.to_string(),
            status,
        )
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests (pure logic — no network)
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn introspection_build_query_contains_schema() {
        let probe = IntrospectionProbe { endpoint: "/graphql".into() };
        let q = probe.build_query();
        let qs = q["query"].as_str().unwrap();
        assert!(qs.contains("__schema"));
    }

    #[test]
    fn introspection_interprets_leak_correctly() {
        let probe = IntrospectionProbe { endpoint: "/graphql".into() };
        let body = r#"{"data":{"__schema":{"types":[{"name":"Query"}]}}}"#;
        let result = probe.interpret_response(body, 200);
        assert!(result.bypassed);
    }

    #[test]
    fn introspection_no_false_positive_on_blocked() {
        let probe = IntrospectionProbe { endpoint: "/graphql".into() };
        let result = probe.interpret_response(r#"{"errors":[{"message":"disabled"}]}"#, 200);
        assert!(!result.bypassed);
    }

    #[test]
    fn batch_probe_builds_array_of_operations() {
        let probe = BatchQueryProbe { endpoint: "/graphql".into(), batch_size: 3 };
        let q = probe.build_query();
        assert!(q.is_array());
        assert_eq!(q.as_array().unwrap().len(), 3);
    }

    #[test]
    fn batch_probe_detects_acceptance() {
        let probe = BatchQueryProbe { endpoint: "/graphql".into(), batch_size: 2 };
        let body = r#"[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]"#;
        let result = probe.interpret_response(body, 200);
        assert!(result.bypassed);
    }

    #[test]
    fn alias_probe_builds_correct_alias_count() {
        let probe = AliasAmplificationProbe::new("/graphql");
        let q = probe.build_query();
        let qs = q["query"].as_str().unwrap();
        assert!(qs.contains("a0:"));
        assert!(qs.contains("a19:"));
    }

    #[test]
    fn alias_probe_detects_full_response() {
        let probe = AliasAmplificationProbe { endpoint: "/graphql".into(), alias_count: 3 };
        let body = r#"{"data":{"a0":"Query","a1":"Query","a2":"Query"}}"#;
        let result = probe.interpret_response(body, 200);
        assert!(result.bypassed);
    }

    #[test]
    fn probe_result_truncates_large_body() {
        let big = "x".repeat(8192);
        let r = ProbeResult::new(false, "test", big, 200);
        assert!(r.raw_body.len() <= 4096 + 50); // room for truncation suffix
        assert!(r.raw_body.contains("[truncated]"));
    }
}
