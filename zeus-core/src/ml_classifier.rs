//! ML Response Classifier — heuristic and Naïve-Bayes classifiers for
//! determining whether an HTTP/TCP authentication attempt succeeded.
//!
//! Uses the **Template Method** pattern: [`ResponseClassifier`] defines the
//! overall classification pipeline via default trait methods while concrete
//! implementations override feature-extraction and scoring steps.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// The result label produced by a classifier.
#[derive(Debug, Clone, PartialEq)]
pub enum ClassificationLabel {
    /// Authentication clearly succeeded.
    Success,
    /// Authentication clearly failed.
    Failure,
    /// Not enough signal — manual review recommended.
    Uncertain,
}

/// A weighted boolean signal that contributed to the classification decision.
#[derive(Debug, Clone)]
pub struct Signal {
    /// Short identifier for this signal.
    pub name: &'static str,
    /// Contribution to the success score (positive → success, negative → failure).
    pub weight: f32,
    /// Whether this signal was observed in the response.
    pub matched: bool,
}

/// Full output of a classification run.
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    /// The predicted outcome label.
    pub label: ClassificationLabel,
    /// Normalised confidence in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Individual signals that influenced the decision.
    pub signals: Vec<Signal>,
}

// ---------------------------------------------------------------------------
// RawResponse
// ---------------------------------------------------------------------------

/// Raw response data passed into a classifier.
#[derive(Debug, Clone, Default)]
pub struct RawResponse {
    /// HTTP status code, if applicable.
    pub status_code: Option<u16>,
    /// Response body as a string.
    pub body: String,
    /// Response headers as key-value pairs.
    pub headers: Vec<(String, String)>,
    /// Round-trip time in milliseconds.
    pub elapsed_ms: u64,
    /// Number of HTTP redirects followed.
    pub redirect_count: u8,
}

// ---------------------------------------------------------------------------
// ResponseFeatures
// ---------------------------------------------------------------------------

/// Computed feature vector derived from a [`RawResponse`].
#[derive(Debug, Clone, Default)]
pub struct ResponseFeatures {
    pub status_code: Option<u16>,
    pub body_length: usize,
    pub redirect_count: u8,
    /// Body contains success keywords such as "welcome", "dashboard", etc.
    pub has_success_keyword: bool,
    /// Body contains failure keywords such as "invalid", "incorrect", etc.
    pub has_failure_keyword: bool,
    /// Response appears to include a CAPTCHA challenge.
    pub has_captcha: bool,
    pub response_time_ms: u64,
    pub cookie_count: usize,
    /// A `Set-Cookie` header with "session" in its name/value was present.
    pub has_session_cookie: bool,
}

const SUCCESS_KEYWORDS: &[&str] = &[
    "welcome",
    "dashboard",
    "logged in",
    "logout",
    "sign out",
    "my account",
    "profile",
    "hello,",
    "home",
    "success",
];

const FAILURE_KEYWORDS: &[&str] = &[
    "invalid",
    "incorrect",
    "wrong password",
    "bad credentials",
    "authentication failed",
    "login failed",
    "access denied",
    "try again",
    "error",
    "unauthorized",
    "forbidden",
];

// ---------------------------------------------------------------------------
// Template Method trait
// ---------------------------------------------------------------------------

/// Template method trait for response classifiers.
///
/// Concrete types implement [`extract_features`] and [`score_features`];
/// the `classify` method provides the default aggregation pipeline.
pub trait ResponseClassifier: Send + Sync {
    /// Step 1 — derive a feature vector from the raw response.
    fn extract_features(&self, raw: &RawResponse) -> ResponseFeatures;

    /// Step 2 — produce weighted signals from the feature vector.
    fn score_features(&self, features: &ResponseFeatures) -> Vec<Signal>;

    /// Full classification pipeline (Template Method — default implementation).
    ///
    /// Calls [`extract_features`] then [`score_features`], aggregates the
    /// weighted score, and maps it to a [`ClassificationLabel`].
    fn classify(&self, raw: &RawResponse) -> ClassificationResult {
        let features = self.extract_features(raw);
        let signals = self.score_features(&features);

        // Weighted sum over matched signals only.
        let raw_score: f32 = signals.iter().filter(|s| s.matched).map(|s| s.weight).sum();

        // Normalise to [0,1] range where 0.5 is the uncertainty boundary.
        // We map raw_score ∈ (-∞, +∞) via a sigmoid-like clamp.
        let confidence = sigmoid(raw_score);

        let label = if confidence >= 0.65 {
            ClassificationLabel::Success
        } else if confidence <= 0.35 {
            ClassificationLabel::Failure
        } else {
            ClassificationLabel::Uncertain
        };

        ClassificationResult {
            label,
            confidence,
            signals,
        }
    }
}

/// Sigmoid function mapping real-valued score to (0, 1).
fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

// ---------------------------------------------------------------------------
// HeuristicClassifier
// ---------------------------------------------------------------------------

/// Rule-based classifier using hand-tuned signal weights.
///
/// Suitable as a fast, dependency-free first-pass classifier.
pub struct HeuristicClassifier {
    /// Confidence threshold above which the result is labelled `Success`.
    pub threshold: f32,
}

impl Default for HeuristicClassifier {
    fn default() -> Self {
        Self { threshold: 0.65 }
    }
}

impl HeuristicClassifier {
    /// Create a classifier with custom success threshold.
    pub fn new(threshold: f32) -> Self {
        Self { threshold }
    }
}

impl ResponseClassifier for HeuristicClassifier {
    fn extract_features(&self, raw: &RawResponse) -> ResponseFeatures {
        let body_lower = raw.body.to_lowercase();

        let cookie_headers: Vec<_> = raw
            .headers
            .iter()
            .filter(|(k, _)| k.to_lowercase() == "set-cookie")
            .collect();

        let has_session_cookie = cookie_headers.iter().any(|(_, v)| {
            let vl = v.to_lowercase();
            vl.contains("session") || vl.contains("sess") || vl.contains("sid")
        });

        ResponseFeatures {
            status_code: raw.status_code,
            body_length: raw.body.len(),
            redirect_count: raw.redirect_count,
            has_success_keyword: SUCCESS_KEYWORDS.iter().any(|kw| body_lower.contains(kw)),
            has_failure_keyword: FAILURE_KEYWORDS.iter().any(|kw| body_lower.contains(kw)),
            has_captcha: body_lower.contains("captcha") || body_lower.contains("recaptcha"),
            response_time_ms: raw.elapsed_ms,
            cookie_count: cookie_headers.len(),
            has_session_cookie,
        }
    }

    fn score_features(&self, f: &ResponseFeatures) -> Vec<Signal> {
        vec![
            Signal {
                name: "status_200",
                weight: 0.5,
                matched: f.status_code == Some(200),
            },
            Signal {
                name: "status_302_redirect",
                weight: 1.0,
                matched: matches!(f.status_code, Some(301) | Some(302) | Some(303)),
            },
            Signal {
                name: "status_401_403",
                weight: -2.0,
                matched: matches!(f.status_code, Some(401) | Some(403)),
            },
            Signal {
                name: "success_keyword",
                weight: 2.0,
                matched: f.has_success_keyword,
            },
            Signal {
                name: "failure_keyword",
                weight: -2.5,
                matched: f.has_failure_keyword,
            },
            Signal {
                name: "session_cookie",
                weight: 1.5,
                matched: f.has_session_cookie,
            },
            Signal {
                name: "cookie_present",
                weight: 0.5,
                matched: f.cookie_count > 0,
            },
            Signal {
                name: "captcha_present",
                weight: -1.0,
                matched: f.has_captcha,
            },
            Signal {
                name: "large_body",
                weight: 0.3,
                matched: f.body_length > 5000,
            },
            Signal {
                name: "redirect_chain",
                weight: 0.4,
                matched: f.redirect_count >= 2,
            },
        ]
    }
}

// ---------------------------------------------------------------------------
// NaiveBayesClassifier
// ---------------------------------------------------------------------------

/// A simple additive log-probability Naïve Bayes classifier.
///
/// Splits the body into tokens and looks up pre-trained per-word probabilities
/// for the success and failure classes.  No external ML libraries required —
/// all arithmetic is plain `f32` operations.
pub struct NaiveBayesClassifier {
    /// P(word | success) for vocabulary words.
    pub success_word_probs: HashMap<String, f32>,
    /// P(word | failure) for vocabulary words.
    pub failure_word_probs: HashMap<String, f32>,
    /// Prior probability of success (default 0.3).
    prior_success: f32,
}

impl NaiveBayesClassifier {
    /// Build a classifier with hand-tuned default probabilities derived from
    /// common web authentication page patterns.
    pub fn with_defaults() -> Self {
        let success_words: &[(&str, f32)] = &[
            ("welcome", 0.90),
            ("dashboard", 0.92),
            ("logout", 0.88),
            ("profile", 0.80),
            ("account", 0.75),
            ("hello", 0.70),
            ("success", 0.80),
            ("home", 0.65),
            ("authorized", 0.85),
        ];
        let failure_words: &[(&str, f32)] = &[
            ("invalid", 0.92),
            ("incorrect", 0.90),
            ("failed", 0.88),
            ("denied", 0.87),
            ("wrong", 0.85),
            ("error", 0.75),
            ("retry", 0.80),
            ("locked", 0.82),
            ("forbidden", 0.88),
            ("unauthorized", 0.90),
        ];

        Self {
            success_word_probs: success_words
                .iter()
                .map(|(w, p)| (w.to_string(), *p))
                .collect(),
            failure_word_probs: failure_words
                .iter()
                .map(|(w, p)| (w.to_string(), *p))
                .collect(),
            prior_success: 0.3,
        }
    }

    /// Tokenise body text into lowercase words.
    fn tokenise(body: &str) -> Vec<String> {
        body.split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(|t| t.to_lowercase())
            .collect()
    }
}

impl ResponseClassifier for NaiveBayesClassifier {
    fn extract_features(&self, raw: &RawResponse) -> ResponseFeatures {
        // Reuse the heuristic extractor logic.
        HeuristicClassifier::default().extract_features(raw)
    }

    fn score_features(&self, features: &ResponseFeatures) -> Vec<Signal> {
        // Return basic heuristic signals (Bayes scoring happens in classify override).
        HeuristicClassifier::default().score_features(features)
    }

    /// Override the default pipeline to incorporate log-probability scoring.
    fn classify(&self, raw: &RawResponse) -> ClassificationResult {
        let features = self.extract_features(raw);
        let mut signals = self.score_features(&features);

        // Log-probability accumulation.
        let tokens = Self::tokenise(&raw.body);
        let mut log_p_success = (self.prior_success).ln();
        let mut log_p_failure = (1.0 - self.prior_success).ln();

        for token in &tokens {
            if let Some(&p) = self.success_word_probs.get(token) {
                log_p_success += p.ln();
                log_p_failure += (1.0 - p).ln();
            }
            if let Some(&p) = self.failure_word_probs.get(token) {
                log_p_failure += p.ln();
                log_p_success += (1.0 - p).ln();
            }
        }

        // Convert log-odds to probability.
        let bayes_score = log_p_success - log_p_failure;
        signals.push(Signal {
            name: "bayes_log_odds",
            weight: bayes_score.clamp(-5.0, 5.0),
            matched: bayes_score > 0.0,
        });

        let raw_score: f32 = signals.iter().filter(|s| s.matched).map(|s| s.weight).sum();
        let confidence = sigmoid(raw_score);

        let label = if confidence >= 0.65 {
            ClassificationLabel::Success
        } else if confidence <= 0.35 {
            ClassificationLabel::Failure
        } else {
            ClassificationLabel::Uncertain
        };

        ClassificationResult {
            label,
            confidence,
            signals,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn success_response() -> RawResponse {
        RawResponse {
            status_code: Some(200),
            body: "Welcome back! You are now logged in. <a href='/logout'>logout</a> dashboard"
                .into(),
            headers: vec![("Set-Cookie".into(), "session_id=abc123; Path=/".into())],
            elapsed_ms: 120,
            redirect_count: 0,
        }
    }

    fn failure_response() -> RawResponse {
        RawResponse {
            status_code: Some(401),
            body: "Invalid username or password. Authentication failed. Please try again.".into(),
            headers: vec![],
            elapsed_ms: 45,
            redirect_count: 0,
        }
    }

    #[test]
    fn heuristic_classifies_success() {
        let clf = HeuristicClassifier::default();
        let result = clf.classify(&success_response());
        assert_eq!(result.label, ClassificationLabel::Success);
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn heuristic_classifies_failure() {
        let clf = HeuristicClassifier::default();
        let result = clf.classify(&failure_response());
        assert_eq!(result.label, ClassificationLabel::Failure);
        assert!(result.confidence < 0.5);
    }

    #[test]
    fn heuristic_detects_session_cookie_signal() {
        let clf = HeuristicClassifier::default();
        let features = clf.extract_features(&success_response());
        assert!(features.has_session_cookie);
    }

    #[test]
    fn naivebayes_classifies_success() {
        let clf = NaiveBayesClassifier::with_defaults();
        let result = clf.classify(&success_response());
        assert_eq!(result.label, ClassificationLabel::Success);
    }

    #[test]
    fn naivebayes_classifies_failure() {
        let clf = NaiveBayesClassifier::with_defaults();
        let result = clf.classify(&failure_response());
        assert_eq!(result.label, ClassificationLabel::Failure);
    }

    #[test]
    fn classification_result_contains_signals() {
        let clf = HeuristicClassifier::default();
        let result = clf.classify(&success_response());
        assert!(!result.signals.is_empty());
        assert!(result.signals.iter().any(|s| s.name == "success_keyword"));
    }

    #[test]
    fn sigmoid_midpoint_is_half() {
        let s = sigmoid(0.0);
        assert!((s - 0.5).abs() < 1e-6);
    }

    #[test]
    fn uncertain_label_when_low_signal() {
        let clf = HeuristicClassifier::default();
        let raw = RawResponse {
            status_code: Some(200),
            body: "OK".into(),
            headers: vec![],
            elapsed_ms: 80,
            redirect_count: 0,
        };
        let result = clf.classify(&raw);
        // Low signal — should not be a confident Success or Failure.
        assert!(
            result.label == ClassificationLabel::Uncertain
                || result.confidence > 0.35 && result.confidence < 0.65
        );
    }
}
