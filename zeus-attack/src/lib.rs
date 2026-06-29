//! Attack strategies — Strategy pattern.

pub mod brute_force;
pub mod checkpoint;
pub mod combinator;
pub mod dedup;
pub mod dictionary;
pub mod hybrid;
pub mod markov;
pub mod mask;
pub mod mutation_v2;
pub mod permutation;
pub mod prince;
pub mod rules;
pub mod spray;
pub mod stuffing;
pub mod wordlist;

pub use brute_force::BruteForceStrategy;
pub use checkpoint::CheckpointStrategy;
pub use combinator::CombinatorStrategy;
pub use dedup::DeduplicateStrategy;
pub use dictionary::DictionaryStrategy;
pub use hybrid::{HybridMode, HybridStrategy, mask_permutation_count};
pub use markov::{MarkovChain, MarkovStrategy};
pub use mask::MaskStrategy;
pub use permutation::{LeetStrategy, PermutationStrategy};
pub use prince::PrinceStrategy;
pub use rules::{Rule, RuleSet, RulesStrategy, parse_rule};
pub use spray::{PasswordSprayStrategy, SprayConfig};
pub use stuffing::{BreachEntry, CredentialStuffingPipeline, CredentialStuffingStrategy};
pub use wordlist::Wordlist;

use std::pin::Pin;
use tokio_stream::Stream;
use zeus_core::Credential;

pub type CredentialStream = Pin<Box<dyn Stream<Item = Credential> + Send>>;

/// Strategy pattern — each attack mode implements this.
pub trait AttackStrategy: Send + Sync {
    fn name(&self) -> &'static str;
    fn credentials(&self) -> CredentialStream;
    fn estimated_count(&self) -> Option<u64>;
}
