//! scryer-core — Hartwell Labs Lead Intelligence & External Attack Surface (MVP+).
//!
//! Pipeline: LOAD -> SCORE -> ENRICH(passive DNS) -> RANK -> REPORT/EXPORT.
//! Zasady (zgodne z orgiem):
//!   * pasywne źródła domyślnie (publiczny DNS, dane publiczne) — zero aktywnego
//!     skanowania osób trzecich; aktywny tryb wymaga jawnej autoryzacji (flaga),
//!   * zero network deps — własny minimalny klient DNS (dnsmini),
//!   * deterministyczny output + manifest sha256 (audit-ready, LOG PR7).

pub mod bzp;
pub mod discovery;
pub mod dnsmini;
pub mod enrich;
pub mod export;
pub mod intel;
pub mod model;
pub mod ontology;
pub mod query;
pub mod report;
pub mod score;
pub mod send;
pub mod server;
pub mod store;
pub mod viz;

pub use model::{Hook, Lead, Sector};
pub use score::{
    dedupe, export_csv, load_json, manifest_hash, rank, run, validate, PipelineReport,
};
