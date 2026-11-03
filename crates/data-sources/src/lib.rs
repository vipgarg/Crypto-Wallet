//! Blockchain data sources (ARCHITECTURE.md §5.5).
//!
//! - The network config (providers + pinned contracts) is compiled in.
//! - Every fact is asked of every configured provider for that network.
//! - Results are compared exactly. **No majority vote**: any disagreement is
//!   reported as a disagreement, and a single answer is "unverified".
//! - Providers are only asked about individual addresses (never an xpub).

pub mod config;
pub mod cross_check;
pub mod fetch;
pub mod http;
pub mod signet;

pub use config::{NetworkConfig, ProviderConfig, ProviderKind};
pub use cross_check::{cross_check, CrossChecked};
pub use http::{HttpClient, HttpError, ReqwestClient};
