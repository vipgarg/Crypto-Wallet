//! Watch-only wallet core: the wallet registry (public data only) and the
//! cross-checked portfolio. There is no secret-handling code in this crate.

pub mod activity;
pub mod portfolio;
pub mod registry;

pub use portfolio::{
    build_portfolio, AssetBalance, AssetTotal, BalanceStatus, NoProgress, Portfolio, ProgressLevel,
    ProgressSink, WalletPortfolio,
};
pub use registry::{BtcWatch, NewWalletInput, Registry, RegistryError, WatchWallet};
