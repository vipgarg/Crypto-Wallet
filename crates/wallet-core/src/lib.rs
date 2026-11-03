//! Watch-only wallet core: the wallet registry (public data only) and the
//! cross-checked portfolio. There is no secret-handling code in this crate.

pub mod activity;
pub mod btc_activity;
pub mod eth_activity;
pub mod portfolio;
pub mod receive;
pub mod registry;

pub use portfolio::{
    build_portfolio, AssetBalance, AssetTotal, BalanceStatus, NoProgress, Portfolio, ProgressLevel,
    ProgressSink, WalletPortfolio,
};
pub use registry::{
    from_signer_export, BtcWatch, NewWalletInput, Registry, RegistryError, WatchWallet,
};
