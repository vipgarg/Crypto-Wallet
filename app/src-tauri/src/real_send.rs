//! Real-network sending (TRON and Ethereum mainnet), **off by default**.
//!
//! The test-network code (`tron_test`, `eth_test`) is reused unchanged for
//! real money: [`real_view`] gives it a configuration whose "test" slots
//! hold the real providers and the real USDT contracts from the reviewed
//! config, and [`is_real`] lets it pick the real chain id, fee cap and
//! explorer. Nothing here can be reached unless the owner has switched on
//! real sending in Settings (after the release gates), and the tablet signs
//! real payments only with wallets made by a real-networks build.

use data_sources::config::SignetProvider;
use data_sources::NetworkConfig;
use wallet_types::Network;

/// The configuration the send code uses for real money.
pub fn real_view(config: &NetworkConfig) -> NetworkConfig {
    let as_nodes = |n: Network| -> Vec<SignetProvider> {
        config
            .providers_for(n)
            .map(|p| SignetProvider {
                id: p.id.clone(),
                base_url: p.base_url.clone(),
                operator: p.operator.clone(),
            })
            .collect()
    };
    let mut c = config.clone();
    c.nile_providers = as_nodes(Network::Tron);
    c.usdt_trc20_nile = Some(config.usdt_trc20);
    c.sepolia_providers = as_nodes(Network::Ethereum);
    c.usdt_erc20_sepolia = Some(config.usdt_erc20);
    c.signet_providers = Vec::new();
    c
}

/// True for a configuration made by [`real_view`].
pub fn is_real(config: &NetworkConfig) -> bool {
    config.usdt_trc20_nile == Some(config.usdt_trc20)
        || config.usdt_erc20_sepolia == Some(config.usdt_erc20)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_view_uses_the_real_contracts_and_nodes() {
        let c = NetworkConfig::embedded().expect("config");
        assert!(!is_real(&c));
        let r = real_view(&c);
        assert!(is_real(&r));
        assert_eq!(r.usdt_trc20_nile, Some(c.usdt_trc20));
        assert_eq!(
            r.usdt_erc20_sepolia.map(|a| a.to_checksum()).as_deref(),
            Some(signer_tablet_mainnet_usdt())
        );
        assert!(r
            .nile_providers
            .iter()
            .all(|p| !p.base_url.contains("nile")));
        assert!(r.sepolia_providers.len() >= 2);
    }

    /// The same value the tablet pins for real Ethereum USDT.
    fn signer_tablet_mainnet_usdt() -> &'static str {
        "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    }
}
