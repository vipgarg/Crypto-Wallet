//! Network configuration: providers and pinned contracts (§9.6).

use std::collections::HashSet;

use chain_eth::EthAddress;
use chain_tron::TronAddress;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use wallet_types::Network;

/// The config file compiled into this binary.
pub const EMBEDDED_CONFIG: &str = include_str!("../../../config/networks.v1.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// Esplora REST API (Bitcoin).
    Esplora,
    /// Ethereum JSON-RPC.
    EthJsonRpc,
    /// TRON full-node HTTP API (`/wallet/...`).
    TronHttp,
}

impl ProviderKind {
    fn network(self) -> Network {
        match self {
            ProviderKind::Esplora => Network::Bitcoin,
            ProviderKind::EthJsonRpc => Network::Ethereum,
            ProviderKind::TronHttp => Network::Tron,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub id: String,
    pub network: Network,
    pub kind: ProviderKind,
    pub base_url: String,
    pub operator: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPinned {
    usdt_erc20: String,
    eth_chain_id: u64,
    usdt_trc20: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    version: u32,
    pinned: RawPinned,
    providers: Vec<ProviderConfig>,
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub version: u32,
    pub usdt_erc20: EthAddress,
    pub eth_chain_id: u64,
    pub usdt_trc20: TronAddress,
    pub providers: Vec<ProviderConfig>,
    /// SHA-256 of the exact config text, shown in the app so you can compare
    /// it with the reviewed release record.
    pub sha256: String,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config is not valid TOML for this version: {0}")]
    Parse(String),
    #[error("unsupported config version {0}")]
    Version(u32),
    #[error("pinned contract is invalid: {0}")]
    Contract(String),
    #[error("eth_chain_id must be 1 (Ethereum mainnet)")]
    ChainId,
    #[error("provider '{0}': {1}")]
    Provider(String, &'static str),
}

impl NetworkConfig {
    pub fn embedded() -> Result<Self, ConfigError> {
        Self::parse(EMBEDDED_CONFIG)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        if raw.version != 1 {
            return Err(ConfigError::Version(raw.version));
        }
        let usdt_erc20: EthAddress = raw
            .pinned
            .usdt_erc20
            .parse()
            .map_err(|e: chain_eth::EthAddressError| ConfigError::Contract(e.to_string()))?;
        let usdt_trc20: TronAddress = raw
            .pinned
            .usdt_trc20
            .parse()
            .map_err(|e: chain_tron::TronAddressError| ConfigError::Contract(e.to_string()))?;
        if raw.pinned.eth_chain_id != 1 {
            return Err(ConfigError::ChainId);
        }
        let mut ids = HashSet::new();
        for p in &raw.providers {
            let err = |m| ConfigError::Provider(p.id.clone(), m);
            if !ids.insert(p.id.clone()) {
                return Err(err("duplicate id"));
            }
            if p.kind.network() != p.network {
                return Err(err("kind does not match network"));
            }
            let rest = p
                .base_url
                .strip_prefix("https://")
                .ok_or_else(|| err("URL must start with https://"))?;
            if rest.is_empty() || rest.contains(char::is_whitespace) || p.base_url.ends_with('/') {
                return Err(err("URL is malformed (no trailing slash, no spaces)"));
            }
            if p.operator.trim().is_empty() {
                return Err(err("operator must be named"));
            }
        }
        let mut hasher = Sha256::new();
        // Hash with LF line endings so the value is identical on Windows
        // (where Git may check the file out with CRLF) and everywhere else.
        hasher.update(text.replace("\r\n", "\n").as_bytes());
        Ok(Self {
            version: raw.version,
            usdt_erc20,
            eth_chain_id: raw.pinned.eth_chain_id,
            usdt_trc20,
            providers: raw.providers,
            sha256: hex::encode(hasher.finalize()),
        })
    }

    pub fn providers_for(&self, network: Network) -> impl Iterator<Item = &ProviderConfig> {
        self.providers.iter().filter(move |p| p.network == network)
    }

    /// Networks with fewer than two independent operators configured.
    pub fn networks_lacking_independence(&self) -> Vec<Network> {
        Network::ALL
            .into_iter()
            .filter(|n| {
                let ops: HashSet<&str> = self
                    .providers_for(*n)
                    .map(|p| p.operator.as_str())
                    .collect();
                ops.len() < 2
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_config_is_valid_and_independent() {
        let c = NetworkConfig::embedded().expect("embedded config");
        assert_eq!(
            c.usdt_erc20.to_checksum(),
            "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        );
        assert_eq!(
            c.usdt_trc20.to_base58(),
            "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
        );
        assert!(c.networks_lacking_independence().is_empty());
        assert_eq!(c.sha256.len(), 64);
    }

    fn with_provider(extra: &str) -> String {
        format!(
            "version = 1\n[pinned]\nusdt_erc20 = \"0xdAC17F958D2ee523a2206206994597C13D831ec7\"\neth_chain_id = 1\nusdt_trc20 = \"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t\"\n{extra}"
        )
    }

    #[test]
    fn rejects_unsafe_config() {
        let http = with_provider("[[providers]]\nid=\"a\"\nnetwork=\"bitcoin\"\nkind=\"esplora\"\nbase_url=\"http://x.example/api\"\noperator=\"A\"\n");
        assert!(matches!(
            NetworkConfig::parse(&http),
            Err(ConfigError::Provider(_, _))
        ));
        let mismatch = with_provider("[[providers]]\nid=\"a\"\nnetwork=\"tron\"\nkind=\"esplora\"\nbase_url=\"https://x.example\"\noperator=\"A\"\n");
        assert!(matches!(
            NetworkConfig::parse(&mismatch),
            Err(ConfigError::Provider(_, _))
        ));
        let unknown = with_provider("evil = true\n");
        assert!(matches!(
            NetworkConfig::parse(&unknown),
            Err(ConfigError::Parse(_))
        ));
        let ok = "[[providers]]\nid=\"a\"\nnetwork=\"bitcoin\"\nkind=\"esplora\"\nbase_url=\"https://x.example\"\noperator=\"A\"\n";
        assert!(NetworkConfig::parse(&with_provider(ok)).is_ok());
        let bad_contract = with_provider(ok).replace("831ec7", "831EC7");
        assert!(matches!(
            NetworkConfig::parse(&bad_contract),
            Err(ConfigError::Contract(_))
        ));
        let bad_chain = with_provider(ok).replace("eth_chain_id = 1", "eth_chain_id = 56");
        assert!(matches!(
            NetworkConfig::parse(&bad_chain),
            Err(ConfigError::ChainId)
        ));
    }

    #[test]
    fn hash_ignores_windows_line_endings() {
        let lf = NetworkConfig::parse(EMBEDDED_CONFIG).expect("lf");
        let crlf_text = EMBEDDED_CONFIG.replace("\r\n", "\n").replace('\n', "\r\n");
        let crlf = NetworkConfig::parse(&crlf_text).expect("crlf");
        assert_eq!(lf.sha256, crlf.sha256);
    }

    #[test]
    fn same_operator_twice_is_not_independent() {
        let cfg = with_provider(
            "[[providers]]\nid=\"a\"\nnetwork=\"bitcoin\"\nkind=\"esplora\"\nbase_url=\"https://a.example\"\noperator=\"Same\"\n\
             [[providers]]\nid=\"b\"\nnetwork=\"bitcoin\"\nkind=\"esplora\"\nbase_url=\"https://b.example\"\noperator=\"Same\"\n",
        );
        let c = NetworkConfig::parse(&cfg).expect("parse");
        assert!(c
            .networks_lacking_independence()
            .contains(&Network::Bitcoin));
    }
}
