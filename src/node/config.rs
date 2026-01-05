//! Configuration file support for qpb-node.
//!
//! Configuration is loaded in layers:
//! 1. Defaults (hardcoded)
//! 2. Config file (qpb.toml in datadir)
//! 3. CLI flags (highest priority, override everything)

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Top-level configuration structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Network: "mainnet", "testnet", or "devnet"
    pub chain: Option<String>,
    /// Data directory path
    pub datadir: Option<String>,
    /// Chain parameters file path
    pub chainparams: Option<String>,

    /// RPC server configuration
    pub rpc: RpcConfig,

    /// P2P network configuration
    pub p2p: P2pConfig,

    /// Mining configuration
    pub mining: MiningConfig,

    /// Logging configuration
    pub log: LogConfig,
}

/// RPC server configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RpcConfig {
    /// RPC bind address (e.g., "127.0.0.1:28332")
    pub bind: Option<String>,
    /// RPC username for authentication
    pub user: Option<String>,
    /// RPC password for authentication
    pub password: Option<String>,
    /// Maximum requests per second per client (0 = unlimited)
    pub rate_limit: Option<u32>,
}

/// P2P network configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct P2pConfig {
    /// Enable listening for inbound connections
    pub listen: Option<bool>,
    /// Address to bind for P2P connections (e.g., "0.0.0.0")
    pub bind: Option<String>,
    /// P2P port override
    pub port: Option<u16>,
    /// Maximum inbound connections
    pub max_inbound: Option<usize>,
    /// Peer addresses to connect to
    pub connect: Option<Vec<String>>,
    /// Connection deadline in milliseconds
    pub deadline_ms: Option<u64>,
    /// Connection retry attempts
    pub attempts: Option<usize>,
    /// Initial backoff in milliseconds
    pub backoff_ms: Option<u64>,
}

/// Mining configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MiningConfig {
    /// Skip proof-of-work verification (dev only)
    pub no_pow: Option<bool>,
}

/// Logging configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// Log level filter (e.g., "info", "debug", "warn")
    pub level: Option<String>,
}

impl Config {
    /// Load configuration from a TOML file.
    ///
    /// Returns an empty config if the file doesn't exist.
    /// Returns an error if the file exists but is malformed.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Config::default());
        }

        let contents = fs::read_to_string(path).map_err(|e| ConfigError::Read {
            path: path.display().to_string(),
            source: e,
        })?;

        toml::from_str(&contents).map_err(|e| ConfigError::Parse {
            path: path.display().to_string(),
            source: e,
        })
    }

    /// Load configuration from the default location in the data directory.
    ///
    /// Looks for `qpb.toml` in the specified data directory.
    pub fn load_from_datadir<P: AsRef<Path>>(datadir: P) -> Result<Self, ConfigError> {
        let config_path = datadir.as_ref().join("qpb.toml");
        Self::load(config_path)
    }
}

/// Configuration loading errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file '{path}': {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file '{path}': {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_empty_config() {
        let config = Config::default();
        assert!(config.chain.is_none());
        assert!(config.rpc.bind.is_none());
        assert!(config.p2p.listen.is_none());
    }

    #[test]
    fn test_load_nonexistent() {
        let config = Config::load("/nonexistent/path/qpb.toml").unwrap();
        assert!(config.chain.is_none());
    }

    #[test]
    fn test_load_full_config() {
        let toml_content = r#"
chain = "testnet"
datadir = "/var/lib/qpb"

[rpc]
bind = "127.0.0.1:18332"
user = "admin"
password = "secret"
rate_limit = 50

[p2p]
listen = true
bind = "0.0.0.0"
port = 18333
max_inbound = 100
connect = ["seed1.example.com:18333", "seed2.example.com:18333"]

[mining]
no_pow = false

[log]
level = "debug"
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();

        let config = Config::load(file.path()).unwrap();
        assert_eq!(config.chain, Some("testnet".to_string()));
        assert_eq!(config.datadir, Some("/var/lib/qpb".to_string()));
        assert_eq!(config.rpc.bind, Some("127.0.0.1:18332".to_string()));
        assert_eq!(config.rpc.user, Some("admin".to_string()));
        assert_eq!(config.rpc.rate_limit, Some(50));
        assert_eq!(config.p2p.listen, Some(true));
        assert_eq!(config.p2p.port, Some(18333));
        assert_eq!(config.p2p.max_inbound, Some(100));
        assert_eq!(
            config.p2p.connect,
            Some(vec![
                "seed1.example.com:18333".to_string(),
                "seed2.example.com:18333".to_string()
            ])
        );
        assert_eq!(config.mining.no_pow, Some(false));
        assert_eq!(config.log.level, Some("debug".to_string()));
    }

    #[test]
    fn test_partial_config() {
        let toml_content = r#"
chain = "devnet"

[rpc]
bind = "127.0.0.1:28332"
"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();

        let config = Config::load(file.path()).unwrap();
        assert_eq!(config.chain, Some("devnet".to_string()));
        assert_eq!(config.rpc.bind, Some("127.0.0.1:28332".to_string()));
        // Others should be None
        assert!(config.rpc.user.is_none());
        assert!(config.p2p.listen.is_none());
    }

    #[test]
    fn test_invalid_toml() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"invalid [ toml").unwrap();

        let result = Config::load(file.path());
        assert!(result.is_err());
    }
}
