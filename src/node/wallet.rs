//! Wallet storage and key management for QPB node.
//!
//! Provides persistent key storage, address tracking, and UTXO management
//! for wallet integration with the node.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Result, anyhow};
use pqcrypto_dilithium::dilithium3::{SecretKey, detached_sign, keypair, secret_key_bytes};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PKTrait, SecretKey as SKTrait};
use serde::{Deserialize, Serialize};

use crate::address::{encode_address, qpkh32};
use crate::script::build_p2qpkh;
use crate::types::Prevout;

/// Algorithm ID for ML-DSA-65 (Dilithium3).
const MLDSA_ALG_ID: u8 = 0x11;

/// A key entry in the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletKey {
    /// Serialized public key (alg_id || pk).
    pub pk_ser_hex: String,
    /// Secret key (hex encoded). In production, this should be encrypted.
    pub sk_hex: String,
    /// Derived P2QPKH address.
    pub address: String,
    /// Label for the key (optional).
    #[serde(default)]
    pub label: String,
}

/// Wallet file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletFile {
    /// Wallet format version.
    pub version: u32,
    /// Network (devnet, testnet, mainnet).
    pub network: String,
    /// Human-readable prefix for addresses.
    pub hrp: String,
    /// Keys stored in the wallet.
    pub keys: Vec<WalletKey>,
}

impl WalletFile {
    /// Create a new empty wallet.
    pub fn new(network: &str, hrp: &str) -> Self {
        Self {
            version: 1,
            network: network.to_string(),
            hrp: hrp.to_string(),
            keys: Vec::new(),
        }
    }

    /// Load wallet from file.
    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)?;
        let wallet: WalletFile = serde_json::from_str(&data)?;
        Ok(wallet)
    }

    /// Save wallet to file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        fs::write(path, data)?;
        Ok(())
    }

    /// Generate a new key and add it to the wallet.
    pub fn generate_key(&mut self, label: &str) -> Result<String> {
        let (pk, sk) = keypair();
        let pk_bytes = pk.as_bytes();
        let sk_bytes = sk.as_bytes();

        // Serialize public key with algorithm ID prefix
        let mut pk_ser = Vec::with_capacity(1 + pk_bytes.len());
        pk_ser.push(MLDSA_ALG_ID);
        pk_ser.extend_from_slice(pk_bytes);

        // Compute address
        let qpkh = qpkh32(&pk_ser);
        let address = encode_address(&self.hrp, 3, &qpkh).map_err(|e| anyhow!("{}", e))?;

        let key = WalletKey {
            pk_ser_hex: hex::encode(&pk_ser),
            sk_hex: hex::encode(sk_bytes),
            address: address.clone(),
            label: label.to_string(),
        };

        self.keys.push(key);
        Ok(address)
    }

    /// Get all addresses in the wallet.
    pub fn addresses(&self) -> Vec<&str> {
        self.keys.iter().map(|k| k.address.as_str()).collect()
    }

    /// Get all scriptPubKeys for wallet addresses (for UTXO filtering).
    pub fn script_pubkeys(&self) -> Result<HashSet<Vec<u8>>> {
        let mut spks = HashSet::new();
        for key in &self.keys {
            let pk_ser = hex::decode(&key.pk_ser_hex)?;
            let qpkh = qpkh32(&pk_ser);
            let spk = build_p2qpkh(qpkh);
            spks.insert(spk);
        }
        Ok(spks)
    }

    /// Find key by address.
    pub fn find_key(&self, address: &str) -> Option<&WalletKey> {
        self.keys.iter().find(|k| k.address == address)
    }

    /// Find key by scriptPubKey.
    pub fn find_key_by_spk(&self, spk: &[u8]) -> Option<&WalletKey> {
        for key in &self.keys {
            if let Ok(pk_ser) = hex::decode(&key.pk_ser_hex) {
                let qpkh = qpkh32(&pk_ser);
                let key_spk = build_p2qpkh(qpkh);
                if key_spk == spk {
                    return Some(key);
                }
            }
        }
        None
    }

    /// Sign a message with the key for a given address.
    pub fn sign(&self, address: &str, msg32: &[u8; 32]) -> Result<Vec<u8>> {
        let key = self
            .find_key(address)
            .ok_or_else(|| anyhow!("address not in wallet"))?;

        let sk_bytes = hex::decode(&key.sk_hex)?;
        if sk_bytes.len() != secret_key_bytes() {
            return Err(anyhow!("invalid secret key length"));
        }

        let sk = SecretKey::from_bytes(&sk_bytes).map_err(|e| anyhow!("{:?}", e))?;
        let sig = detached_sign(msg32, &sk);
        Ok(sig.as_bytes().to_vec())
    }

    /// Get the serialized public key for an address.
    pub fn get_pk_ser(&self, address: &str) -> Result<Vec<u8>> {
        let key = self
            .find_key(address)
            .ok_or_else(|| anyhow!("address not in wallet"))?;
        Ok(hex::decode(&key.pk_ser_hex)?)
    }
}

/// Wallet UTXO entry with outpoint info.
#[derive(Debug, Clone, Serialize)]
pub struct WalletUtxo {
    /// Transaction ID (hex).
    pub txid: String,
    /// Output index.
    pub vout: u32,
    /// Address that owns this UTXO.
    pub address: String,
    /// Value in satoshis.
    pub value: u64,
    /// ScriptPubKey (hex).
    pub script_pubkey: String,
}

/// Wallet state integrated with the node.
#[derive(Debug)]
pub struct Wallet {
    /// The wallet file with keys.
    pub file: WalletFile,
    /// Path to wallet file.
    pub path: std::path::PathBuf,
}

impl Wallet {
    /// Create or load a wallet.
    pub fn open_or_create(path: &Path, network: &str, hrp: &str) -> Result<Self> {
        let file = if path.exists() {
            WalletFile::load(path)?
        } else {
            let wallet = WalletFile::new(network, hrp);
            wallet.save(path)?;
            wallet
        };

        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }

    /// Load an existing wallet.
    pub fn load(path: &Path) -> Result<Self> {
        let file = WalletFile::load(path)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }

    /// Save the wallet.
    pub fn save(&self) -> Result<()> {
        self.file.save(&self.path)
    }

    /// Generate a new address.
    pub fn get_new_address(&mut self, label: &str) -> Result<String> {
        let addr = self.file.generate_key(label)?;
        self.save()?;
        Ok(addr)
    }

    /// Get wallet balance by filtering UTXO set.
    pub fn get_balance<F>(&self, utxo_iter: F) -> Result<u64>
    where
        F: FnOnce() -> Vec<(String, u32, Prevout)>,
    {
        let spks = self.file.script_pubkeys()?;
        let utxos = utxo_iter();
        let balance: u64 = utxos
            .iter()
            .filter(|(_, _, prevout)| spks.contains(&prevout.script_pubkey))
            .map(|(_, _, prevout)| prevout.value)
            .sum();
        Ok(balance)
    }

    /// List wallet UTXOs.
    pub fn list_unspent<F>(&self, utxo_iter: F) -> Result<Vec<WalletUtxo>>
    where
        F: FnOnce() -> Vec<(String, u32, Prevout)>,
    {
        let spks = self.file.script_pubkeys()?;
        let utxos = utxo_iter();

        let mut wallet_utxos = Vec::new();
        for (txid_hex, vout, prevout) in utxos {
            if spks.contains(&prevout.script_pubkey) {
                // Find the address for this UTXO
                let address = self
                    .file
                    .find_key_by_spk(&prevout.script_pubkey)
                    .map(|k| k.address.clone())
                    .unwrap_or_default();

                wallet_utxos.push(WalletUtxo {
                    txid: txid_hex,
                    vout,
                    address,
                    value: prevout.value,
                    script_pubkey: hex::encode(&prevout.script_pubkey),
                });
            }
        }

        Ok(wallet_utxos)
    }

    /// Sign a message with a wallet key.
    pub fn sign(&self, address: &str, msg32: &[u8; 32]) -> Result<Vec<u8>> {
        self.file.sign(address, msg32)
    }

    /// Get all addresses.
    pub fn addresses(&self) -> Vec<&str> {
        self.file.addresses()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn wallet_create_and_keygen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.json");

        let mut wallet = Wallet::open_or_create(&path, "devnet", "qpbdev").unwrap();
        assert!(wallet.file.keys.is_empty());

        let addr1 = wallet.get_new_address("test1").unwrap();
        assert!(addr1.starts_with("qpbdev"));
        assert_eq!(wallet.file.keys.len(), 1);

        let addr2 = wallet.get_new_address("test2").unwrap();
        assert_ne!(addr1, addr2);
        assert_eq!(wallet.file.keys.len(), 2);
    }

    #[test]
    fn wallet_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.json");

        // Create wallet and add key
        {
            let mut wallet = Wallet::open_or_create(&path, "devnet", "qpbdev").unwrap();
            wallet.get_new_address("persist-test").unwrap();
        }

        // Reload and verify
        let wallet2 = Wallet::load(&path).unwrap();
        assert_eq!(wallet2.file.keys.len(), 1);
        assert_eq!(wallet2.file.keys[0].label, "persist-test");
    }

    #[test]
    fn wallet_sign_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.json");

        let mut wallet = Wallet::open_or_create(&path, "devnet", "qpbdev").unwrap();
        let addr = wallet.get_new_address("sign-test").unwrap();

        let msg = [0x42u8; 32];
        let sig = wallet.sign(&addr, &msg).unwrap();

        // Verify signature length (ML-DSA-65 signature is 3309 bytes)
        assert_eq!(sig.len(), 3309);
    }
}
