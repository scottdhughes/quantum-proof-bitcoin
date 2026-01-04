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

use crate::address::{decode_address, encode_address, qpkh32};
use crate::constants::{COINBASE_MATURITY, SEQUENCE_FINAL, SEQUENCE_RBF_ENABLED};
use crate::script::build_p2qpkh;
use crate::sighash::qpb_sighash;
use crate::types::{OutPoint, Prevout, Transaction, TxIn, TxOut};

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
    /// Block height at which this output was created.
    pub height: u32,
    /// True if this output is from a coinbase transaction.
    pub is_coinbase: bool,
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
                    height: prevout.height,
                    is_coinbase: prevout.is_coinbase,
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

    /// Create and sign a transaction sending to an address.
    ///
    /// # Arguments
    /// * `recipient` - Destination address
    /// * `amount` - Amount to send in satoshis
    /// * `fee_rate` - Fee rate in sat/vB
    /// * `utxos` - Available UTXOs from the node
    /// * `current_height` - Current block height (for coinbase maturity)
    /// * `rbf` - Enable BIP125 RBF opt-in (allows fee bumping)
    ///
    /// # Returns
    /// * Signed transaction ready for broadcast
    pub fn create_transaction(
        &mut self,
        recipient: &str,
        amount: u64,
        fee_rate: u64,
        utxos: Vec<(String, u32, Prevout)>,
        current_height: u32,
        rbf: bool,
    ) -> Result<Transaction> {
        // Decode recipient address to get scriptPubKey
        let decoded = decode_address(recipient).map_err(|e| anyhow!("invalid address: {}", e))?;
        let recipient_spk = decoded.script_pubkey;

        // Get wallet UTXOs and filter out immature coinbase outputs
        let all_wallet_utxos = self.list_unspent(|| utxos)?;
        let wallet_utxos: Vec<WalletUtxo> = all_wallet_utxos
            .into_iter()
            .filter(|u| {
                if u.is_coinbase {
                    let confirmations = current_height.saturating_sub(u.height);
                    confirmations >= COINBASE_MATURITY
                } else {
                    true
                }
            })
            .collect();

        if wallet_utxos.is_empty() {
            return Err(anyhow!("no mature UTXOs available"));
        }

        // Estimate transaction size for fee calculation
        // Base size: ~10 bytes (version + locktime + counts)
        // Per input: ~41 bytes base + witness (sig ~3310 + pk ~1953 + overhead ~10)
        // Per output: ~43 bytes (8 value + 1 len + 34 scriptPubKey)
        let input_weight = 41 * 4 + (3310 + 1953 + 10); // ~5314 WU per input
        let output_weight = 43 * 4; // 172 WU per output
        let base_weight = 10 * 4; // 40 WU

        // Select coins (simple largest-first algorithm)
        let selected = select_coins(
            &wallet_utxos,
            amount,
            fee_rate,
            input_weight,
            output_weight,
            base_weight,
        )?;

        // Calculate fee based on actual selection
        let num_inputs = selected.utxos.len();
        let num_outputs = if selected.change > 0 { 2 } else { 1 };
        let total_weight =
            base_weight + (num_inputs * input_weight) + (num_outputs * output_weight);
        let vsize = total_weight.div_ceil(4);
        let fee = vsize as u64 * fee_rate;

        // Verify we have enough
        if selected.total < amount + fee {
            return Err(anyhow!(
                "insufficient funds: have {}, need {} + {} fee",
                selected.total,
                amount,
                fee
            ));
        }

        let change = selected.total - amount - fee;

        // Build transaction inputs
        let mut vin = Vec::with_capacity(num_inputs);
        let mut prevouts = Vec::with_capacity(num_inputs);
        let mut input_addresses = Vec::with_capacity(num_inputs);

        for utxo in &selected.utxos {
            let mut txid = [0u8; 32];
            let txid_bytes = hex::decode(&utxo.txid)?;
            txid.copy_from_slice(&txid_bytes);

            // Use RBF-signaling sequence if requested, otherwise final
            let sequence = if rbf {
                SEQUENCE_RBF_ENABLED
            } else {
                SEQUENCE_FINAL
            };

            vin.push(TxIn {
                prevout: OutPoint {
                    txid,
                    vout: utxo.vout,
                },
                script_sig: Vec::new(), // SegWit: empty script_sig
                sequence,
                witness: Vec::new(), // Will be filled after signing
            });

            prevouts.push(Prevout {
                value: utxo.value,
                script_pubkey: hex::decode(&utxo.script_pubkey)?,
                height: utxo.height,
                is_coinbase: utxo.is_coinbase,
            });

            input_addresses.push(utxo.address.clone());
        }

        // Build transaction outputs
        let mut vout = Vec::with_capacity(num_outputs);

        // Recipient output
        vout.push(TxOut {
            value: amount,
            script_pubkey: recipient_spk,
        });

        // Change output (if any)
        if change > 0 {
            // Use first wallet address for change, or generate new one
            let change_address = if self.file.keys.is_empty() {
                self.get_new_address("change")?
            } else {
                self.file.keys[0].address.clone()
            };
            let change_decoded = decode_address(&change_address)
                .map_err(|e| anyhow!("invalid change address: {}", e))?;
            vout.push(TxOut {
                value: change,
                script_pubkey: change_decoded.script_pubkey,
            });
        }

        let mut tx = Transaction {
            version: 1,
            vin,
            vout,
            lock_time: 0,
        };

        // Sign each input
        for (i, address) in input_addresses.iter().enumerate() {
            let sighash_type = 0x01u8; // SIGHASH_ALL
            let msg32 = qpb_sighash(&tx, i, &prevouts, sighash_type, 0x00, None)
                .map_err(|e| anyhow!("sighash failed: {:?}", e))?;

            let sig = self.file.sign(address, &msg32)?;
            let pk_ser = self.file.get_pk_ser(address)?;

            // Witness: [sig || sighash_type, pk_ser]
            let mut sig_ser = sig;
            sig_ser.push(sighash_type);

            tx.vin[i].witness = vec![sig_ser, pk_ser];
        }

        Ok(tx)
    }
}

/// Result of coin selection.
#[derive(Debug)]
struct CoinSelection {
    /// Selected UTXOs.
    utxos: Vec<WalletUtxo>,
    /// Total value of selected UTXOs.
    total: u64,
    /// Change amount (may be 0).
    change: u64,
}

/// Select coins using largest-first algorithm.
///
/// This is a simple algorithm that selects UTXOs from largest to smallest
/// until we have enough to cover the target amount plus estimated fees.
fn select_coins(
    available: &[WalletUtxo],
    target: u64,
    fee_rate: u64,
    input_weight: usize,
    output_weight: usize,
    base_weight: usize,
) -> Result<CoinSelection> {
    // Sort by value descending (largest first)
    let mut sorted: Vec<_> = available.iter().collect();
    sorted.sort_by(|a, b| b.value.cmp(&a.value));

    let mut selected = Vec::new();
    let mut total = 0u64;

    for utxo in sorted {
        selected.push(utxo.clone());
        total += utxo.value;

        // Calculate fee for current selection
        let num_inputs = selected.len();
        // Assume 2 outputs (recipient + change)
        let num_outputs = 2;
        let total_weight =
            base_weight + (num_inputs * input_weight) + (num_outputs * output_weight);
        let vsize = total_weight.div_ceil(4);
        let fee = vsize as u64 * fee_rate;

        if total >= target + fee {
            let change = total - target - fee;
            return Ok(CoinSelection {
                utxos: selected,
                total,
                change,
            });
        }
    }

    // Not enough funds
    let needed = {
        let num_inputs = selected.len().max(1);
        let total_weight = base_weight + (num_inputs * input_weight) + (2 * output_weight);
        let vsize = total_weight.div_ceil(4);
        target + (vsize as u64 * fee_rate)
    };
    Err(anyhow!(
        "insufficient funds: have {}, need approximately {}",
        total,
        needed
    ))
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
