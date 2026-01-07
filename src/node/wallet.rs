//! Wallet storage and key management for QPB node.
//!
//! Provides persistent key storage, address tracking, and UTXO management
//! for wallet integration with the node.
//!
//! ## Encryption
//!
//! Wallets can be encrypted at rest using AES-256-GCM with Argon2id key derivation.
//! When encrypted, secret keys are stored as ciphertext and require a password to unlock.
//!
//! - **Version 1**: Legacy unencrypted format (keys stored as plaintext hex)
//! - **Version 2**: Supports both encrypted and unencrypted modes

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng},
};
use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use pqcrypto_dilithium::dilithium3::{SecretKey, detached_sign, keypair, secret_key_bytes};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PKTrait, SecretKey as SKTrait};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::address::{decode_address, encode_address, qpkh32};
use crate::constants::{COINBASE_MATURITY, SEQUENCE_FINAL, SEQUENCE_RBF_ENABLED};
use crate::script::build_p2qpkh;
use crate::sighash::qpb_sighash;
use crate::types::{OutPoint, Prevout, Transaction, TxIn, TxOut};

/// Algorithm ID for ML-DSA-65 (Dilithium3).
const MLDSA_ALG_ID: u8 = 0x11;

/// Algorithm ID for SHRINCS.
#[cfg(feature = "shrincs-dev")]
const SHRINCS_ALG_ID: u8 = 0x30;

/// Current wallet format version.
/// v2: encryption support
/// v3: multi-algorithm support (alg_id field, SHRINCS signing state)
const WALLET_VERSION: u32 = 3;

/// Argon2id parameters for key derivation.
/// These provide good security while keeping unlock time reasonable (~1 second).
const ARGON2_M_COST: u32 = 65536; // 64 MiB memory
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 1; // 1 parallel lane
const ARGON2_OUTPUT_LEN: usize = 32; // 256-bit key

/// Salt length for Argon2.
const SALT_LEN: usize = 32;

/// Nonce length for AES-256-GCM.
const NONCE_LEN: usize = 12;

/// A key entry in the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletKey {
    /// Serialized public key (alg_id || pk).
    pub pk_ser_hex: String,
    /// Secret key (hex encoded). Stored encrypted when wallet is locked.
    /// For ML-DSA: raw secret key bytes.
    /// For SHRINCS: sk_seed(32) || pk_seed(32) || prf_key(32) = 96 bytes.
    pub sk_hex: String,
    /// Derived P2QPKH address.
    pub address: String,
    /// Label for the key (optional).
    #[serde(default)]
    pub label: String,
    /// Algorithm ID (0x11 = ML-DSA, 0x30 = SHRINCS). Defaults to ML-DSA for v2 wallets.
    #[serde(default = "default_alg_id")]
    pub alg_id: u8,
    /// SHRINCS signing state (hex encoded, only for SHRINCS keys).
    /// Must be persisted after each signature to prevent key reuse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_state_hex: Option<String>,
}

/// Default algorithm ID for backward compatibility with v2 wallets.
fn default_alg_id() -> u8 {
    MLDSA_ALG_ID
}

/// Encryption metadata for encrypted wallets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMeta {
    /// Argon2id salt (hex encoded, 32 bytes).
    pub salt: String,
    /// AES-GCM nonce (hex encoded, 12 bytes).
    pub nonce: String,
}

/// Wallet file format (version 2 with optional encryption).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletFile {
    /// Wallet format version.
    pub version: u32,
    /// Network (devnet, testnet, mainnet).
    pub network: String,
    /// Human-readable prefix for addresses.
    pub hrp: String,
    /// Whether the wallet is encrypted.
    #[serde(default)]
    pub encrypted: bool,
    /// Encryption metadata (only present when encrypted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionMeta>,
    /// Encrypted keys blob (hex encoded ciphertext, only when encrypted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    /// Keys stored in the wallet (only present when not encrypted).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<WalletKey>,
}

// ============================================================================
// Encryption Helper Functions
// ============================================================================

/// Derive an encryption key from a password using Argon2id.
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| anyhow!("argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2 hash error: {}", e))?;

    Ok(key)
}

/// Encrypt data using AES-256-GCM.
fn encrypt_data(key: &[u8; 32], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("aes init error: {}", e))?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("encryption error: {}", e))
}

/// Decrypt data using AES-256-GCM.
fn decrypt_data(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("aes init error: {}", e))?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("decryption error: incorrect password or corrupted data"))
}

/// Generate random bytes for salt or nonce.
fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Simple timestamp for wallet dumps (avoids chrono dependency).
fn chrono_lite_now() -> String {
    use std::time::SystemTime;

    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs();
            // Convert Unix timestamp to ISO 8601-ish format
            // This is approximate but sufficient for wallet dumps
            let days = secs / 86400;
            let years_since_1970 = days / 365;
            let year = 1970 + years_since_1970;

            // Rough month/day calculation
            let day_of_year = days % 365;
            let month = (day_of_year / 30).min(11) + 1;
            let day = (day_of_year % 30) + 1;

            let time_of_day = secs % 86400;
            let hour = time_of_day / 3600;
            let minute = (time_of_day % 3600) / 60;
            let second = time_of_day % 60;

            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                year, month, day, hour, minute, second
            )
        }
        Err(_) => "unknown".to_string(),
    }
}

impl WalletFile {
    /// Create a new empty wallet (unencrypted).
    pub fn new(network: &str, hrp: &str) -> Self {
        Self {
            version: WALLET_VERSION,
            network: network.to_string(),
            hrp: hrp.to_string(),
            encrypted: false,
            encryption: None,
            ciphertext: None,
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

    /// Check if the wallet is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// Encrypt the wallet with a password.
    ///
    /// This encrypts all secret keys and clears the plaintext keys array.
    /// The wallet must be saved after encryption.
    pub fn encrypt(&mut self, password: &str) -> Result<()> {
        if self.encrypted {
            return Err(anyhow!("wallet is already encrypted"));
        }

        if password.is_empty() {
            return Err(anyhow!("password cannot be empty"));
        }

        // Generate salt and nonce
        let salt: [u8; SALT_LEN] = generate_random_bytes();
        let nonce: [u8; NONCE_LEN] = generate_random_bytes();

        // Derive encryption key from password
        let key = derive_key(password, &salt)?;

        // Serialize keys to JSON
        let keys_json = serde_json::to_string(&self.keys)?;

        // Encrypt the keys JSON
        let ciphertext = encrypt_data(&key, &nonce, keys_json.as_bytes())?;

        // Update wallet state
        self.encrypted = true;
        self.encryption = Some(EncryptionMeta {
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
        });
        self.ciphertext = Some(hex::encode(ciphertext));
        self.keys.clear();

        Ok(())
    }

    /// Decrypt the wallet keys with a password.
    ///
    /// Returns the decrypted keys. The wallet file itself remains encrypted on disk.
    pub fn decrypt_keys(&self, password: &str) -> Result<Vec<WalletKey>> {
        if !self.encrypted {
            return Ok(self.keys.clone());
        }

        let encryption = self
            .encryption
            .as_ref()
            .ok_or_else(|| anyhow!("encrypted wallet missing encryption metadata"))?;

        let ciphertext_hex = self
            .ciphertext
            .as_ref()
            .ok_or_else(|| anyhow!("encrypted wallet missing ciphertext"))?;

        // Decode salt and nonce
        let salt = hex::decode(&encryption.salt)?;
        let nonce_bytes = hex::decode(&encryption.nonce)?;
        let ciphertext = hex::decode(ciphertext_hex)?;

        if salt.len() != SALT_LEN {
            return Err(anyhow!("invalid salt length"));
        }
        if nonce_bytes.len() != NONCE_LEN {
            return Err(anyhow!("invalid nonce length"));
        }

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_bytes);

        // Derive key and decrypt
        let key = derive_key(password, &salt)?;
        let plaintext = decrypt_data(&key, &nonce, &ciphertext)?;

        // Parse decrypted JSON
        let keys: Vec<WalletKey> = serde_json::from_slice(&plaintext)
            .map_err(|e| anyhow!("failed to parse decrypted keys: {}", e))?;

        Ok(keys)
    }

    /// Change the wallet password.
    ///
    /// Requires the old password to decrypt, then re-encrypts with the new password.
    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        if !self.encrypted {
            return Err(anyhow!("wallet is not encrypted"));
        }

        if new_password.is_empty() {
            return Err(anyhow!("new password cannot be empty"));
        }

        // Decrypt with old password
        let keys = self.decrypt_keys(old_password)?;

        // Generate new salt and nonce
        let salt: [u8; SALT_LEN] = generate_random_bytes();
        let nonce: [u8; NONCE_LEN] = generate_random_bytes();

        // Derive new encryption key
        let key = derive_key(new_password, &salt)?;

        // Re-encrypt
        let keys_json = serde_json::to_string(&keys)?;
        let ciphertext = encrypt_data(&key, &nonce, keys_json.as_bytes())?;

        // Update wallet state
        self.encryption = Some(EncryptionMeta {
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
        });
        self.ciphertext = Some(hex::encode(ciphertext));

        Ok(())
    }

    /// Generate a new ML-DSA key and add it to the wallet.
    pub fn generate_key(&mut self, label: &str) -> Result<String> {
        self.generate_key_mldsa(label)
    }

    /// Generate a new ML-DSA-65 key.
    fn generate_key_mldsa(&mut self, label: &str) -> Result<String> {
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
            alg_id: MLDSA_ALG_ID,
            signing_state_hex: None,
        };

        self.keys.push(key);
        Ok(address)
    }

    /// Generate a new SHRINCS key and add it to the wallet.
    #[cfg(feature = "shrincs-dev")]
    pub fn generate_key_shrincs(&mut self, label: &str) -> Result<String> {
        use crate::pq::shrincs_keypair;

        let (pk_ser, key_material, signing_state) =
            shrincs_keypair().map_err(|e| anyhow!("SHRINCS keygen failed: {:?}", e))?;

        // Serialize secret key seeds: sk_seed || pk_seed || prf_key = 96 bytes
        let mut sk_bytes = Vec::with_capacity(96);
        sk_bytes.extend_from_slice(&key_material.sk.sk_seed);
        sk_bytes.extend_from_slice(&key_material.sk.pk_seed);
        sk_bytes.extend_from_slice(&key_material.sk.prf_key);

        // Serialize signing state
        let state_bytes = signing_state.to_bytes();

        // Compute address
        let qpkh = qpkh32(&pk_ser);
        let address = encode_address(&self.hrp, 3, &qpkh).map_err(|e| anyhow!("{}", e))?;

        let key = WalletKey {
            pk_ser_hex: hex::encode(&pk_ser),
            sk_hex: hex::encode(&sk_bytes),
            address: address.clone(),
            label: label.to_string(),
            alg_id: SHRINCS_ALG_ID,
            signing_state_hex: Some(hex::encode(&state_bytes)),
        };

        self.keys.push(key);
        Ok(address)
    }

    /// Generate a new key with specified algorithm.
    pub fn generate_key_with_algorithm(&mut self, label: &str, algorithm: &str) -> Result<String> {
        match algorithm.to_lowercase().as_str() {
            "mldsa" | "ml-dsa" | "dilithium" => self.generate_key_mldsa(label),
            #[cfg(feature = "shrincs-dev")]
            "shrincs" => self.generate_key_shrincs(label),
            _ => Err(anyhow!(
                "Unknown algorithm: {}. Supported: mldsa, shrincs",
                algorithm
            )),
        }
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
    /// Note: For SHRINCS keys, use sign_mut() instead as it updates signing state.
    pub fn sign(&self, address: &str, msg32: &[u8; 32]) -> Result<Vec<u8>> {
        let key = self
            .find_key(address)
            .ok_or_else(|| anyhow!("address not in wallet"))?;

        match key.alg_id {
            MLDSA_ALG_ID | 0 => {
                // ML-DSA signing (stateless)
                let sk_bytes = hex::decode(&key.sk_hex)?;
                if sk_bytes.len() != secret_key_bytes() {
                    return Err(anyhow!("invalid ML-DSA secret key length"));
                }
                let sk = SecretKey::from_bytes(&sk_bytes).map_err(|e| anyhow!("{:?}", e))?;
                let sig = detached_sign(msg32, &sk);
                Ok(sig.as_bytes().to_vec())
            }
            #[cfg(feature = "shrincs-dev")]
            SHRINCS_ALG_ID => Err(anyhow!(
                "SHRINCS signing requires mutable wallet access - use sign_mut()"
            )),
            _ => Err(anyhow!("Unknown algorithm ID: 0x{:02x}", key.alg_id)),
        }
    }

    /// Sign a message with the key for a given address (mutable version for SHRINCS).
    pub fn sign_mut(&mut self, address: &str, msg32: &[u8; 32]) -> Result<Vec<u8>> {
        // Find key index first to avoid borrow issues
        let key_idx = self
            .keys
            .iter()
            .position(|k| k.address == address)
            .ok_or_else(|| anyhow!("address not in wallet"))?;

        let alg_id = self.keys[key_idx].alg_id;

        match alg_id {
            MLDSA_ALG_ID | 0 => {
                // ML-DSA signing (stateless) - delegate to immutable version
                let sk_bytes = hex::decode(&self.keys[key_idx].sk_hex)?;
                if sk_bytes.len() != secret_key_bytes() {
                    return Err(anyhow!("invalid ML-DSA secret key length"));
                }
                let sk = SecretKey::from_bytes(&sk_bytes).map_err(|e| anyhow!("{:?}", e))?;
                let sig = detached_sign(msg32, &sk);
                Ok(sig.as_bytes().to_vec())
            }
            #[cfg(feature = "shrincs-dev")]
            SHRINCS_ALG_ID => self.sign_shrincs(key_idx, msg32),
            _ => Err(anyhow!("Unknown algorithm ID: 0x{:02x}", alg_id)),
        }
    }

    /// Sign with SHRINCS key (stateful - updates signing state).
    #[cfg(feature = "shrincs-dev")]
    fn sign_shrincs(&mut self, key_idx: usize, msg32: &[u8; 32]) -> Result<Vec<u8>> {
        use crate::pq::shrincs_sign;
        use crate::shrincs::shrincs::{ShrincsFullParams, keygen_from_seeds};
        use crate::shrincs::state::SigningState;

        let key = &self.keys[key_idx];

        // Decode secret key seeds (96 bytes: sk_seed || pk_seed || prf_key)
        let sk_bytes = hex::decode(&key.sk_hex)?;
        if sk_bytes.len() != 96 {
            return Err(anyhow!(
                "invalid SHRINCS secret key length: expected 96, got {}",
                sk_bytes.len()
            ));
        }

        let sk_seed: [u8; 32] = sk_bytes[0..32].try_into().unwrap();
        let pk_seed: [u8; 32] = sk_bytes[32..64].try_into().unwrap();
        let prf_key: [u8; 32] = sk_bytes[64..96].try_into().unwrap();

        // Decode signing state
        let state_hex = key
            .signing_state_hex
            .as_ref()
            .ok_or_else(|| anyhow!("SHRINCS key missing signing state"))?;
        let state_bytes = hex::decode(state_hex)?;
        let mut signing_state = SigningState::from_bytes(&state_bytes)
            .map_err(|e| anyhow!("invalid signing state: {:?}", e))?;

        // Reconstruct key material from seeds
        let params = ShrincsFullParams::LEVEL1_2_30;
        let (key_material, _) = keygen_from_seeds(sk_seed, pk_seed, prf_key, params)
            .map_err(|e| anyhow!("failed to reconstruct key material: {:?}", e))?;

        // Sign (updates state)
        let sig = shrincs_sign(&key_material, &mut signing_state, msg32, 0x01)
            .map_err(|e| anyhow!("SHRINCS signing failed: {:?}", e))?;

        // Update signing state in wallet
        let new_state_bytes = signing_state.to_bytes();
        self.keys[key_idx].signing_state_hex = Some(hex::encode(&new_state_bytes));

        Ok(sig)
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
    /// Number of confirmations (current_height - height + 1).
    pub confirmations: u32,
    /// True if this output is from a coinbase transaction.
    pub is_coinbase: bool,
}

/// Wallet state integrated with the node.
///
/// For encrypted wallets, decrypted keys are held in memory only when unlocked.
/// The wallet can be set to auto-lock after a timeout.
pub struct Wallet {
    /// The wallet file with keys (encrypted keys stored on disk).
    pub file: WalletFile,
    /// Path to wallet file.
    pub path: std::path::PathBuf,
    /// Decrypted keys held in memory when wallet is unlocked.
    /// None if wallet is locked (or unencrypted - uses file.keys directly).
    unlocked_keys: Option<Vec<WalletKey>>,
    /// Derived encryption key (stored while unlocked for re-encryption).
    /// This is the Argon2id-derived 256-bit key, NOT the password.
    encryption_key: Option<[u8; 32]>,
    /// When the wallet should auto-lock (None = no auto-lock).
    unlock_until: Option<Instant>,
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("file", &self.file)
            .field("path", &self.path)
            .field(
                "unlocked_keys",
                &self
                    .unlocked_keys
                    .as_ref()
                    .map(|k| format!("[{} keys]", k.len())),
            )
            .field("encryption_key", &self.encryption_key.map(|_| "[REDACTED]"))
            .field("unlock_until", &self.unlock_until)
            .finish()
    }
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
            unlocked_keys: None,
            encryption_key: None,
            unlock_until: None,
        })
    }

    /// Load an existing wallet.
    pub fn load(path: &Path) -> Result<Self> {
        let file = WalletFile::load(path)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            unlocked_keys: None,
            encryption_key: None,
            unlock_until: None,
        })
    }

    // ========================================================================
    // Encryption / Locking
    // ========================================================================

    /// Check if the wallet is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.file.encrypted
    }

    /// Check if the wallet is unlocked (ready for signing).
    ///
    /// For unencrypted wallets, this always returns true.
    /// For encrypted wallets, returns true only if unlocked and not timed out.
    pub fn is_unlocked(&self) -> bool {
        if !self.file.encrypted {
            return true;
        }
        // Check if unlocked and not expired
        if let Some(keys) = &self.unlocked_keys {
            if let Some(until) = self.unlock_until
                && Instant::now() > until
            {
                return false; // Timed out
            }
            !keys.is_empty() || self.unlocked_keys.is_some()
        } else {
            false
        }
    }

    /// Encrypt the wallet with a password.
    ///
    /// This encrypts all keys and saves the wallet. After encryption,
    /// the wallet will need to be unlocked with `unlock()` before signing.
    pub fn encrypt_wallet(&mut self, password: &str) -> Result<()> {
        if self.file.encrypted {
            return Err(anyhow!("wallet is already encrypted"));
        }
        self.file.encrypt(password)?;
        self.save()?;
        Ok(())
    }

    /// Unlock an encrypted wallet for signing operations.
    ///
    /// # Arguments
    /// * `password` - The wallet password
    /// * `timeout_secs` - Optional timeout in seconds (0 = no timeout)
    pub fn unlock(&mut self, password: &str, timeout_secs: u64) -> Result<()> {
        if !self.file.encrypted {
            return Err(anyhow!("wallet is not encrypted"));
        }

        // Get encryption metadata
        let encryption = self
            .file
            .encryption
            .as_ref()
            .ok_or_else(|| anyhow!("encrypted wallet missing encryption metadata"))?;
        let salt = hex::decode(&encryption.salt)?;

        // Derive encryption key from password
        let key = derive_key(password, &salt)?;

        // Decrypt keys using the derived key
        let keys = self.file.decrypt_keys(password)?;

        self.unlocked_keys = Some(keys);
        self.encryption_key = Some(key);

        // Set timeout if specified
        if timeout_secs > 0 {
            self.unlock_until = Some(Instant::now() + Duration::from_secs(timeout_secs));
        } else {
            self.unlock_until = None;
        }

        Ok(())
    }

    /// Lock the wallet, clearing decrypted keys and encryption key from memory.
    pub fn lock(&mut self) {
        // Securely clear the encryption key
        if let Some(ref mut key) = self.encryption_key {
            key.fill(0);
        }
        self.unlocked_keys = None;
        self.encryption_key = None;
        self.unlock_until = None;
    }

    /// Change the wallet password.
    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        self.file.change_password(old_password, new_password)?;
        self.save()?;
        // Re-unlock with new password if was unlocked
        if self.unlocked_keys.is_some() {
            let timeout = self
                .unlock_until
                .map(|u| u.saturating_duration_since(Instant::now()).as_secs())
                .unwrap_or(0);
            self.unlock(new_password, timeout)?;
        }
        Ok(())
    }

    /// Save the wallet.
    pub fn save(&self) -> Result<()> {
        self.file.save(&self.path)
    }

    /// Generate a new address.
    ///
    /// For encrypted wallets, this requires the wallet to be unlocked.
    /// The new key is added to both the in-memory unlocked keys and
    /// re-encrypted to the on-disk ciphertext.
    pub fn get_new_address(&mut self, label: &str) -> Result<String> {
        if self.file.encrypted && self.unlocked_keys.is_none() {
            return Err(anyhow!(
                "wallet is locked; unlock first to generate new address"
            ));
        }

        // Generate the new key
        let (pk, sk) = keypair();
        let pk_bytes = pk.as_bytes();
        let sk_bytes = sk.as_bytes();

        // Serialize public key with algorithm ID prefix
        let mut pk_ser = Vec::with_capacity(1 + pk_bytes.len());
        pk_ser.push(MLDSA_ALG_ID);
        pk_ser.extend_from_slice(pk_bytes);

        // Compute address
        let qpkh = qpkh32(&pk_ser);
        let address = encode_address(&self.file.hrp, 3, &qpkh).map_err(|e| anyhow!("{}", e))?;

        let key = WalletKey {
            pk_ser_hex: hex::encode(&pk_ser),
            sk_hex: hex::encode(sk_bytes),
            address: address.clone(),
            label: label.to_string(),
            alg_id: MLDSA_ALG_ID,
            signing_state_hex: None,
        };

        if self.file.encrypted {
            // Add to unlocked keys and re-encrypt
            let keys = self.unlocked_keys.as_mut().unwrap();
            keys.push(key);
            self.sync_encrypted_keys()?;
        } else {
            // Add directly to file keys
            self.file.keys.push(key);
        }

        self.save()?;
        Ok(address)
    }

    /// Sync unlocked keys back to encrypted ciphertext.
    ///
    /// This re-encrypts the keys with a new nonce for forward secrecy.
    fn sync_encrypted_keys(&mut self) -> Result<()> {
        if !self.file.encrypted {
            return Ok(());
        }

        let keys = self
            .unlocked_keys
            .as_ref()
            .ok_or_else(|| anyhow!("cannot sync: wallet is locked"))?;

        let encryption_key = self
            .encryption_key
            .ok_or_else(|| anyhow!("cannot sync: encryption key not available"))?;

        // Generate new nonce for forward secrecy
        let nonce: [u8; NONCE_LEN] = generate_random_bytes();

        // Serialize keys to JSON
        let keys_json = serde_json::to_string(keys)?;

        // Encrypt the keys JSON
        let ciphertext = encrypt_data(&encryption_key, &nonce, keys_json.as_bytes())?;

        // Update wallet file with new ciphertext and nonce
        if let Some(ref mut encryption) = self.file.encryption {
            encryption.nonce = hex::encode(nonce);
        }
        self.file.ciphertext = Some(hex::encode(ciphertext));

        Ok(())
    }

    /// Get the keys to use for operations.
    ///
    /// For unencrypted wallets, returns file keys.
    /// For encrypted wallets, returns unlocked keys (requires unlock first).
    /// Returns error if wallet is locked or unlock timeout has expired.
    fn get_active_keys(&self) -> Result<&Vec<WalletKey>> {
        if self.file.encrypted {
            // Check if timed out
            if let Some(until) = self.unlock_until
                && Instant::now() > until
            {
                return Err(anyhow!("wallet unlock has timed out"));
            }
            self.unlocked_keys
                .as_ref()
                .ok_or_else(|| anyhow!("wallet is locked"))
        } else {
            Ok(&self.file.keys)
        }
    }

    /// Compute script pubkeys from a set of keys.
    fn compute_script_pubkeys(keys: &[WalletKey]) -> Result<HashSet<Vec<u8>>> {
        let mut spks = HashSet::new();
        for key in keys {
            let pk_ser = hex::decode(&key.pk_ser_hex)?;
            let qpkh = qpkh32(&pk_ser);
            let spk = build_p2qpkh(qpkh);
            spks.insert(spk);
        }
        Ok(spks)
    }

    /// Find a key by address.
    fn find_key_by_address<'a>(keys: &'a [WalletKey], address: &str) -> Option<&'a WalletKey> {
        keys.iter().find(|k| k.address == address)
    }

    /// Find a key by scriptPubKey.
    fn find_key_by_script(keys: &[WalletKey], spk: &[u8]) -> Option<WalletKey> {
        for key in keys {
            if let Ok(pk_ser) = hex::decode(&key.pk_ser_hex) {
                let qpkh = qpkh32(&pk_ser);
                let key_spk = build_p2qpkh(qpkh);
                if key_spk == spk {
                    return Some(key.clone());
                }
            }
        }
        None
    }

    /// Get wallet balance by filtering UTXO set.
    ///
    /// For encrypted wallets, requires the wallet to be unlocked.
    pub fn get_balance<F>(&self, utxo_iter: F) -> Result<u64>
    where
        F: FnOnce() -> Vec<(String, u32, Prevout)>,
    {
        let keys = self.get_active_keys()?;
        let spks = Self::compute_script_pubkeys(keys)?;
        let utxos = utxo_iter();
        let balance: u64 = utxos
            .iter()
            .filter(|(_, _, prevout)| spks.contains(&prevout.script_pubkey))
            .map(|(_, _, prevout)| prevout.value)
            .sum();
        Ok(balance)
    }

    /// List wallet UTXOs.
    ///
    /// For encrypted wallets, requires the wallet to be unlocked.
    pub fn list_unspent<F>(&self, utxo_iter: F, current_height: u32) -> Result<Vec<WalletUtxo>>
    where
        F: FnOnce() -> Vec<(String, u32, Prevout)>,
    {
        let keys = self.get_active_keys()?;
        let spks = Self::compute_script_pubkeys(keys)?;
        let utxos = utxo_iter();

        let mut wallet_utxos = Vec::new();
        for (txid_hex, vout, prevout) in utxos {
            if spks.contains(&prevout.script_pubkey) {
                // Find the address for this UTXO
                let address = Self::find_key_by_script(keys, &prevout.script_pubkey)
                    .map(|k| k.address)
                    .unwrap_or_default();

                // Calculate confirmations: current_height - utxo_height
                // This matches the codebase convention of "blocks built on top"
                // Height 0 means unconfirmed (mempool), so confirmations = 0
                let confirmations = current_height.saturating_sub(prevout.height);

                wallet_utxos.push(WalletUtxo {
                    txid: txid_hex,
                    vout,
                    address,
                    value: prevout.value,
                    script_pubkey: hex::encode(&prevout.script_pubkey),
                    height: prevout.height,
                    confirmations,
                    is_coinbase: prevout.is_coinbase,
                });
            }
        }

        Ok(wallet_utxos)
    }

    /// Sign a message with a wallet key.
    ///
    /// For encrypted wallets, requires the wallet to be unlocked.
    /// Note: For SHRINCS keys, use sign_mut() instead as it updates signing state.
    pub fn sign(&self, address: &str, msg32: &[u8; 32]) -> Result<Vec<u8>> {
        let keys = self.get_active_keys()?;
        let key = Self::find_key_by_address(keys, address)
            .ok_or_else(|| anyhow!("address not in wallet"))?;

        match key.alg_id {
            MLDSA_ALG_ID | 0 => {
                let sk_bytes = hex::decode(&key.sk_hex)?;
                if sk_bytes.len() != secret_key_bytes() {
                    return Err(anyhow!("invalid ML-DSA secret key length"));
                }
                let sk = SecretKey::from_bytes(&sk_bytes).map_err(|e| anyhow!("{:?}", e))?;
                let sig = detached_sign(msg32, &sk);
                Ok(sig.as_bytes().to_vec())
            }
            #[cfg(feature = "shrincs-dev")]
            SHRINCS_ALG_ID => Err(anyhow!(
                "SHRINCS signing requires mutable wallet access - use sign_mut()"
            )),
            _ => Err(anyhow!("Unknown algorithm ID: 0x{:02x}", key.alg_id)),
        }
    }

    /// Sign a message with a wallet key (mutable version for SHRINCS).
    ///
    /// For encrypted wallets, requires the wallet to be unlocked.
    /// For SHRINCS keys, updates and persists signing state.
    pub fn sign_mut(&mut self, address: &str, msg32: &[u8; 32]) -> Result<Vec<u8>> {
        let keys = self.get_active_keys()?;
        let key = Self::find_key_by_address(keys, address)
            .ok_or_else(|| anyhow!("address not in wallet"))?
            .clone(); // Clone to avoid borrow issues

        match key.alg_id {
            MLDSA_ALG_ID | 0 => {
                let sk_bytes = hex::decode(&key.sk_hex)?;
                if sk_bytes.len() != secret_key_bytes() {
                    return Err(anyhow!("invalid ML-DSA secret key length"));
                }
                let sk = SecretKey::from_bytes(&sk_bytes).map_err(|e| anyhow!("{:?}", e))?;
                let sig = detached_sign(msg32, &sk);
                Ok(sig.as_bytes().to_vec())
            }
            #[cfg(feature = "shrincs-dev")]
            SHRINCS_ALG_ID => self.sign_shrincs_encrypted(&key, msg32),
            _ => Err(anyhow!("Unknown algorithm ID: 0x{:02x}", key.alg_id)),
        }
    }

    /// Sign with SHRINCS key in encrypted wallet (stateful - updates signing state).
    #[cfg(feature = "shrincs-dev")]
    fn sign_shrincs_encrypted(&mut self, key: &WalletKey, msg32: &[u8; 32]) -> Result<Vec<u8>> {
        use crate::pq::shrincs_sign;
        use crate::shrincs::shrincs::{ShrincsFullParams, keygen_from_seeds};
        use crate::shrincs::state::SigningState;

        // Decode secret key seeds (96 bytes: sk_seed || pk_seed || prf_key)
        let sk_bytes = hex::decode(&key.sk_hex)?;
        if sk_bytes.len() != 96 {
            return Err(anyhow!(
                "invalid SHRINCS secret key length: expected 96, got {}",
                sk_bytes.len()
            ));
        }

        let sk_seed: [u8; 32] = sk_bytes[0..32].try_into().unwrap();
        let pk_seed: [u8; 32] = sk_bytes[32..64].try_into().unwrap();
        let prf_key: [u8; 32] = sk_bytes[64..96].try_into().unwrap();

        // Decode signing state
        let state_hex = key
            .signing_state_hex
            .as_ref()
            .ok_or_else(|| anyhow!("SHRINCS key missing signing state"))?;
        let state_bytes = hex::decode(state_hex)?;
        let mut signing_state = SigningState::from_bytes(&state_bytes)
            .map_err(|e| anyhow!("invalid signing state: {:?}", e))?;

        // Reconstruct key material from seeds
        let params = ShrincsFullParams::LEVEL1_2_30;
        let (key_material, _) = keygen_from_seeds(sk_seed, pk_seed, prf_key, params)
            .map_err(|e| anyhow!("failed to reconstruct key material: {:?}", e))?;

        // Sign (updates state)
        let sig = shrincs_sign(&key_material, &mut signing_state, msg32, 0x01)
            .map_err(|e| anyhow!("SHRINCS signing failed: {:?}", e))?;

        // Update signing state in the appropriate key store
        let new_state_bytes = signing_state.to_bytes();
        let new_state_hex = hex::encode(&new_state_bytes);

        // Update in file.keys (for unencrypted) or unlocked_keys (for encrypted)
        if self.file.encrypted
            && let Some(ref mut unlocked) = self.unlocked_keys
            && let Some(k) = unlocked.iter_mut().find(|k| k.address == key.address)
        {
            k.signing_state_hex = Some(new_state_hex.clone());
        }
        // Always update file.keys for persistence
        if let Some(k) = self.file.keys.iter_mut().find(|k| k.address == key.address) {
            k.signing_state_hex = Some(new_state_hex);
        }

        // Save wallet to persist state
        self.save()?;

        Ok(sig)
    }

    /// Get all addresses.
    ///
    /// For encrypted wallets, requires the wallet to be unlocked.
    pub fn addresses(&self) -> Result<Vec<String>> {
        let keys = self.get_active_keys()?;
        Ok(keys.iter().map(|k| k.address.clone()).collect())
    }

    /// Get the serialized public key for an address.
    ///
    /// For encrypted wallets, requires the wallet to be unlocked.
    pub fn get_pk_ser(&self, address: &str) -> Result<Vec<u8>> {
        let keys = self.get_active_keys()?;
        let key = Self::find_key_by_address(keys, address)
            .ok_or_else(|| anyhow!("address not in wallet"))?;
        Ok(hex::decode(&key.pk_ser_hex)?)
    }

    // ========================================================================
    // Backup / Dump
    // ========================================================================

    /// Create a backup of the wallet file.
    ///
    /// This copies the wallet file to the destination path. For encrypted wallets,
    /// the backup contains encrypted keys and can be safely copied without unlocking.
    pub fn backup(&self, destination: &Path) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = destination.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent)?;
        }

        // Copy the wallet file
        fs::copy(&self.path, destination)?;
        Ok(())
    }

    /// Dump wallet keys to a human-readable text file.
    ///
    /// For encrypted wallets, this requires the wallet to be unlocked.
    /// The output format includes secret keys, public keys, addresses, and labels.
    ///
    /// **WARNING**: The dump file contains plaintext secret keys and should
    /// be handled with extreme care. Consider encrypting the file after export.
    pub fn dump_keys(&self) -> Result<String> {
        use std::fmt::Write;

        let keys = self.get_active_keys()?;

        let mut output = String::new();

        // Header
        writeln!(output, "# QPB Wallet Dump")?;
        writeln!(output, "# Created: {}", chrono_lite_now())?;
        writeln!(output, "# Network: {}", self.file.network)?;
        writeln!(output, "# HRP: {}", self.file.hrp)?;
        writeln!(output, "# Keys: {}", keys.len())?;
        writeln!(output, "#")?;
        writeln!(
            output,
            "# WARNING: This file contains plaintext secret keys!"
        )?;
        writeln!(
            output,
            "# Store securely and delete after import/verification."
        )?;
        writeln!(output, "#")?;
        writeln!(output, "# Format: secretkey pubkey address label")?;
        writeln!(output)?;

        // Keys
        for key in keys {
            let label = if key.label.is_empty() {
                "-"
            } else {
                &key.label
            };
            writeln!(
                output,
                "{} {} {} {}",
                key.sk_hex, key.pk_ser_hex, key.address, label
            )?;
        }

        writeln!(output)?;
        writeln!(output, "# End of dump")?;

        Ok(output)
    }

    /// Import keys from a wallet dump file.
    ///
    /// For encrypted wallets, this requires the wallet to be unlocked.
    /// Keys that already exist (by address) are skipped.
    ///
    /// Returns the number of keys imported.
    pub fn import_dump(&mut self, dump_content: &str) -> Result<usize> {
        let mut imported = 0;

        for line in dump_content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse: secretkey pubkey address [label]
            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            if parts.len() < 3 {
                continue; // Skip malformed lines
            }

            let sk_hex = parts[0];
            let pk_ser_hex = parts[1];
            let address = parts[2];
            let label = parts.get(3).unwrap_or(&"imported");

            // Verify the secret key is valid hex and correct length
            let sk_bytes = hex::decode(sk_hex)
                .map_err(|_| anyhow!("invalid secret key hex for address {}", address))?;

            if sk_bytes.len() != pqcrypto_dilithium::dilithium3::secret_key_bytes() {
                return Err(anyhow!(
                    "invalid secret key length for address {} (expected {}, got {})",
                    address,
                    pqcrypto_dilithium::dilithium3::secret_key_bytes(),
                    sk_bytes.len()
                ));
            }

            // Verify the secret key parses correctly
            let _ = pqcrypto_dilithium::dilithium3::SecretKey::from_bytes(&sk_bytes)
                .map_err(|e| anyhow!("invalid secret key: {:?}", e))?;

            // Verify the public key
            let pk_ser = hex::decode(pk_ser_hex)
                .map_err(|_| anyhow!("invalid public key hex for address {}", address))?;

            // Verify address matches the public key
            let qpkh = qpkh32(&pk_ser);
            let derived_address =
                encode_address(&self.file.hrp, 3, &qpkh).map_err(|e| anyhow!("{}", e))?;

            if derived_address != address {
                return Err(anyhow!(
                    "address mismatch: dump says {}, key derives to {}",
                    address,
                    derived_address
                ));
            }

            // Check if address already exists
            let keys = self.get_active_keys()?;
            if Self::find_key_by_address(keys, address).is_some() {
                continue; // Skip existing keys
            }

            // Add the key (imported keys are ML-DSA by default)
            let new_key = WalletKey {
                pk_ser_hex: pk_ser_hex.to_string(),
                sk_hex: sk_hex.to_string(),
                address: address.to_string(),
                label: label.to_string(),
                alg_id: MLDSA_ALG_ID,
                signing_state_hex: None,
            };

            if self.file.encrypted {
                // Add to unlocked keys and re-encrypt
                let unlocked_keys = self
                    .unlocked_keys
                    .as_mut()
                    .ok_or_else(|| anyhow!("wallet is locked"))?;
                unlocked_keys.push(new_key);
                self.sync_encrypted_keys()?;
            } else {
                self.file.keys.push(new_key);
            }

            imported += 1;
        }

        if imported > 0 {
            self.save()?;
        }

        Ok(imported)
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
        let all_wallet_utxos = self.list_unspent(|| utxos, current_height)?;
        let wallet_utxos: Vec<WalletUtxo> = all_wallet_utxos
            .into_iter()
            .filter(|u| {
                if u.is_coinbase {
                    // Use pre-computed confirmations from list_unspent
                    u.confirmations >= COINBASE_MATURITY
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
            let keys = self.get_active_keys()?;
            let change_address = if keys.is_empty() {
                self.get_new_address("change")?
            } else {
                keys[0].address.clone()
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

            let sig = self.sign(address, &msg32)?;
            let pk_ser = self.get_pk_ser(address)?;

            // Witness: [sig || sighash_type, pk_ser]
            let mut sig_ser = sig;
            sig_ser.push(sighash_type);

            tx.vin[i].witness = vec![sig_ser, pk_ser];
        }

        Ok(tx)
    }

    /// Create a replacement transaction for RBF fee bumping.
    ///
    /// Reuses the same inputs as the original transaction to guarantee
    /// conflict (required for RBF). Increases fee by reducing change output.
    ///
    /// # Arguments
    /// * `original_tx` - The original transaction to replace
    /// * `original_prevouts` - Prevouts for the original transaction's inputs
    /// * `new_fee_rate` - New fee rate in sat/vB
    ///
    /// # Returns
    /// * Signed replacement transaction
    /// * Error if change is insufficient to cover new fee
    pub fn create_replacement_transaction(
        &self,
        original_tx: &Transaction,
        original_prevouts: &[Prevout],
        new_fee_rate: u64,
    ) -> Result<Transaction> {
        if original_tx.vin.len() != original_prevouts.len() {
            return Err(anyhow!(
                "prevouts count {} doesn't match inputs {}",
                original_prevouts.len(),
                original_tx.vin.len()
            ));
        }

        if original_tx.vout.is_empty() {
            return Err(anyhow!("original transaction has no outputs"));
        }

        // Calculate input sum
        let input_sum: u64 = original_prevouts.iter().map(|p| p.value).sum();

        // Recipient is always the first output (convention from create_transaction)
        let recipient_output = original_tx.vout[0].clone();
        let recipient_amount = recipient_output.value;

        // Estimate transaction size for fee calculation
        // Same formula as create_transaction
        let input_weight = 41 * 4 + (3310 + 1953 + 10); // ~5314 WU per input
        let output_weight = 43 * 4; // 172 WU per output
        let base_weight = 10 * 4; // 40 WU

        let num_inputs = original_tx.vin.len();

        // First, try with 2 outputs (recipient + change)
        let weight_with_change = base_weight + (num_inputs * input_weight) + (2 * output_weight);
        let vsize_with_change = weight_with_change.div_ceil(4);
        let fee_with_change = vsize_with_change as u64 * new_fee_rate;

        let available_for_change = input_sum.saturating_sub(recipient_amount + fee_with_change);

        // Determine outputs based on whether change is worth including
        let (vout, _new_fee) = if available_for_change > 0 {
            // Include change output
            // Find the change address from original tx (second output if exists)
            let change_spk = if original_tx.vout.len() > 1 {
                original_tx.vout[1].script_pubkey.clone()
            } else {
                // No change in original, use first wallet address
                let keys = self.get_active_keys()?;
                if keys.is_empty() {
                    return Err(anyhow!("wallet has no keys for change output"));
                }
                let pk_ser = hex::decode(&keys[0].pk_ser_hex)?;
                let qpkh = qpkh32(&pk_ser);
                build_p2qpkh(qpkh)
            };

            let vout = vec![
                recipient_output,
                TxOut {
                    value: available_for_change,
                    script_pubkey: change_spk,
                },
            ];
            (vout, fee_with_change)
        } else {
            // No room for change - try without change output
            let weight_no_change = base_weight + (num_inputs * input_weight) + output_weight;
            let vsize_no_change = weight_no_change.div_ceil(4);
            let fee_no_change = vsize_no_change as u64 * new_fee_rate;

            if input_sum < recipient_amount + fee_no_change {
                return Err(anyhow!(
                    "insufficient funds for fee bump: need {} sats, have {} sats",
                    recipient_amount + fee_no_change,
                    input_sum
                ));
            }

            (vec![recipient_output], fee_no_change)
        };

        // Build replacement transaction with same inputs
        let mut vin = Vec::with_capacity(num_inputs);
        let mut input_addresses = Vec::with_capacity(num_inputs);
        let keys = self.get_active_keys()?;

        for (i, orig_vin) in original_tx.vin.iter().enumerate() {
            // Find the wallet key for this input
            let key = Self::find_key_by_script(keys, &original_prevouts[i].script_pubkey)
                .ok_or_else(|| anyhow!("wallet does not own input {} (cannot sign)", i))?;

            input_addresses.push(key.address.clone());

            vin.push(TxIn {
                prevout: orig_vin.prevout.clone(),
                script_sig: Vec::new(),
                sequence: SEQUENCE_RBF_ENABLED, // Always RBF for replacements
                witness: Vec::new(),
            });
        }

        let mut tx = Transaction {
            version: original_tx.version,
            vin,
            vout,
            lock_time: original_tx.lock_time,
        };

        // Sign each input
        for (i, address) in input_addresses.iter().enumerate() {
            let sighash_type = 0x01u8; // SIGHASH_ALL
            let msg32 = qpb_sighash(&tx, i, original_prevouts, sighash_type, 0x00, None)
                .map_err(|e| anyhow!("sighash failed: {:?}", e))?;

            let sig = self.sign(address, &msg32)?;
            let pk_ser = self.get_pk_ser(address)?;

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
