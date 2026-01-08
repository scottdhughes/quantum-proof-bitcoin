//! Wallet encryption integration tests.

use std::path::Path;
use tempfile::tempdir;

use qpb_consensus::node::node::Node;
use qpb_consensus::node::rpc::handle_rpc;

fn rpc_call(node: &mut Node, method: &str, params: &str) -> serde_json::Value {
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{}}}"#,
        method, params
    );
    let resp = handle_rpc(node, &req);
    serde_json::from_str(&resp).unwrap()
}

fn rpc_ok(node: &mut Node, method: &str, params: &str) -> serde_json::Value {
    let resp = rpc_call(node, method, params);
    if resp.get("error").is_some() && !resp["error"].is_null() {
        panic!("{} failed: {:?}", method, resp["error"]);
    }
    resp["result"].clone()
}

fn rpc_err(node: &mut Node, method: &str, params: &str) -> String {
    let resp = rpc_call(node, method, params);
    resp["error"]["message"]
        .as_str()
        .unwrap_or("no error")
        .to_string()
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn encryptwallet_basic() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Create wallet
    rpc_ok(&mut node, "createwallet", "[]");

    // Generate an address before encryption
    let addr = rpc_ok(&mut node, "getnewaddress", r#"["test"]"#);
    assert!(addr.is_string());

    // Check wallet info before encryption
    let info = rpc_ok(&mut node, "getwalletinfo", "[]");
    assert_eq!(info["encrypted"], false);
    assert_eq!(info["unlocked"], true);

    // Encrypt the wallet
    let result = rpc_ok(&mut node, "encryptwallet", r#"["mypassword123"]"#);
    assert!(
        result["warning"]
            .as_str()
            .unwrap()
            .contains("encrypted successfully")
    );

    // Check wallet info after encryption
    // Note: After encryption, wallet is locked so we load from disk
    let mut node2 = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();
    let info = rpc_ok(&mut node2, "getwalletinfo", "[]");
    assert_eq!(info["encrypted"], true);
    assert_eq!(info["unlocked"], false); // Locked after encryption
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn encryptwallet_cannot_encrypt_twice() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    rpc_ok(&mut node, "createwallet", "[]");
    rpc_ok(&mut node, "encryptwallet", r#"["password1"]"#);

    // Trying to encrypt again should fail
    let mut node2 = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();
    let err = rpc_err(&mut node2, "encryptwallet", r#"["password2"]"#);
    assert!(err.contains("already encrypted"));
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn walletpassphrase_unlocks_wallet() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Create and encrypt wallet
    rpc_ok(&mut node, "createwallet", "[]");
    rpc_ok(&mut node, "getnewaddress", r#"["test"]"#);
    rpc_ok(&mut node, "encryptwallet", r#"["testpass"]"#);

    // Reload node (wallet is now locked)
    let mut node2 = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Operations should fail when locked
    let err = rpc_err(&mut node2, "listaddresses", "[]");
    assert!(err.contains("locked"));

    // Unlock with password
    rpc_ok(&mut node2, "walletpassphrase", r#"["testpass", 300]"#);

    // Now operations should work
    let addresses = rpc_ok(&mut node2, "listaddresses", "[]");
    assert!(addresses.is_array());
    assert!(!addresses.as_array().unwrap().is_empty());

    // Check wallet info shows unlocked
    let info = rpc_ok(&mut node2, "getwalletinfo", "[]");
    assert_eq!(info["encrypted"], true);
    assert_eq!(info["unlocked"], true);
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn walletpassphrase_wrong_password_fails() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    rpc_ok(&mut node, "createwallet", "[]");
    rpc_ok(&mut node, "getnewaddress", r#"["test"]"#);
    rpc_ok(&mut node, "encryptwallet", r#"["correctpassword"]"#);

    // Reload node
    let mut node2 = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Wrong password should fail
    let err = rpc_err(&mut node2, "walletpassphrase", r#"["wrongpassword", 300]"#);
    assert!(err.contains("incorrect password") || err.contains("decryption"));
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn walletlock_locks_wallet() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    rpc_ok(&mut node, "createwallet", "[]");
    rpc_ok(&mut node, "getnewaddress", r#"["test"]"#);
    rpc_ok(&mut node, "encryptwallet", r#"["testpass"]"#);

    // Reload and unlock
    let mut node2 = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();
    rpc_ok(&mut node2, "walletpassphrase", r#"["testpass", 300]"#);

    // Verify unlocked
    let info = rpc_ok(&mut node2, "getwalletinfo", "[]");
    assert_eq!(info["unlocked"], true);

    // Lock the wallet
    rpc_ok(&mut node2, "walletlock", "[]");

    // Operations should fail now
    let err = rpc_err(&mut node2, "listaddresses", "[]");
    assert!(err.contains("locked"));
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn walletpassphrasechange_changes_password() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    rpc_ok(&mut node, "createwallet", "[]");
    rpc_ok(&mut node, "getnewaddress", r#"["test"]"#);
    rpc_ok(&mut node, "encryptwallet", r#"["oldpass"]"#);

    // Change password
    let mut node2 = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();
    rpc_ok(
        &mut node2,
        "walletpassphrasechange",
        r#"["oldpass", "newpass"]"#,
    );

    // Old password should no longer work
    let mut node3 = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();
    let err = rpc_err(&mut node3, "walletpassphrase", r#"["oldpass", 300]"#);
    assert!(err.contains("incorrect password") || err.contains("decryption"));

    // New password should work
    rpc_ok(&mut node3, "walletpassphrase", r#"["newpass", 300]"#);
    let addresses = rpc_ok(&mut node3, "listaddresses", "[]");
    assert!(addresses.is_array());
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn generate_address_after_unlock() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Create wallet with one address, then encrypt
    rpc_ok(&mut node, "createwallet", "[]");
    let addr1 = rpc_ok(&mut node, "getnewaddress", r#"["addr1"]"#);
    rpc_ok(&mut node, "encryptwallet", r#"["pass"]"#);

    // Reload and unlock
    let mut node2 = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();
    rpc_ok(&mut node2, "walletpassphrase", r#"["pass", 300]"#);

    // Generate new address while unlocked
    let addr2 = rpc_ok(&mut node2, "getnewaddress", r#"["addr2"]"#);
    assert_ne!(addr1.as_str(), addr2.as_str());

    // List addresses should show both
    let addresses = rpc_ok(&mut node2, "listaddresses", "[]");
    assert_eq!(addresses.as_array().unwrap().len(), 2);

    // Lock and reload - both addresses should still be there
    rpc_ok(&mut node2, "walletlock", "[]");

    let mut node3 = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();
    rpc_ok(&mut node3, "walletpassphrase", r#"["pass", 300]"#);
    let addresses = rpc_ok(&mut node3, "listaddresses", "[]");
    assert_eq!(addresses.as_array().unwrap().len(), 2);
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn encrypted_wallet_unencrypted_functions() {
    // Test that balance and other read operations don't work when locked
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    rpc_ok(&mut node, "createwallet", "[]");
    rpc_ok(&mut node, "getnewaddress", r#"["test"]"#);
    rpc_ok(&mut node, "encryptwallet", r#"["testpass"]"#);

    // Reload node (locked)
    let mut node2 = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // These should all fail when locked
    let err = rpc_err(&mut node2, "getbalance", "[]");
    assert!(err.contains("locked"));

    let err = rpc_err(&mut node2, "listunspent", "[]");
    assert!(err.contains("locked"));

    let err = rpc_err(&mut node2, "listaddresses", "[]");
    assert!(err.contains("locked"));

    // Unlock and they should work
    rpc_ok(&mut node2, "walletpassphrase", r#"["testpass", 300]"#);

    let balance = rpc_ok(&mut node2, "getbalance", "[]");
    assert_eq!(balance.as_u64().unwrap(), 0);

    let utxos = rpc_ok(&mut node2, "listunspent", "[]");
    assert!(utxos.is_array());

    let addresses = rpc_ok(&mut node2, "listaddresses", "[]");
    assert!(!addresses.as_array().unwrap().is_empty());
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn walletpassphrase_on_unencrypted_wallet_fails() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    rpc_ok(&mut node, "createwallet", "[]");

    // Trying to unlock an unencrypted wallet should fail
    let err = rpc_err(&mut node, "walletpassphrase", r#"["somepass", 300]"#);
    assert!(err.contains("not encrypted"));
}

// ============================================================================
// Backup and Dump Tests
// ============================================================================

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn backupwallet_creates_copy() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Create wallet with an address
    rpc_ok(&mut node, "createwallet", "[]");
    let addr = rpc_ok(&mut node, "getnewaddress", r#"["backup-test"]"#);
    assert!(addr.is_string());

    // Backup to a new location
    let backup_path = dir.path().join("backup.json");
    let backup_path_str = backup_path.to_str().unwrap();
    let params = format!(r#"["{}"]"#, backup_path_str);
    rpc_ok(&mut node, "backupwallet", &params);

    // Verify backup file exists and is valid JSON
    assert!(backup_path.exists());
    let backup_content = std::fs::read_to_string(&backup_path).unwrap();
    let backup: serde_json::Value = serde_json::from_str(&backup_content).unwrap();
    assert_eq!(backup["network"], "devnet");
    assert!(!backup["keys"].as_array().unwrap().is_empty());
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn backupwallet_works_on_encrypted() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Create, add key, and encrypt wallet
    rpc_ok(&mut node, "createwallet", "[]");
    rpc_ok(&mut node, "getnewaddress", r#"["test"]"#);
    rpc_ok(&mut node, "encryptwallet", r#"["password"]"#);

    // Reload node (wallet is locked)
    let mut node2 = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Backup should work without unlocking
    let backup_path = dir.path().join("encrypted-backup.json");
    let params = format!(r#"["{}"]"#, backup_path.to_str().unwrap());
    rpc_ok(&mut node2, "backupwallet", &params);

    // Verify backup has encrypted format
    let backup_content = std::fs::read_to_string(&backup_path).unwrap();
    let backup: serde_json::Value = serde_json::from_str(&backup_content).unwrap();
    assert_eq!(backup["encrypted"], true);
    assert!(backup["ciphertext"].is_string());
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn dumpwallet_exports_keys() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Create wallet with addresses
    rpc_ok(&mut node, "createwallet", "[]");
    let addr1 = rpc_ok(&mut node, "getnewaddress", r#"["first"]"#);
    let addr2 = rpc_ok(&mut node, "getnewaddress", r#"["second"]"#);

    // Dump to file
    let dump_path = dir.path().join("dump.txt");
    let params = format!(r#"["{}"]"#, dump_path.to_str().unwrap());
    let result = rpc_ok(&mut node, "dumpwallet", &params);
    assert!(result["warning"].as_str().unwrap().contains("private keys"));

    // Verify dump file content
    let dump_content = std::fs::read_to_string(&dump_path).unwrap();
    assert!(dump_content.contains("# QPB Wallet Dump"));
    assert!(dump_content.contains("Network: devnet"));
    assert!(dump_content.contains(addr1.as_str().unwrap()));
    assert!(dump_content.contains(addr2.as_str().unwrap()));
    assert!(dump_content.contains("first"));
    assert!(dump_content.contains("second"));
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn dumpwallet_requires_unlock_for_encrypted() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Create and encrypt
    rpc_ok(&mut node, "createwallet", "[]");
    rpc_ok(&mut node, "getnewaddress", r#"["test"]"#);
    rpc_ok(&mut node, "encryptwallet", r#"["password"]"#);

    // Reload (locked)
    let mut node2 = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Dump should fail when locked
    let dump_path = dir.path().join("dump.txt");
    let params = format!(r#"["{}"]"#, dump_path.to_str().unwrap());
    let err = rpc_err(&mut node2, "dumpwallet", &params);
    assert!(err.contains("unlock") || err.contains("locked") || err.contains("encrypted"));

    // Unlock and try again
    rpc_ok(&mut node2, "walletpassphrase", r#"["password", 300]"#);
    rpc_ok(&mut node2, "dumpwallet", &params);
    assert!(dump_path.exists());
}

#[test]
#[ignore = "SHRINCS is stateful - key import requires signing state (see PR #xxx)"]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn importwallet_imports_keys() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    // Create first wallet and dump
    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();
    rpc_ok(&mut node, "createwallet", "[]");
    let addr1 = rpc_ok(&mut node, "getnewaddress", r#"["original"]"#);

    let dump_path = dir.path().join("dump.txt");
    let dump_params = format!(r#"["{}"]"#, dump_path.to_str().unwrap());
    rpc_ok(&mut node, "dumpwallet", &dump_params);

    // Create second wallet in different directory
    let dir2 = tempdir().unwrap();
    let datadir2 = dir2.path();
    let mut node2 = Node::open_or_init(
        "devnet",
        datadir2,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();
    rpc_ok(&mut node2, "createwallet", "[]");

    // Initially, second wallet has no keys
    let addresses = rpc_ok(&mut node2, "listaddresses", "[]");
    assert!(addresses.as_array().unwrap().is_empty());

    // Import from dump
    let result = rpc_ok(&mut node2, "importwallet", &dump_params);
    assert_eq!(result["imported"].as_u64().unwrap(), 1);

    // Now wallet should have the imported key
    let addresses = rpc_ok(&mut node2, "listaddresses", "[]");
    let addr_list: Vec<&str> = addresses
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(addr_list.contains(&addr1.as_str().unwrap()));
}

#[test]
#[ignore = "SHRINCS is stateful - key import requires signing state (see PR #xxx)"]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn importwallet_skips_existing_keys() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Create wallet and dump
    rpc_ok(&mut node, "createwallet", "[]");
    rpc_ok(&mut node, "getnewaddress", r#"["test"]"#);

    let dump_path = dir.path().join("dump.txt");
    let dump_params = format!(r#"["{}"]"#, dump_path.to_str().unwrap());
    rpc_ok(&mut node, "dumpwallet", &dump_params);

    // Import back into same wallet (keys should be skipped)
    let result = rpc_ok(&mut node, "importwallet", &dump_params);
    assert_eq!(result["imported"].as_u64().unwrap(), 0); // Should skip existing

    // Wallet should still have only 1 key
    let addresses = rpc_ok(&mut node, "listaddresses", "[]");
    assert_eq!(addresses.as_array().unwrap().len(), 1);
}
