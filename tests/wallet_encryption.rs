//! Wallet encryption integration tests.

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
fn encryptwallet_basic() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

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
    assert!(result["warning"].as_str().unwrap().contains("encrypted successfully"));

    // Check wallet info after encryption
    // Note: After encryption, wallet is locked so we load from disk
    let mut node2 = Node::open_or_init("devnet", datadir, true).unwrap();
    let info = rpc_ok(&mut node2, "getwalletinfo", "[]");
    assert_eq!(info["encrypted"], true);
    assert_eq!(info["unlocked"], false); // Locked after encryption
}

#[test]
fn encryptwallet_cannot_encrypt_twice() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    rpc_ok(&mut node, "createwallet", "[]");
    rpc_ok(&mut node, "encryptwallet", r#"["password1"]"#);

    // Trying to encrypt again should fail
    let mut node2 = Node::open_or_init("devnet", datadir, true).unwrap();
    let err = rpc_err(&mut node2, "encryptwallet", r#"["password2"]"#);
    assert!(err.contains("already encrypted"));
}

#[test]
fn walletpassphrase_unlocks_wallet() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Create and encrypt wallet
    rpc_ok(&mut node, "createwallet", "[]");
    rpc_ok(&mut node, "getnewaddress", r#"["test"]"#);
    rpc_ok(&mut node, "encryptwallet", r#"["testpass"]"#);

    // Reload node (wallet is now locked)
    let mut node2 = Node::open_or_init("devnet", datadir, true).unwrap();

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
fn walletpassphrase_wrong_password_fails() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    rpc_ok(&mut node, "createwallet", "[]");
    rpc_ok(&mut node, "getnewaddress", r#"["test"]"#);
    rpc_ok(&mut node, "encryptwallet", r#"["correctpassword"]"#);

    // Reload node
    let mut node2 = Node::open_or_init("devnet", datadir, true).unwrap();

    // Wrong password should fail
    let err = rpc_err(&mut node2, "walletpassphrase", r#"["wrongpassword", 300]"#);
    assert!(err.contains("incorrect password") || err.contains("decryption"));
}

#[test]
fn walletlock_locks_wallet() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    rpc_ok(&mut node, "createwallet", "[]");
    rpc_ok(&mut node, "getnewaddress", r#"["test"]"#);
    rpc_ok(&mut node, "encryptwallet", r#"["testpass"]"#);

    // Reload and unlock
    let mut node2 = Node::open_or_init("devnet", datadir, true).unwrap();
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
fn walletpassphrasechange_changes_password() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    rpc_ok(&mut node, "createwallet", "[]");
    rpc_ok(&mut node, "getnewaddress", r#"["test"]"#);
    rpc_ok(&mut node, "encryptwallet", r#"["oldpass"]"#);

    // Change password
    let mut node2 = Node::open_or_init("devnet", datadir, true).unwrap();
    rpc_ok(
        &mut node2,
        "walletpassphrasechange",
        r#"["oldpass", "newpass"]"#,
    );

    // Old password should no longer work
    let mut node3 = Node::open_or_init("devnet", datadir, true).unwrap();
    let err = rpc_err(&mut node3, "walletpassphrase", r#"["oldpass", 300]"#);
    assert!(err.contains("incorrect password") || err.contains("decryption"));

    // New password should work
    rpc_ok(&mut node3, "walletpassphrase", r#"["newpass", 300]"#);
    let addresses = rpc_ok(&mut node3, "listaddresses", "[]");
    assert!(addresses.is_array());
}

#[test]
fn generate_address_after_unlock() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Create wallet with one address, then encrypt
    rpc_ok(&mut node, "createwallet", "[]");
    let addr1 = rpc_ok(&mut node, "getnewaddress", r#"["addr1"]"#);
    rpc_ok(&mut node, "encryptwallet", r#"["pass"]"#);

    // Reload and unlock
    let mut node2 = Node::open_or_init("devnet", datadir, true).unwrap();
    rpc_ok(&mut node2, "walletpassphrase", r#"["pass", 300]"#);

    // Generate new address while unlocked
    let addr2 = rpc_ok(&mut node2, "getnewaddress", r#"["addr2"]"#);
    assert_ne!(addr1.as_str(), addr2.as_str());

    // List addresses should show both
    let addresses = rpc_ok(&mut node2, "listaddresses", "[]");
    assert_eq!(addresses.as_array().unwrap().len(), 2);

    // Lock and reload - both addresses should still be there
    rpc_ok(&mut node2, "walletlock", "[]");

    let mut node3 = Node::open_or_init("devnet", datadir, true).unwrap();
    rpc_ok(&mut node3, "walletpassphrase", r#"["pass", 300]"#);
    let addresses = rpc_ok(&mut node3, "listaddresses", "[]");
    assert_eq!(addresses.as_array().unwrap().len(), 2);
}

#[test]
fn encrypted_wallet_unencrypted_functions() {
    // Test that balance and other read operations don't work when locked
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    rpc_ok(&mut node, "createwallet", "[]");
    rpc_ok(&mut node, "getnewaddress", r#"["test"]"#);
    rpc_ok(&mut node, "encryptwallet", r#"["testpass"]"#);

    // Reload node (locked)
    let mut node2 = Node::open_or_init("devnet", datadir, true).unwrap();

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
fn walletpassphrase_on_unencrypted_wallet_fails() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    rpc_ok(&mut node, "createwallet", "[]");

    // Trying to unlock an unencrypted wallet should fail
    let err = rpc_err(&mut node, "walletpassphrase", r#"["somepass", 300]"#);
    assert!(err.contains("not encrypted"));
}
