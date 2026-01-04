use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::address::decode_address;
use crate::address::load_hrp;
use crate::node::chainparams::{load_chainparams, select_network};
use crate::node::miner::{
    build_block_template, mine_block_bytes, mine_block_bytes_with_mempool, mine_block_to_address,
};
use crate::node::node::{Node, parse_transaction};
use crate::node::wallet::Wallet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcAction {
    Continue,
    Stop,
}

#[derive(Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Vec<Value>,
}

#[derive(Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

#[derive(Serialize)]
struct RpcResponse<'a> {
    jsonrpc: &'a str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

pub fn handle_rpc(node: &mut Node, req_json: &str) -> String {
    handle_rpc_action(node, req_json).0
}

/// Returns (response_json, action).
pub fn handle_rpc_action(node: &mut Node, req_json: &str) -> (String, RpcAction) {
    let parsed: RpcRequest = match serde_json::from_str(req_json) {
        Ok(r) => r,
        Err(_) => {
            return (
                ser_error(Value::Null, -32700, "parse error"),
                RpcAction::Continue,
            );
        }
    };

    if parsed.jsonrpc != "2.0" {
        return (
            ser_error(parsed.id, -32600, "invalid request"),
            RpcAction::Continue,
        );
    }

    match dispatch(node, &parsed.method, &parsed.params) {
        Ok((res, action)) => (ser_ok(parsed.id, res), action),
        Err(e) => (
            ser_error(parsed.id, -32000, &e.to_string()),
            RpcAction::Continue,
        ),
    }
}

fn dispatch(node: &mut Node, method: &str, params: &[Value]) -> Result<(Value, RpcAction)> {
    match method {
        "getblockcount" => Ok((Value::from(node.height()), RpcAction::Continue)),
        "getbestblockhash" => Ok((
            Value::from(node.best_hash_hex().to_string()),
            RpcAction::Continue,
        )),
        "getblockhash" => {
            let h = params
                .first()
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("missing height"))?;
            let hash = node
                .get_blockhash(h)
                .ok_or_else(|| anyhow!("height out of range"))?;
            Ok((Value::from(hash), RpcAction::Continue))
        }
        "getblock" => {
            let hash = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing block hash"))?;
            let bytes = node
                .get_block_bytes(hash)
                .ok_or_else(|| anyhow!("block not found"))?;
            Ok((Value::from(hex::encode(bytes)), RpcAction::Continue))
        }
        "submitblock" => {
            let hex = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing block hex"))?;
            let bytes = hex::decode(hex).map_err(|_| anyhow!("invalid block hex"))?;
            node.submit_block_bytes(&bytes)?;
            Ok((Value::String("accepted".to_string()), RpcAction::Continue))
        }
        "generatenextblock" => {
            let n = params
                .first()
                .and_then(|v| v.as_u64())
                .unwrap_or(1)
                .clamp(1, 10) as usize;
            let cp = load_chainparams(std::path::Path::new("docs/chain/chainparams.json"))?;
            let net = select_network(&cp, &node.chain)?;
            let mut hashes = Vec::with_capacity(n);
            for _ in 0..n {
                let bytes = mine_block_bytes(node, net, node.no_pow())?;
                node.submit_block_bytes(&bytes)?;
                hashes.push(Value::String(node.best_hash_hex().to_string()));
            }
            let val = if n == 1 {
                hashes.pop().unwrap()
            } else {
                Value::Array(hashes)
            };
            Ok((val, RpcAction::Continue))
        }
        "generateblock" => {
            // Generate block including mempool transactions
            let n = params
                .first()
                .and_then(|v| v.as_u64())
                .unwrap_or(1)
                .clamp(1, 10) as usize;
            let cp = load_chainparams(std::path::Path::new("docs/chain/chainparams.json"))?;
            let net = select_network(&cp, &node.chain)?;
            let mut hashes = Vec::with_capacity(n);
            for _ in 0..n {
                let bytes = mine_block_bytes_with_mempool(node, net, node.no_pow(), true)?;
                node.submit_block_bytes(&bytes)?;
                hashes.push(Value::String(node.best_hash_hex().to_string()));
            }
            let val = if n == 1 {
                hashes.pop().unwrap()
            } else {
                Value::Array(hashes)
            };
            Ok((val, RpcAction::Continue))
        }
        "generatetoaddress" => {
            // generatetoaddress <n> <address>
            // Generate n blocks with coinbase paying to address
            let n = params
                .first()
                .and_then(|v| v.as_u64())
                .unwrap_or(1)
                .clamp(1, 10) as usize;
            let address = params
                .get(1)
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing address"))?;

            // Decode address to get script_pubkey
            let decoded = decode_address(address).map_err(|e| anyhow!("invalid address: {}", e))?;

            let cp = load_chainparams(std::path::Path::new("docs/chain/chainparams.json"))?;
            let net = select_network(&cp, &node.chain)?;
            let mut hashes = Vec::with_capacity(n);
            for _ in 0..n {
                let bytes =
                    mine_block_to_address(node, net, decoded.script_pubkey.clone(), node.no_pow())?;
                node.submit_block_bytes(&bytes)?;
                hashes.push(Value::String(node.best_hash_hex().to_string()));
            }
            let val = if n == 1 {
                hashes.pop().unwrap()
            } else {
                Value::Array(hashes)
            };
            Ok((val, RpcAction::Continue))
        }
        "getutxo" => {
            let txid_hex = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing txid"))?;
            let vout = params
                .get(1)
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("missing vout"))? as u32;
            let mut txid = [0u8; 32];
            let txid_bytes = hex::decode(txid_hex).map_err(|_| anyhow!("invalid txid"))?;
            if txid_bytes.len() != 32 {
                return Err(anyhow!("invalid txid length"));
            }
            txid.copy_from_slice(&txid_bytes);
            let res = if let Some(p) = node.utxo_get(&txid, vout) {
                serde_json::json!({
                    "value": p.value,
                    "script_pubkey_hex": hex::encode(p.script_pubkey),
                })
            } else {
                Value::Null
            };
            Ok((res, RpcAction::Continue))
        }
        "stop" | "shutdown" => Ok((Value::String("stopping".to_string()), RpcAction::Stop)),
        "sendrawtransaction" => {
            let hex = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing transaction hex"))?;
            let bytes = hex::decode(hex).map_err(|_| anyhow!("invalid transaction hex"))?;
            let tx = parse_transaction(&bytes)?;
            let txid = node.add_to_mempool(tx)?;
            Ok((Value::String(hex::encode(txid)), RpcAction::Continue))
        }
        "getmempoolinfo" => {
            let info = node.mempool_info();
            Ok((
                serde_json::json!({
                    "size": info.size,
                    "bytes": info.bytes,
                    "total_fee": info.total_fee,
                }),
                RpcAction::Continue,
            ))
        }
        "estimatesmartfee" => {
            // Bitcoin Core compatible format (returns BTC/kB)
            let conf_target = params.first().and_then(|v| v.as_u64()).unwrap_or(6);
            let estimate = node.estimate_smart_fee(conf_target);

            // Convert sat/vB to BTC/kB: 1 BTC/kB = 100,000 sat/vB
            let feerate_btc_kb = estimate.feerate_sat_vb / 100_000.0;

            let mut result = serde_json::json!({
                "feerate": feerate_btc_kb,
                "blocks": estimate.blocks,
            });

            if !estimate.errors.is_empty() {
                result["errors"] = serde_json::json!(estimate.errors);
            }

            Ok((result, RpcAction::Continue))
        }
        "estimatefee" => {
            // Simpler format returning sat/vB directly
            let conf_target = params.first().and_then(|v| v.as_u64()).unwrap_or(6);
            let estimate = node.estimate_smart_fee(conf_target);

            Ok((
                serde_json::json!({
                    "feerate_sat_vb": estimate.feerate_sat_vb,
                    "blocks": estimate.blocks,
                }),
                RpcAction::Continue,
            ))
        }
        "getrawmempool" => {
            let info = node.mempool_info();
            // For now, return just the count. Full txid list would need Mempool iteration.
            Ok((
                serde_json::json!({
                    "count": info.size,
                }),
                RpcAction::Continue,
            ))
        }
        "getblocktemplate" => {
            let cp = load_chainparams(std::path::Path::new("docs/chain/chainparams.json"))?;
            let net = select_network(&cp, &node.chain)?;
            let template = build_block_template(node, net)?;
            let val = serde_json::to_value(template).map_err(|e| anyhow!("{}", e))?;
            Ok((val, RpcAction::Continue))
        }
        // Wallet RPCs
        "createwallet" => {
            let wallet_path = node.datadir.join("wallet.json");
            let hrp = load_hrp(
                &node.chain,
                Some(std::path::Path::new("docs/chain/chainparams.json")),
            );
            let _wallet = Wallet::open_or_create(&wallet_path, &node.chain, &hrp)?;
            Ok((
                serde_json::json!({
                    "name": "default",
                    "path": wallet_path.to_string_lossy(),
                }),
                RpcAction::Continue,
            ))
        }
        "getnewaddress" => {
            let label = params.first().and_then(|v| v.as_str()).unwrap_or("");
            let wallet_path = node.datadir.join("wallet.json");
            let hrp = load_hrp(
                &node.chain,
                Some(std::path::Path::new("docs/chain/chainparams.json")),
            );
            let mut wallet = Wallet::open_or_create(&wallet_path, &node.chain, &hrp)?;
            let address = wallet.get_new_address(label)?;
            Ok((Value::String(address), RpcAction::Continue))
        }
        "getbalance" => {
            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }
            let wallet = Wallet::load(&wallet_path)?;
            let balance = wallet.get_balance(|| node.utxo_iter_all())?;
            // Return balance in satoshis
            Ok((Value::from(balance), RpcAction::Continue))
        }
        "listunspent" => {
            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }
            let wallet = Wallet::load(&wallet_path)?;
            let utxos = wallet.list_unspent(|| node.utxo_iter_all())?;
            let val = serde_json::to_value(utxos).map_err(|e| anyhow!("{}", e))?;
            Ok((val, RpcAction::Continue))
        }
        "listaddresses" => {
            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }
            let wallet = Wallet::load(&wallet_path)?;
            let addresses: Vec<Value> = wallet
                .addresses()
                .into_iter()
                .map(|a| Value::String(a.to_string()))
                .collect();
            Ok((Value::Array(addresses), RpcAction::Continue))
        }
        "sendtoaddress" => {
            // sendtoaddress <address> <amount> [fee_rate] [rbf]
            let address = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing address"))?;
            let amount = params
                .get(1)
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("missing amount"))?;
            let fee_rate = params.get(2).and_then(|v| v.as_u64()).unwrap_or(1); // default 1 sat/vB
            let rbf = params.get(3).and_then(|v| v.as_bool()).unwrap_or(false); // default no RBF

            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }
            let hrp = load_hrp(
                &node.chain,
                Some(std::path::Path::new("docs/chain/chainparams.json")),
            );
            let mut wallet = Wallet::open_or_create(&wallet_path, &node.chain, &hrp)?;

            // Get all UTXOs for coin selection
            let utxos = node.utxo_iter_all();
            let current_height = node.height() as u32;

            // Create and sign transaction with optional RBF signaling
            let tx =
                wallet.create_transaction(address, amount, fee_rate, utxos, current_height, rbf)?;
            let txid = tx.txid();

            // Add to mempool
            node.add_to_mempool(tx)?;

            Ok((Value::String(hex::encode(txid)), RpcAction::Continue))
        }
        "bumpfee" => {
            // bumpfee <txid> <new_fee_rate>
            // Creates a replacement transaction with higher fee
            let txid_hex = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing txid"))?;
            let new_fee_rate = params
                .get(1)
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("missing new_fee_rate"))?;

            // Parse txid
            let txid_bytes = hex::decode(txid_hex).map_err(|_| anyhow!("invalid txid hex"))?;
            if txid_bytes.len() != 32 {
                return Err(anyhow!("txid must be 32 bytes"));
            }
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&txid_bytes);

            // Get the original transaction from mempool
            let original_entry = node
                .mempool_get_entry(&txid)
                .ok_or_else(|| anyhow!("transaction not in mempool"))?;

            // Check if original signals RBF
            if !original_entry.signals_rbf {
                return Err(anyhow!(
                    "transaction does not signal RBF (sequence must be <= 0xfffffffd)"
                ));
            }

            // Get wallet
            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }
            let hrp = load_hrp(
                &node.chain,
                Some(std::path::Path::new("docs/chain/chainparams.json")),
            );
            let mut wallet = Wallet::open_or_create(&wallet_path, &node.chain, &hrp)?;

            // Collect outputs from original transaction (to recreate the payment)
            let original_tx = &original_entry.tx;

            // Find recipient output
            // Convention: first output is always recipient, second (if exists) is change
            // This matches how create_transaction builds transactions
            if original_tx.vout.is_empty() {
                return Err(anyhow!("original transaction has no outputs"));
            }

            // First output is the recipient
            let recipient_spk = original_tx.vout[0].script_pubkey.clone();
            let recipient_amount = original_tx.vout[0].value;

            // Encode recipient address from scriptPubKey
            // This is a P2QPKH scriptPubKey: OP_3 (0x53) PUSH32 (0x20) <32-byte hash>
            if recipient_spk.len() != 34 || recipient_spk[0] != 0x53 || recipient_spk[1] != 0x20 {
                return Err(anyhow!("unsupported recipient script type for bumpfee"));
            }
            let mut recipient_hash = [0u8; 32];
            recipient_hash.copy_from_slice(&recipient_spk[2..34]);
            let recipient_address = crate::address::encode_address(&hrp, 3, &recipient_hash)
                .map_err(|e| anyhow!("failed to encode recipient address: {}", e))?;

            // Create replacement transaction with same recipient but higher fee
            let utxos = node.utxo_iter_all();
            let current_height = node.height() as u32;

            // The replacement must signal RBF too (in case user wants to bump again)
            let replacement_tx = wallet.create_transaction(
                &recipient_address,
                recipient_amount,
                new_fee_rate,
                utxos,
                current_height,
                true, // RBF enabled
            )?;

            let new_txid = replacement_tx.txid();

            // Calculate the new fee
            let input_sum: u64 = {
                // Get prevouts for the replacement tx to calculate fee
                let mut sum = 0u64;
                for vin in &replacement_tx.vin {
                    if let Some(prevout) = node.utxo_get(&vin.prevout.txid, vin.prevout.vout) {
                        sum += prevout.value;
                    }
                }
                sum
            };
            let output_sum: u64 = replacement_tx.vout.iter().map(|o| o.value).sum();
            let new_fee = input_sum.saturating_sub(output_sum);

            // Add replacement to mempool (RBF validation happens inside)
            node.add_to_mempool(replacement_tx)?;

            Ok((
                serde_json::json!({
                    "txid": hex::encode(new_txid),
                    "origfee": original_entry.fee,
                    "fee": new_fee,
                    "errors": [],
                }),
                RpcAction::Continue,
            ))
        }
        _ => Err(anyhow!("method not found")),
    }
}

fn ser_ok(id: Value, result: Value) -> String {
    serde_json::to_string(&RpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    })
    .unwrap_or_else(|_| "{}".to_string())
}

fn ser_error(id: Value, code: i32, message: &str) -> String {
    serde_json::to_string(&RpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcError {
            code,
            message: message.to_string(),
        }),
    })
    .unwrap_or_else(|_| "{}".to_string())
}
