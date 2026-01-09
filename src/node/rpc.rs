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
use crate::script::parse_script_pubkey;
use crate::types::Prevout;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcAction {
    Continue,
    Stop,
    /// Broadcast newly-mined blocks to peers.
    BroadcastBlocks(Vec<[u8; 32]>),
    /// Broadcast a newly-accepted transaction to peers.
    BroadcastTransaction([u8; 32]),
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
/// Supports both single JSON-RPC requests and batch requests (JSON arrays).
pub fn handle_rpc_action(node: &mut Node, req_json: &str) -> (String, RpcAction) {
    // Try parsing as single request first
    if let Ok(parsed) = serde_json::from_str::<RpcRequest>(req_json) {
        return handle_single_request(node, parsed);
    }

    // Try parsing as batch request (array)
    if let Ok(batch) = serde_json::from_str::<Vec<RpcRequest>>(req_json) {
        if batch.is_empty() {
            return (
                ser_error(Value::Null, -32600, "empty batch request"),
                RpcAction::Continue,
            );
        }

        let mut responses = Vec::with_capacity(batch.len());
        let mut combined_action = RpcAction::Continue;

        for req in batch {
            let (response_json, action) = handle_single_request(node, req);
            responses.push(serde_json::from_str::<Value>(&response_json).unwrap_or(Value::Null));

            // Collect any broadcast actions
            match action {
                RpcAction::BroadcastBlocks(blocks) => {
                    if let RpcAction::BroadcastBlocks(ref mut existing) = combined_action {
                        existing.extend(blocks);
                    } else {
                        combined_action = RpcAction::BroadcastBlocks(blocks);
                    }
                }
                RpcAction::BroadcastTransaction(txid) => {
                    combined_action = RpcAction::BroadcastTransaction(txid);
                }
                RpcAction::Stop => combined_action = RpcAction::Stop,
                RpcAction::Continue => {}
            }
        }

        return (
            serde_json::to_string(&responses).unwrap_or_default(),
            combined_action,
        );
    }

    // Neither single nor batch - parse error
    (
        ser_error(Value::Null, -32700, "parse error"),
        RpcAction::Continue,
    )
}

fn handle_single_request(node: &mut Node, parsed: RpcRequest) -> (String, RpcAction) {
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
        "getblockheader" => {
            let hash = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing block hash"))?;
            let header_info = node
                .get_block_header(hash)
                .ok_or_else(|| anyhow!("block not found"))?;
            let result = serde_json::json!({
                "hash": header_info.hash,
                "confirmations": header_info.confirmations,
                "height": header_info.height,
                "version": header_info.version,
                "merkleroot": header_info.merkle_root,
                "time": header_info.time,
                "bits": header_info.bits,
                "nonce": header_info.nonce,
                "previousblockhash": header_info.previous_block_hash,
                "nextblockhash": header_info.next_block_hash
            });
            Ok((result, RpcAction::Continue))
        }
        "getrawtransaction" => {
            let txid_hex = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing txid"))?;
            let verbose = params.get(1).and_then(|v| v.as_bool()).unwrap_or(false);

            let txid: [u8; 32] = hex::decode(txid_hex)
                .map_err(|_| anyhow!("invalid txid hex"))?
                .try_into()
                .map_err(|_| anyhow!("txid must be 32 bytes"))?;

            // Try mempool first
            if let Some(tx) = node.mempool_get(&txid) {
                let hex = hex::encode(tx.serialize(true));
                if verbose {
                    // Return decoded transaction
                    let result = serde_json::json!({
                        "txid": txid_hex,
                        "hex": hex,
                        "version": tx.version,
                        "locktime": tx.lock_time,
                        "vin": tx.vin.iter().map(|inp| {
                            serde_json::json!({
                                "txid": hex::encode(inp.prevout.txid),
                                "vout": inp.prevout.vout,
                                "scriptSig": {
                                    "hex": hex::encode(&inp.script_sig)
                                },
                                "sequence": inp.sequence
                            })
                        }).collect::<Vec<_>>(),
                        "vout": tx.vout.iter().enumerate().map(|(i, out)| {
                            serde_json::json!({
                                "value": out.value as f64 / 100_000_000.0,
                                "n": i,
                                "scriptPubKey": {
                                    "hex": hex::encode(&out.script_pubkey)
                                }
                            })
                        }).collect::<Vec<_>>(),
                        "confirmations": 0
                    });
                    Ok((result, RpcAction::Continue))
                } else {
                    Ok((Value::from(hex), RpcAction::Continue))
                }
            } else if let Some(loc) = node.txindex_get(&txid) {
                // Transaction found in txindex - load from block
                let block = node
                    .get_block_parsed(&loc.block_hash)
                    .ok_or_else(|| anyhow!("block not found: {}", loc.block_hash))?;
                let tx = block
                    .txdata
                    .get(loc.tx_position as usize)
                    .ok_or_else(|| anyhow!("tx position {} out of range", loc.tx_position))?;

                let hex = hex::encode(tx.serialize(true));
                if verbose {
                    // Calculate confirmations
                    let block_height = node.get_block_height(&loc.block_hash).unwrap_or(0);
                    let tip_height = node.height();
                    let confirmations = if block_height <= tip_height {
                        (tip_height - block_height + 1) as i64
                    } else {
                        -1
                    };

                    let result = serde_json::json!({
                        "txid": txid_hex,
                        "hex": hex,
                        "blockhash": loc.block_hash,
                        "blockheight": block_height,
                        "confirmations": confirmations,
                        "version": tx.version,
                        "locktime": tx.lock_time,
                        "vin": tx.vin.iter().map(|inp| {
                            serde_json::json!({
                                "txid": hex::encode(inp.prevout.txid),
                                "vout": inp.prevout.vout,
                                "scriptSig": {
                                    "hex": hex::encode(&inp.script_sig)
                                },
                                "sequence": inp.sequence
                            })
                        }).collect::<Vec<_>>(),
                        "vout": tx.vout.iter().enumerate().map(|(i, out)| {
                            serde_json::json!({
                                "value": out.value as f64 / 100_000_000.0,
                                "n": i,
                                "scriptPubKey": {
                                    "hex": hex::encode(&out.script_pubkey)
                                }
                            })
                        }).collect::<Vec<_>>()
                    });
                    Ok((result, RpcAction::Continue))
                } else {
                    Ok((Value::from(hex), RpcAction::Continue))
                }
            } else if !node.txindex_enabled() {
                Err(anyhow!(
                    "transaction not found (txindex not enabled, use --txindex flag)"
                ))
            } else {
                Err(anyhow!("transaction not found"))
            }
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
            let cp = load_chainparams(&node.params_path)?;
            let net = select_network(&cp, &node.chain)?;
            let mut hashes = Vec::with_capacity(n);
            let mut block_hashes_to_broadcast = Vec::with_capacity(n);
            for _ in 0..n {
                let bytes = mine_block_bytes(node, net, node.no_pow())?;
                node.submit_block_bytes(&bytes)?;
                let best_hash = node.best_hash_hex();
                hashes.push(Value::String(best_hash.to_string()));
                // Collect block hash for broadcast
                let hash_bytes = hex::decode(best_hash)?;
                let mut block_hash = [0u8; 32];
                block_hash.copy_from_slice(&hash_bytes);
                block_hashes_to_broadcast.push(block_hash);
            }
            let val = if n == 1 {
                hashes.pop().unwrap()
            } else {
                Value::Array(hashes)
            };
            // Broadcast ALL mined blocks to peers (not just tip)
            Ok((val, RpcAction::BroadcastBlocks(block_hashes_to_broadcast)))
        }
        "generateblock" => {
            // Generate block including mempool transactions
            let n = params
                .first()
                .and_then(|v| v.as_u64())
                .unwrap_or(1)
                .clamp(1, 10) as usize;
            let cp = load_chainparams(&node.params_path)?;
            let net = select_network(&cp, &node.chain)?;
            let mut hashes = Vec::with_capacity(n);
            let mut block_hashes_to_broadcast = Vec::with_capacity(n);
            for _ in 0..n {
                let bytes = mine_block_bytes_with_mempool(node, net, node.no_pow(), true)?;
                node.submit_block_bytes(&bytes)?;
                let best_hash = node.best_hash_hex();
                hashes.push(Value::String(best_hash.to_string()));
                // Collect block hash for broadcast
                let hash_bytes = hex::decode(best_hash)?;
                let mut block_hash = [0u8; 32];
                block_hash.copy_from_slice(&hash_bytes);
                block_hashes_to_broadcast.push(block_hash);
            }
            let val = if n == 1 {
                hashes.pop().unwrap()
            } else {
                Value::Array(hashes)
            };
            // Broadcast ALL mined blocks to peers (not just tip)
            Ok((val, RpcAction::BroadcastBlocks(block_hashes_to_broadcast)))
        }
        "generatetoaddress" => {
            // generatetoaddress <n> <address>
            // Generate n blocks with coinbase paying to address
            let n = params
                .first()
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("missing or invalid block count"))?;
            if n > 10 {
                return Err(anyhow!("block count exceeds maximum of 10"));
            }
            let n = n as usize;
            let address = params
                .get(1)
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing address"))?;

            // Decode address to get script_pubkey
            let decoded = decode_address(address).map_err(|e| anyhow!("invalid address: {}", e))?;

            let cp = load_chainparams(&node.params_path)?;
            let net = select_network(&cp, &node.chain)?;
            let mut hashes = Vec::with_capacity(n);
            let mut block_hashes_to_broadcast = Vec::with_capacity(n);
            for _ in 0..n {
                let bytes =
                    mine_block_to_address(node, net, decoded.script_pubkey.clone(), node.no_pow())?;
                node.submit_block_bytes(&bytes)?;
                let best_hash = node.best_hash_hex();
                hashes.push(Value::String(best_hash.to_string()));
                // Collect block hash for broadcast
                let hash_bytes = hex::decode(best_hash)?;
                let mut block_hash = [0u8; 32];
                block_hash.copy_from_slice(&hash_bytes);
                block_hashes_to_broadcast.push(block_hash);
            }
            let val = if hashes.is_empty() {
                Value::Array(vec![])
            } else if hashes.len() == 1 {
                hashes.pop().unwrap()
            } else {
                Value::Array(hashes)
            };
            // Broadcast ALL mined blocks to peers (not just tip)
            Ok((val, RpcAction::BroadcastBlocks(block_hashes_to_broadcast)))
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
            // Broadcast to peers (sender_id=0 means broadcast to all)
            Ok((
                Value::String(hex::encode(txid)),
                RpcAction::BroadcastTransaction(txid),
            ))
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
        "gettxindexinfo" => Ok((
            serde_json::json!({
                "enabled": node.txindex_enabled(),
                "txcount": node.txindex_len(),
            }),
            RpcAction::Continue,
        )),
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
            let cp = load_chainparams(&node.params_path)?;
            let net = select_network(&cp, &node.chain)?;
            let template = build_block_template(node, net)?;
            let val = serde_json::to_value(template).map_err(|e| anyhow!("{}", e))?;
            Ok((val, RpcAction::Continue))
        }
        // Wallet RPCs
        "createwallet" => {
            let wallet_path = node.datadir.join("wallet.json");
            let hrp = load_hrp(&node.chain, Some(&node.params_path));
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

            // Use cached wallet if available (for encrypted wallets)
            let address = if let Some(wallet) = node.wallet_mut() {
                wallet.get_new_address(label)?
            } else {
                let hrp = load_hrp(&node.chain, Some(&node.params_path));
                let mut wallet = Wallet::open_or_create(&wallet_path, &node.chain, &hrp)?;
                let addr = wallet.get_new_address(label)?;
                // If encrypted, warn the user (they should use walletpassphrase first)
                if wallet.is_encrypted() {
                    return Err(anyhow!(
                        "wallet is locked; unlock with walletpassphrase first"
                    ));
                }
                addr
            };
            Ok((Value::String(address), RpcAction::Continue))
        }
        "getbalance" => {
            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }

            // Use cached wallet if available (for encrypted wallets)
            let balance = if let Some(wallet) = node.wallet() {
                wallet.get_balance(|| node.utxo_iter_all())?
            } else {
                let wallet = Wallet::load(&wallet_path)?;
                if wallet.is_encrypted() {
                    return Err(anyhow!(
                        "wallet is locked; unlock with walletpassphrase first"
                    ));
                }
                wallet.get_balance(|| node.utxo_iter_all())?
            };
            // Return balance in satoshis
            Ok((Value::from(balance), RpcAction::Continue))
        }
        "listunspent" => {
            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }

            let current_height = node.height() as u32;

            // Use cached wallet if available (for encrypted wallets)
            let utxos = if let Some(wallet) = node.wallet() {
                wallet.list_unspent(|| node.utxo_iter_all(), current_height)?
            } else {
                let wallet = Wallet::load(&wallet_path)?;
                if wallet.is_encrypted() {
                    return Err(anyhow!(
                        "wallet is locked; unlock with walletpassphrase first"
                    ));
                }
                wallet.list_unspent(|| node.utxo_iter_all(), current_height)?
            };
            let val = serde_json::to_value(utxos).map_err(|e| anyhow!("{}", e))?;
            Ok((val, RpcAction::Continue))
        }
        "listaddresses" => {
            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }

            // Use cached wallet if available (for encrypted wallets)
            let addresses = if let Some(wallet) = node.wallet() {
                wallet.addresses()?
            } else {
                let wallet = Wallet::load(&wallet_path)?;
                if wallet.is_encrypted() {
                    return Err(anyhow!(
                        "wallet is locked; unlock with walletpassphrase first"
                    ));
                }
                wallet.addresses()?
            };
            let addresses: Vec<Value> = addresses.into_iter().map(Value::String).collect();
            Ok((Value::Array(addresses), RpcAction::Continue))
        }
        "sendtoaddress" => {
            // sendtoaddress <address> <amount> [fee_rate] [rbf=true]
            let address = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing address"))?;
            let amount = params
                .get(1)
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("missing amount"))?;
            if amount == 0 {
                return Err(anyhow!("amount must be greater than 0"));
            }
            let fee_rate = match params.get(2) {
                None => 1, // default 1 sat/vB
                Some(v) => v.as_u64().ok_or_else(|| {
                    anyhow!("invalid fee_rate: must be a positive integer (sat/vB)")
                })?,
            };
            let rbf = params.get(3).and_then(|v| v.as_bool()).unwrap_or(true); // default RBF enabled

            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }

            // Get all UTXOs with typed OutPoints
            let all_utxos = node.utxo_iter_all_outpoints();

            // Filter out UTXOs already spent in mempool (confirmed-only policy)
            let mempool = node.mempool_ref();
            let utxos: Vec<(String, u32, Prevout)> = all_utxos
                .into_iter()
                .filter(|(outpoint, _)| !mempool.is_spent(outpoint))
                .map(|(op, prevout)| (hex::encode(op.txid), op.vout, prevout))
                .collect();

            let current_height = node.height() as u32;

            // Use cached wallet if available (for encrypted wallets)
            let tx = if let Some(wallet) = node.wallet_mut() {
                wallet.create_transaction(
                    address,
                    amount,
                    fee_rate,
                    utxos.clone(),
                    current_height,
                    rbf,
                )?
            } else {
                let hrp = load_hrp(&node.chain, Some(&node.params_path));
                let mut wallet = Wallet::open_or_create(&wallet_path, &node.chain, &hrp)?;
                if wallet.is_encrypted() {
                    return Err(anyhow!(
                        "wallet is locked; unlock with walletpassphrase first"
                    ));
                }
                wallet.create_transaction(address, amount, fee_rate, utxos, current_height, rbf)?
            };
            let txid = tx.txid();

            // Add to mempool
            node.add_to_mempool(tx)?;

            Ok((
                Value::String(hex::encode(txid)),
                RpcAction::BroadcastTransaction(txid),
            ))
        }
        "fanout" => {
            // fanout <count> <amount_per_output> [fee_rate]
            // Creates a transaction with many outputs to self for UTXO fan-out
            let count = params
                .first()
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("missing count"))?;
            if count == 0 || count > 500 {
                return Err(anyhow!("count must be between 1 and 500"));
            }
            let amount_per_output = params
                .get(1)
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("missing amount_per_output"))?;
            let fee_rate = params.get(2).and_then(|v| v.as_u64()).unwrap_or(1);

            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }

            // Get all UTXOs with typed OutPoints
            let all_utxos = node.utxo_iter_all_outpoints();

            // Filter out UTXOs already spent in mempool (confirmed-only policy)
            let mempool = node.mempool_ref();
            let utxos: Vec<(String, u32, Prevout)> = all_utxos
                .into_iter()
                .filter(|(outpoint, _)| !mempool.is_spent(outpoint))
                .map(|(op, prevout)| (hex::encode(op.txid), op.vout, prevout))
                .collect();

            let current_height = node.height() as u32;

            // Use cached wallet if available (for encrypted wallets)
            let tx = if let Some(wallet) = node.wallet_mut() {
                wallet.create_fanout_transaction(
                    count as u32,
                    amount_per_output,
                    fee_rate,
                    utxos.clone(),
                    current_height,
                )?
            } else {
                let hrp = load_hrp(&node.chain, Some(&node.params_path));
                let mut wallet = Wallet::open_or_create(&wallet_path, &node.chain, &hrp)?;
                if wallet.is_encrypted() {
                    return Err(anyhow!(
                        "wallet is locked; unlock with walletpassphrase first"
                    ));
                }
                wallet.create_fanout_transaction(
                    count as u32,
                    amount_per_output,
                    fee_rate,
                    utxos,
                    current_height,
                )?
            };

            let txid = tx.txid();
            let outputs_created = tx.vout.len();
            let total_output: u64 = tx.vout.iter().map(|o| o.value).sum();

            // Calculate fee from inputs vs outputs
            // We need input values - get them from prevouts we passed
            let input_total: u64 = {
                let all_utxos = node.utxo_iter_all_outpoints();
                tx.vin
                    .iter()
                    .filter_map(|vin| {
                        all_utxos
                            .iter()
                            .find(|(op, _)| {
                                op.txid == vin.prevout.txid && op.vout == vin.prevout.vout
                            })
                            .map(|(_, prevout)| prevout.value)
                    })
                    .sum()
            };
            let fee = input_total.saturating_sub(total_output);

            // Add to mempool
            node.add_to_mempool(tx)?;

            let result = serde_json::json!({
                "txid": hex::encode(txid),
                "outputs_created": outputs_created,
                "total": total_output,
                "fee": fee
            });

            Ok((result, RpcAction::BroadcastTransaction(txid)))
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
            let hrp = load_hrp(&node.chain, Some(&node.params_path));
            let mut wallet = Wallet::open_or_create(&wallet_path, &node.chain, &hrp)?;

            // Get the original transaction
            let original_tx = &original_entry.tx;

            // Collect prevouts for original inputs (needed for signing and fee calculation)
            let mut original_prevouts = Vec::new();
            for vin in &original_tx.vin {
                let prevout = node
                    .utxo_get(&vin.prevout.txid, vin.prevout.vout)
                    .ok_or_else(|| {
                        anyhow!("cannot find prevout for input (may have been spent)")
                    })?;
                original_prevouts.push(prevout);
            }

            // Create replacement transaction reusing the same inputs
            // This guarantees conflict with the original (required for RBF)
            let replacement_tx = wallet.create_replacement_transaction(
                original_tx,
                &original_prevouts,
                new_fee_rate,
            )?;

            let new_txid = replacement_tx.txid();

            // Calculate the new fee
            let input_sum: u64 = original_prevouts.iter().map(|p| p.value).sum();
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
                RpcAction::BroadcastTransaction(new_txid),
            ))
        }
        // Wallet encryption RPCs
        "encryptwallet" => {
            // encryptwallet <passphrase>
            let password = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing passphrase"))?;

            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }

            let mut wallet = Wallet::load(&wallet_path)?;

            if wallet.is_encrypted() {
                return Err(anyhow!("wallet is already encrypted"));
            }

            wallet.encrypt_wallet(password)?;

            Ok((
                serde_json::json!({
                    "warning": "wallet encrypted successfully; you must unlock with walletpassphrase before signing transactions"
                }),
                RpcAction::Continue,
            ))
        }
        "walletpassphrase" => {
            // walletpassphrase <passphrase> <timeout>
            let password = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing passphrase"))?;

            let timeout_secs = params.get(1).and_then(|v| v.as_u64()).unwrap_or(300); // default 5 minutes

            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }

            let mut wallet = Wallet::load(&wallet_path)?;

            if !wallet.is_encrypted() {
                return Err(anyhow!("wallet is not encrypted"));
            }

            wallet.unlock(password, timeout_secs)?;

            // Store the unlocked wallet in the node for subsequent operations
            node.set_wallet(Some(wallet));

            Ok((Value::Null, RpcAction::Continue))
        }
        "walletlock" => {
            // walletlock
            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }

            // Clear any cached unlocked wallet from the node
            if let Some(wallet) = node.wallet_mut() {
                wallet.lock();
            }
            node.set_wallet(None);

            Ok((Value::Null, RpcAction::Continue))
        }
        "walletpassphrasechange" => {
            // walletpassphrasechange <oldpassphrase> <newpassphrase>
            let old_password = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing old passphrase"))?;

            let new_password = params
                .get(1)
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing new passphrase"))?;

            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }

            let mut wallet = Wallet::load(&wallet_path)?;

            if !wallet.is_encrypted() {
                return Err(anyhow!("wallet is not encrypted"));
            }

            wallet.change_password(old_password, new_password)?;

            Ok((Value::Null, RpcAction::Continue))
        }
        "getwalletinfo" => {
            // getwalletinfo - returns wallet status including encryption state
            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }

            let wallet = if let Some(w) = node.wallet() {
                // Use cached wallet if available (may be unlocked)
                let is_unlocked = w.is_unlocked();
                let is_encrypted = w.is_encrypted();
                let key_count = w.addresses().map(|a| a.len()).unwrap_or(0);
                serde_json::json!({
                    "walletname": "default",
                    "encrypted": is_encrypted,
                    "unlocked": is_unlocked,
                    "keypoolsize": key_count,
                })
            } else {
                // Load from disk (will be locked if encrypted)
                let wallet = Wallet::load(&wallet_path)?;
                let is_encrypted = wallet.is_encrypted();
                let key_count = if is_encrypted {
                    0 // Can't count keys when locked
                } else {
                    wallet.addresses().map(|a| a.len()).unwrap_or(0)
                };
                serde_json::json!({
                    "walletname": "default",
                    "encrypted": is_encrypted,
                    "unlocked": !is_encrypted, // Unencrypted wallets are always "unlocked"
                    "keypoolsize": key_count,
                })
            };

            Ok((wallet, RpcAction::Continue))
        }
        "backupwallet" => {
            // backupwallet <destination>
            // Creates a backup of the wallet file (works on encrypted wallets without unlock)
            let destination = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing destination path"))?;

            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }

            let wallet = Wallet::load(&wallet_path)?;
            wallet.backup(std::path::Path::new(destination))?;

            Ok((Value::Null, RpcAction::Continue))
        }
        "dumpwallet" => {
            // dumpwallet <filename>
            // Exports all private keys to a human-readable text file
            // Requires wallet to be unlocked if encrypted
            let filename = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing filename"))?;

            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }

            // Check if we have a cached unlocked wallet
            let dump_content = if let Some(wallet) = node.wallet() {
                wallet.dump_keys()?
            } else {
                let wallet = Wallet::load(&wallet_path)?;
                if wallet.is_encrypted() {
                    return Err(anyhow!(
                        "wallet is encrypted; unlock with walletpassphrase first"
                    ));
                }
                wallet.dump_keys()?
            };

            // Write to file
            std::fs::write(filename, &dump_content)?;

            Ok((
                serde_json::json!({
                    "filename": filename,
                    "warning": "File contains plaintext private keys. Store securely!"
                }),
                RpcAction::Continue,
            ))
        }
        "importwallet" => {
            // importwallet <filename>
            // Imports keys from a wallet dump file
            // Requires wallet to be unlocked if encrypted
            let filename = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing filename"))?;

            let wallet_path = node.datadir.join("wallet.json");
            if !wallet_path.exists() {
                return Err(anyhow!("wallet not found, call createwallet first"));
            }

            // Read dump file
            let dump_content = std::fs::read_to_string(filename)
                .map_err(|e| anyhow!("failed to read dump file: {}", e))?;

            // Import into wallet
            let imported = if let Some(wallet) = node.wallet_mut() {
                wallet.import_dump(&dump_content)?
            } else {
                let mut wallet = Wallet::load(&wallet_path)?;
                if wallet.is_encrypted() {
                    return Err(anyhow!(
                        "wallet is encrypted; unlock with walletpassphrase first"
                    ));
                }
                wallet.import_dump(&dump_content)?
            };

            Ok((
                serde_json::json!({
                    "imported": imported
                }),
                RpcAction::Continue,
            ))
        }
        // ============================================================
        // Ban Management RPCs
        // ============================================================
        "setban" => {
            // setban <addr> <add|remove> [ban_duration_secs]
            // Adds or removes an address from the ban list
            let addr = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing address"))?;
            let action = params
                .get(1)
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing action (add|remove)"))?;

            match action {
                "add" => {
                    let duration = params
                        .get(2)
                        .and_then(|v| v.as_u64())
                        .unwrap_or(crate::constants::DEFAULT_BAN_DURATION_SECS);
                    let reason = params
                        .get(3)
                        .and_then(|v| v.as_str())
                        .unwrap_or("manual ban via RPC");
                    node.ban_list_mut().ban_temporarily(addr, duration, reason);
                    Ok((serde_json::json!({"banned": true}), RpcAction::Continue))
                }
                "remove" => {
                    let removed = node.ban_list_mut().unban(addr);
                    Ok((serde_json::json!({"removed": removed}), RpcAction::Continue))
                }
                _ => Err(anyhow!("action must be 'add' or 'remove'")),
            }
        }
        "listbanned" => {
            // listbanned
            // Returns all banned addresses with their expiration times
            let bans: Vec<serde_json::Value> = node
                .ban_list()
                .list_bans()
                .iter()
                .map(|entry| {
                    serde_json::json!({
                        "address": entry.address,
                        "reason": entry.reason,
                        "ban_time": entry.ban_time,
                        "unban_time": entry.unban_time,
                    })
                })
                .collect();
            Ok((Value::Array(bans), RpcAction::Continue))
        }
        "clearbanned" => {
            // clearbanned
            // Clears all bans
            node.ban_list_mut().clear();
            Ok((serde_json::json!({"cleared": true}), RpcAction::Continue))
        }
        "getcheckpoints" => {
            // getcheckpoints
            // Returns configured checkpoints for this network
            let checkpoints: Vec<serde_json::Value> = node
                .checkpoint_verifier()
                .checkpoints()
                .iter()
                .map(|cp| {
                    serde_json::json!({
                        "height": cp.height,
                        "hash": hex::encode(cp.hash),
                    })
                })
                .collect();
            Ok((
                serde_json::json!({
                    "checkpoints": checkpoints,
                    "max_height": node.checkpoint_verifier().max_checkpoint_height(),
                }),
                RpcAction::Continue,
            ))
        }
        // ============================================================
        // Peer/Connection RPCs
        // ============================================================
        "getpeerinfo" => {
            // getpeerinfo
            // Returns info about all connected peers
            if let Some(pm) = node.peer_manager() {
                let peers: Vec<serde_json::Value> = pm
                    .list_peers()
                    .iter()
                    .map(|peer| {
                        serde_json::json!({
                            "id": peer.id,
                            "addr": peer.addr,
                            "inbound": peer.direction == crate::node::peer::PeerDirection::Inbound,
                            "version": peer.version,
                            "services": format!("{:#x}", peer.services),
                            "startingheight": peer.start_height,
                            "conntime": peer.connected_at,
                            "banscore": peer.score.raw_score(),
                        })
                    })
                    .collect();
                Ok((Value::Array(peers), RpcAction::Continue))
            } else {
                // No peer manager = not listening for connections
                Ok((Value::Array(vec![]), RpcAction::Continue))
            }
        }
        "getconnectioncount" => {
            // getconnectioncount
            // Returns total number of connected peers
            let (inbound, outbound) = node.peer_count();
            Ok((Value::from(inbound + outbound), RpcAction::Continue))
        }
        "getnetworkinfo" => {
            // getnetworkinfo
            // Returns network status info
            let (inbound, outbound) = node.peer_count();
            let listening = node.peer_manager().is_some();
            Ok((
                serde_json::json!({
                    "connections": inbound + outbound,
                    "connections_in": inbound,
                    "connections_out": outbound,
                    "networkactive": listening,
                }),
                RpcAction::Continue,
            ))
        }
        // ============================================================
        // Transaction Utility RPCs
        // ============================================================
        "validateaddress" => {
            // validateaddress <address>
            // Returns address validation info
            let addr = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing address"))?;

            match decode_address(addr) {
                Ok(decoded) => Ok((
                    serde_json::json!({
                        "isvalid": true,
                        "address": addr,
                        "scriptPubKey": hex::encode(&decoded.script_pubkey),
                        "witness_version": decoded.witness_version,
                        "witness_program": hex::encode(decoded.program),
                        "hrp": decoded.hrp,
                    }),
                    RpcAction::Continue,
                )),
                Err(_) => Ok((serde_json::json!({"isvalid": false}), RpcAction::Continue)),
            }
        }
        "decoderawtransaction" => {
            // decoderawtransaction <hex>
            // Parses a hex-encoded transaction and returns JSON
            let hex_str = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing transaction hex"))?;

            let bytes = hex::decode(hex_str).map_err(|_| anyhow!("invalid hex encoding"))?;
            let tx = parse_transaction(&bytes)?;

            // Build vin array
            let vin: Vec<Value> = tx
                .vin
                .iter()
                .map(|inp| {
                    serde_json::json!({
                        "txid": hex::encode(inp.prevout.txid),
                        "vout": inp.prevout.vout,
                        "scriptSig": {
                            "hex": hex::encode(&inp.script_sig)
                        },
                        "sequence": inp.sequence
                    })
                })
                .collect();

            // Build vout array with script type detection
            let vout: Vec<Value> = tx
                .vout
                .iter()
                .enumerate()
                .map(|(i, out)| {
                    let script_type = match parse_script_pubkey(&out.script_pubkey) {
                        crate::script::ScriptType::P2QTSH(_) => "P2QTSH",
                        crate::script::ScriptType::P2QPKH(_) => "P2QPKH",
                        crate::script::ScriptType::OpReturn(_) => "OP_RETURN",
                        crate::script::ScriptType::Unknown => "unknown",
                    };
                    serde_json::json!({
                        "value": out.value as f64 / 100_000_000.0,
                        "n": i,
                        "scriptPubKey": {
                            "hex": hex::encode(&out.script_pubkey),
                            "type": script_type
                        }
                    })
                })
                .collect();

            let result = serde_json::json!({
                "txid": hex::encode(tx.txid()),
                "version": tx.version,
                "locktime": tx.lock_time,
                "size": bytes.len(),
                "vin": vin,
                "vout": vout,
            });
            Ok((result, RpcAction::Continue))
        }
        "gettransaction" => {
            // gettransaction "txid"
            // Returns details about a transaction by txid
            let txid_hex = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing txid parameter"))?;

            let txid_bytes = hex::decode(txid_hex).map_err(|_| anyhow!("invalid txid hex"))?;
            if txid_bytes.len() != 32 {
                return Err(anyhow!("txid must be 32 bytes"));
            }
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&txid_bytes);

            // Check txindex first
            if let Some(loc) = node.txindex_get(&txid) {
                // Found in txindex - get the block and transaction
                let block = node
                    .get_block_parsed(&loc.block_hash)
                    .ok_or_else(|| anyhow!("block not found: {}", loc.block_hash))?;

                if loc.tx_position as usize >= block.txdata.len() {
                    return Err(anyhow!("transaction index out of bounds"));
                }

                let tx = &block.txdata[loc.tx_position as usize];

                // Get block height for confirmations
                let block_height = node.get_block_height(&loc.block_hash).unwrap_or(0);
                let confirmations = node.height().saturating_sub(block_height) + 1;

                // Calculate total output value
                let amount: i64 = tx.vout.iter().map(|o| o.value as i64).sum();

                let result = serde_json::json!({
                    "txid": txid_hex,
                    "blockhash": loc.block_hash,
                    "blockheight": block_height,
                    "confirmations": confirmations,
                    "time": block.header.time,
                    "hex": hex::encode(tx.serialize(true)),
                    "amount": amount,
                });

                Ok((result, RpcAction::Continue))
            } else {
                // Check mempool
                if let Some(tx) = node.mempool_get(&txid) {
                    let amount: i64 = tx.vout.iter().map(|o| o.value as i64).sum();

                    let result = serde_json::json!({
                        "txid": txid_hex,
                        "confirmations": 0,
                        "hex": hex::encode(tx.serialize(true)),
                        "amount": amount,
                    });

                    Ok((result, RpcAction::Continue))
                } else {
                    Err(anyhow!(
                        "transaction not found (requires --txindex or mempool)"
                    ))
                }
            }
        }
        "createrawtransaction" => {
            // createrawtransaction [{"txid":"...", "vout":n},...] {"address":amount,...} [locktime]
            // Creates an unsigned raw transaction
            let inputs = params
                .first()
                .and_then(|v| v.as_array())
                .ok_or_else(|| anyhow!("missing inputs array"))?;
            let outputs = params
                .get(1)
                .and_then(|v| v.as_object())
                .ok_or_else(|| anyhow!("missing outputs object"))?;
            let locktime = params.get(2).and_then(|v| v.as_u64()).unwrap_or(0) as u32;

            // Parse inputs
            let mut vin = Vec::with_capacity(inputs.len());
            for input in inputs {
                let txid_hex = input
                    .get("txid")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("input missing txid"))?;
                let vout = input
                    .get("vout")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow!("input missing vout"))?
                    as u32;

                let txid_bytes =
                    hex::decode(txid_hex).map_err(|_| anyhow!("invalid txid hex: {}", txid_hex))?;
                if txid_bytes.len() != 32 {
                    return Err(anyhow!("txid must be 32 bytes"));
                }
                let mut txid = [0u8; 32];
                txid.copy_from_slice(&txid_bytes);

                vin.push(crate::types::TxIn {
                    prevout: crate::types::OutPoint { txid, vout },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                    witness: vec![],
                });
            }

            // Parse outputs
            let mut vout = Vec::with_capacity(outputs.len());
            for (addr, amount) in outputs {
                // Support both integer satoshis and float BTC amounts
                let value_sats = if let Some(sats) = amount.as_u64() {
                    sats
                } else if let Some(btc) = amount.as_f64() {
                    (btc * 100_000_000.0).round() as u64
                } else {
                    return Err(anyhow!("invalid amount for address {}", addr));
                };

                // Validate output value (defense in depth - also checked at mempool entry)
                // Allow zero for OP_RETURN (addr == "data"), but reject for regular outputs
                if addr != "data" && value_sats == 0 {
                    return Err(anyhow!(
                        "output value must be greater than 0 for address {}",
                        addr
                    ));
                }

                // Handle special "data" key for OP_RETURN
                let script_pubkey = if addr == "data" {
                    let data_hex = amount
                        .as_str()
                        .ok_or_else(|| anyhow!("data value must be hex string"))?;
                    let data =
                        hex::decode(data_hex).map_err(|_| anyhow!("invalid data hex encoding"))?;
                    let mut script = vec![0x6a]; // OP_RETURN
                    crate::varint::ser_bytes(&data, &mut script);
                    script
                } else {
                    // Decode address to scriptPubKey
                    let decoded = decode_address(addr)
                        .map_err(|e| anyhow!("invalid address {}: {}", addr, e))?;
                    decoded.script_pubkey
                };

                vout.push(crate::types::TxOut {
                    value: value_sats,
                    script_pubkey,
                });
            }

            // Build transaction
            let tx = crate::types::Transaction {
                version: 2,
                vin,
                vout,
                lock_time: locktime,
            };

            // Serialize to hex (no witness for unsigned tx)
            let hex_str = hex::encode(tx.serialize(false));
            Ok((Value::String(hex_str), RpcAction::Continue))
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
