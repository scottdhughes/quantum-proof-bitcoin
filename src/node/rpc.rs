use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::node::node::Node;

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
    let parsed: RpcRequest = match serde_json::from_str(req_json) {
        Ok(r) => r,
        Err(_) => {
            return ser_error(Value::Null, -32700, "parse error");
        }
    };

    if parsed.jsonrpc != "2.0" {
        return ser_error(parsed.id, -32600, "invalid request");
    }

    match dispatch(node, &parsed.method, &parsed.params) {
        Ok(res) => ser_ok(parsed.id, res),
        Err(e) => ser_error(parsed.id, -32000, &e.to_string()),
    }
}

fn dispatch(node: &mut Node, method: &str, params: &[Value]) -> Result<Value> {
    match method {
        "getblockcount" => Ok(Value::from(node.height())),
        "getbestblockhash" => Ok(Value::from(node.best_hash_hex().to_string())),
        "getblockhash" => {
            let h = params
                .first()
                .and_then(|v| v.as_u64())
                .ok_or_else(|| anyhow!("missing height"))?;
            let hash = node
                .get_blockhash(h)
                .ok_or_else(|| anyhow!("height out of range"))?;
            Ok(Value::from(hash))
        }
        "getblock" => {
            let hash = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing block hash"))?;
            let bytes = node
                .get_block_bytes(hash)
                .ok_or_else(|| anyhow!("block not found"))?;
            Ok(Value::from(hex::encode(bytes)))
        }
        "submitblock" => {
            let hex = params
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("missing block hex"))?;
            let bytes = hex::decode(hex).map_err(|_| anyhow!("invalid block hex"))?;
            node.submit_block_bytes(&bytes)?;
            Ok(Value::String("accepted".to_string()))
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
            if let Some(p) = node.utxo_get(&txid, vout) {
                Ok(serde_json::json!({
                    "value": p.value,
                    "script_pubkey_hex": hex::encode(p.script_pubkey),
                }))
            } else {
                Ok(Value::Null)
            }
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
