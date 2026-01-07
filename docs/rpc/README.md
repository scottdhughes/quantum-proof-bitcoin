# QPB JSON-RPC API Reference

The QPB node exposes a JSON-RPC 2.0 API on the configured RPC port (default: 38332 for devnet).

## Connection

```bash
# Basic request
curl -X POST http://localhost:38332/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"METHOD","params":[...]}'

# With authentication (if configured)
curl -X POST http://localhost:38332/rpc \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n 'user:pass' | base64)" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}'
```

## HTTP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/rpc` | POST | JSON-RPC API |
| `/health` | GET | Node health status |
| `/metrics` | GET | Prometheus metrics |

---

## Blockchain Methods

### getblockcount

Returns the height of the most-work fully-validated chain.

**Parameters:** None

**Returns:** `number` - Current block height

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}'
```

**Response:**
```json
{"jsonrpc":"2.0","id":1,"result":150}
```

---

### getbestblockhash

Returns the hash of the best (tip) block in the most-work fully-validated chain.

**Parameters:** None

**Returns:** `string` - Block hash (64 hex characters)

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"getbestblockhash","params":[]}'
```

**Response:**
```json
{"jsonrpc":"2.0","id":1,"result":"00000000a1b2c3d4..."}
```

---

### getblock

Returns raw block data for a given block hash.

**Parameters:**

| # | Name | Type | Required | Description |
|---|------|------|----------|-------------|
| 1 | blockhash | string | Yes | Block hash (hex) |

**Returns:** `string` - Raw block data (hex)

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblock","params":["00000000a1b2c3d4..."]}'
```

---

### getblockheader

Returns block header information for a given block hash.

**Parameters:**

| # | Name | Type | Required | Description |
|---|------|------|----------|-------------|
| 1 | blockhash | string | Yes | Block hash (hex) |

**Returns:** Object with header fields

| Field | Type | Description |
|-------|------|-------------|
| hash | string | Block hash |
| confirmations | number | Number of confirmations |
| height | number | Block height |
| version | number | Block version |
| merkleroot | string | Merkle root hash |
| time | number | Block timestamp |
| bits | string | Difficulty target (compact) |
| nonce | number | Nonce value |
| previousblockhash | string | Previous block hash |
| nextblockhash | string | Next block hash (if any) |

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockheader","params":["00000000a1b2c3d4..."]}'
```

---

## Transaction Methods

### getrawtransaction

Returns raw transaction data for a given transaction ID.

**Parameters:**

| # | Name | Type | Required | Description |
|---|------|------|----------|-------------|
| 1 | txid | string | Yes | Transaction ID (hex) |
| 2 | verbose | boolean | No | Return JSON object (default: false) |

**Returns:**
- If verbose=false: `string` - Raw transaction hex
- If verbose=true: Object with decoded transaction

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"getrawtransaction","params":["abc123...",true]}'
```

---

### sendrawtransaction

Submits a raw transaction to the network.

**Parameters:**

| # | Name | Type | Required | Description |
|---|------|------|----------|-------------|
| 1 | hexstring | string | Yes | Signed transaction hex |

**Returns:** `string` - Transaction ID (hex)

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"sendrawtransaction","params":["0200000001..."]}'
```

---

### createrawtransaction

Creates an unsigned raw transaction.

**Parameters:**

| # | Name | Type | Required | Description |
|---|------|------|----------|-------------|
| 1 | inputs | array | Yes | Array of `{"txid":"...", "vout":n}` |
| 2 | outputs | object | Yes | `{"address": amount, ...}` (BTC) |
| 3 | locktime | number | No | Lock time (default: 0) |

**Returns:** `string` - Unsigned transaction hex

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"createrawtransaction","params":[[{"txid":"abc...","vout":0}],{"qpbdev1q...":1.5}]}'
```

---

### decoderawtransaction

Decodes a raw transaction hex into JSON.

**Parameters:**

| # | Name | Type | Required | Description |
|---|------|------|----------|-------------|
| 1 | hexstring | string | Yes | Transaction hex |

**Returns:** Object with decoded transaction

| Field | Type | Description |
|-------|------|-------------|
| txid | string | Transaction ID |
| version | number | Transaction version |
| locktime | number | Lock time |
| size | number | Transaction size in bytes |
| vin | array | Input array |
| vout | array | Output array |

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"decoderawtransaction","params":["0200000001..."]}'
```

---

### validateaddress

Validates an address and returns information about it.

**Parameters:**

| # | Name | Type | Required | Description |
|---|------|------|----------|-------------|
| 1 | address | string | Yes | Address to validate |

**Returns:** Object with address info

| Field | Type | Description |
|-------|------|-------------|
| isvalid | boolean | Whether address is valid |
| address | string | The address (if valid) |
| scriptPubKey | string | Script pubkey hex |
| witness_version | number | Witness version (2 or 3) |
| witness_program | string | Witness program hex |
| hrp | string | Human-readable prefix |

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"validateaddress","params":["qpbdev1q..."]}'
```

---

## Mining Methods

### generatetoaddress

Mines blocks to a specified address.

**Parameters:**

| # | Name | Type | Required | Description |
|---|------|------|----------|-------------|
| 1 | nblocks | number | Yes | Number of blocks (1-10) |
| 2 | address | string | Yes | Coinbase recipient address |

**Returns:** `array` - Array of block hashes

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"generatetoaddress","params":[1,"qpbdev1q..."]}'
```

---

### getblocktemplate

Returns data needed to construct a block.

**Parameters:** None

**Returns:** Block template object with:
- `previousblockhash` - Previous block hash
- `height` - Block height
- `version` - Block version
- `bits` - Difficulty target
- `curtime` - Current timestamp
- `coinbasevalue` - Coinbase value (satoshis)
- `transactions` - Array of transaction templates

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblocktemplate","params":[]}'
```

---

### submitblock

Submits a solved block to the network.

**Parameters:**

| # | Name | Type | Required | Description |
|---|------|------|----------|-------------|
| 1 | hexdata | string | Yes | Block data (hex) |

**Returns:** `string` - "accepted" or error message

---

## Mempool Methods

### getmempoolinfo

Returns information about the memory pool.

**Parameters:** None

**Returns:** Object with mempool stats

| Field | Type | Description |
|-------|------|-------------|
| size | number | Transaction count |
| bytes | number | Total size in bytes |
| total_fee | number | Total fees (satoshis) |

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"getmempoolinfo","params":[]}'
```

---

### estimatesmartfee

Estimates the fee rate for confirmation within n blocks.

**Parameters:**

| # | Name | Type | Required | Description |
|---|------|------|----------|-------------|
| 1 | conf_target | number | No | Confirmation target (default: 6) |

**Returns:** Object with fee estimate

| Field | Type | Description |
|-------|------|-------------|
| feerate | number | Fee rate (BTC/kB) |
| blocks | number | Estimated blocks to confirm |

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"estimatesmartfee","params":[6]}'
```

---

## Wallet Methods

### createwallet

Creates or opens the default wallet.

**Parameters:** None

**Returns:** Object with wallet info

| Field | Type | Description |
|-------|------|-------------|
| name | string | Wallet name |
| path | string | Wallet file path |

---

### getnewaddress

Generates a new receiving address.

**Parameters:**

| # | Name | Type | Required | Description |
|---|------|------|----------|-------------|
| 1 | label | string | No | Address label |

**Returns:** `string` - New address (bech32m format)

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"getnewaddress","params":[]}'
```

**Response:**
```json
{"jsonrpc":"2.0","id":1,"result":"qpbdev1q5xy2k3g9..."}
```

---

### getbalance

Returns the wallet balance.

**Parameters:** None

**Returns:** `number` - Balance in satoshis

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"getbalance","params":[]}'
```

---

### sendtoaddress

Sends coins to an address.

**Parameters:**

| # | Name | Type | Required | Description |
|---|------|------|----------|-------------|
| 1 | address | string | Yes | Recipient address |
| 2 | amount | number | Yes | Amount in satoshis |
| 3 | fee_rate | number | No | Fee rate sat/vB (default: 1) |
| 4 | rbf | boolean | No | Enable RBF (default: false) |

**Returns:** `string` - Transaction ID

**Example:**
```bash
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"sendtoaddress","params":["qpbdev1q...",100000000,2,true]}'
```

---

## Network Methods

### getpeerinfo

Returns information about connected peers.

**Parameters:** None

**Returns:** `array` - Array of peer objects

| Field | Type | Description |
|-------|------|-------------|
| id | number | Peer ID |
| addr | string | IP address |
| inbound | boolean | Inbound connection |
| version | number | Protocol version |
| startingheight | number | Peer's height at connect |
| banscore | number | Misbehavior score |

---

### getnetworkinfo

Returns network status information.

**Parameters:** None

**Returns:** Object with network stats

| Field | Type | Description |
|-------|------|-------------|
| connections | number | Total connections |
| connections_in | number | Inbound connections |
| connections_out | number | Outbound connections |
| networkactive | boolean | Listening for connections |

---

## Control Methods

### stop

Shuts down the node gracefully.

**Parameters:** None

**Returns:** `string` - "stopping"

---

## Additional Methods

The following methods are also available:

| Method | Description |
|--------|-------------|
| `getblockhash` | Get block hash by height |
| `getutxo` | Get UTXO by outpoint |
| `getrawmempool` | Get mempool transaction count |
| `estimatefee` | Estimate fee (sat/vB format) |
| `listunspent` | List wallet UTXOs |
| `listaddresses` | List wallet addresses |
| `bumpfee` | Bump transaction fee (RBF) |
| `getwalletinfo` | Get wallet status |
| `encryptwallet` | Encrypt wallet with passphrase |
| `walletpassphrase` | Unlock encrypted wallet |
| `walletlock` | Lock encrypted wallet |
| `walletpassphrasechange` | Change wallet passphrase |
| `backupwallet` | Backup wallet file |
| `dumpwallet` | Export private keys |
| `importwallet` | Import private keys |
| `setban` | Add/remove IP ban |
| `listbanned` | List banned IPs |
| `clearbanned` | Clear all bans |
| `getcheckpoints` | Get network checkpoints |
| `getconnectioncount` | Get connection count |

---

## Error Codes

| Code | Description |
|------|-------------|
| -32700 | Parse error - Invalid JSON |
| -32600 | Invalid request |
| -32000 | Server error (see message) |

---

## Rate Limiting

The RPC server enforces rate limits to prevent abuse:
- Default: 100 requests per second per client
- Configurable via `--rpc-rate-limit` flag
