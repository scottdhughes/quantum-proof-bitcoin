use crate::hashing::hash256;
use crate::varint::{ser_bytes, write_compact_size};

/// Outpoint (txid, vout).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// Transaction input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub prevout: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

/// Transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

/// Prevout data needed for sighash / validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prevout {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

/// Transaction object (SegWit-aware).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub lock_time: u32,
}

/// Block header (80 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_blockhash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

/// Full block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub txdata: Vec<Transaction>,
}

impl TxIn {
    fn serialize_base(&self, buf: &mut Vec<u8>) {
        // txid is serialized little-endian
        buf.extend_from_slice(&self.prevout.txid.iter().rev().cloned().collect::<Vec<_>>());
        buf.extend_from_slice(&self.prevout.vout.to_le_bytes());
        ser_bytes(&self.script_sig, buf);
        buf.extend_from_slice(&self.sequence.to_le_bytes());
    }
}

impl TxOut {
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.value.to_le_bytes());
        ser_bytes(&self.script_pubkey, buf);
    }
}

impl Transaction {
    /// Serialize transaction with or without witness.
    pub fn serialize(&self, include_witness: bool) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.version.to_le_bytes());

        if include_witness {
            buf.push(0x00);
            buf.push(0x01);
        }

        write_compact_size(self.vin.len() as u64, &mut buf);
        for txin in &self.vin {
            txin.serialize_base(&mut buf);
        }

        write_compact_size(self.vout.len() as u64, &mut buf);
        for txout in &self.vout {
            txout.serialize(&mut buf);
        }

        if include_witness {
            for txin in &self.vin {
                write_compact_size(txin.witness.len() as u64, &mut buf);
                for item in &txin.witness {
                    write_compact_size(item.len() as u64, &mut buf);
                    buf.extend_from_slice(item);
                }
            }
        }

        buf.extend_from_slice(&self.lock_time.to_le_bytes());
        buf
    }

    pub fn txid(&self) -> [u8; 32] {
        hash256(&self.serialize(false))
    }

    pub fn wtxid(&self) -> [u8; 32] {
        hash256(&self.serialize(true))
    }
}

impl BlockHeader {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(80);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(
            &self
                .prev_blockhash
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>(),
        );
        buf.extend_from_slice(&self.merkle_root.iter().rev().cloned().collect::<Vec<_>>());
        buf.extend_from_slice(&self.time.to_le_bytes());
        buf.extend_from_slice(&self.bits.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf
    }

    pub fn hash(&self) -> [u8; 32] {
        hash256(&self.serialize())
    }
}

impl Block {
    /// Serialize block with or without witness data.
    pub fn serialize(&self, include_witness: bool) -> Vec<u8> {
        let mut buf = self.header.serialize();
        write_compact_size(self.txdata.len() as u64, &mut buf);
        for tx in &self.txdata {
            buf.extend_from_slice(&tx.serialize(include_witness));
        }
        buf
    }

    /// Returns (base_bytes, witness_bytes).
    pub fn byte_sizes(&self) -> (usize, usize) {
        let base = self.serialize(false).len();
        let full = self.serialize(true).len();
        let witness = full.saturating_sub(base);
        (base, witness)
    }
}
