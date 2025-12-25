use crate::constants::CHAIN_ID;
use crate::errors::ConsensusError;
use crate::hashing::{hash256, tagged_hash};
use crate::types::{Prevout, Transaction, TxOut};
use crate::varint::ser_bytes;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SighashType(pub u8);

impl SighashType {
    pub const ALL: u8 = 0x01;
    pub const NONE: u8 = 0x02;
    pub const SINGLE: u8 = 0x03;
    pub const ANYONECANPAY: u8 = 0x80;

    pub fn base(self) -> u8 {
        self.0 & 0x7f
    }

    pub fn anyone_can_pay(self) -> bool {
        self.0 & Self::ANYONECANPAY != 0
    }

    pub fn is_valid(self) -> bool {
        matches!(self.base(), Self::ALL | Self::NONE | Self::SINGLE)
    }
}

fn ser_prevout(txid: &[u8; 32], vout: u32, buf: &mut Vec<u8>) {
    buf.extend(txid.iter().rev());
    buf.extend_from_slice(&vout.to_le_bytes());
}

fn ser_output(o: &TxOut, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&o.value.to_le_bytes());
    ser_bytes(&o.script_pubkey, buf);
}

fn hash_outputs_all(outputs: &[TxOut]) -> [u8; 32] {
    let mut buf = Vec::new();
    for o in outputs {
        ser_output(o, &mut buf);
    }
    hash256(&buf)
}

fn hash_outputs_single(outputs: &[TxOut], index: usize) -> [u8; 32] {
    if index >= outputs.len() {
        [0u8; 32]
    } else {
        let mut buf = Vec::new();
        ser_output(&outputs[index], &mut buf);
        hash256(&buf)
    }
}

/// Compute QPB_SIGHASH digest.
///
/// ext_flag: 0x00 for key path (P2QPKH), 0x01 for script path (QTSH).
/// leaf_hash is required when ext_flag == 0x01.
pub fn qpb_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[Prevout],
    sighash_type: u8,
    ext_flag: u8,
    leaf_hash: Option<[u8; 32]>,
) -> Result<[u8; 32], ConsensusError> {
    let sh = SighashType(sighash_type);
    if !sh.is_valid() {
        return Err(ConsensusError::InvalidSighashType);
    }
    if prevouts.len() != tx.vin.len() {
        return Err(ConsensusError::PrevoutsLengthMismatch);
    }
    if input_index >= tx.vin.len() {
        return Err(ConsensusError::PrevoutsLengthMismatch);
    }

    let mut buf = Vec::new();

    // hashPrevouts
    if sh.anyone_can_pay() {
        buf.extend_from_slice(&[0u8; 32]);
    } else {
        let mut tmp = Vec::new();
        for vin in &tx.vin {
            ser_prevout(&vin.prevout.txid, vin.prevout.vout, &mut tmp);
        }
        buf.extend_from_slice(&hash256(&tmp));
    }

    // hashSequences
    if sh.anyone_can_pay() || matches!(sh.base(), SighashType::NONE | SighashType::SINGLE) {
        buf.extend_from_slice(&[0u8; 32]);
    } else {
        let mut tmp = Vec::new();
        for vin in &tx.vin {
            tmp.extend_from_slice(&vin.sequence.to_le_bytes());
        }
        buf.extend_from_slice(&hash256(&tmp));
    }

    // SerPrevout(current)
    {
        let vin = &tx.vin[input_index];
        ser_prevout(&vin.prevout.txid, vin.prevout.vout, &mut buf);
    }

    // value + scriptPubKey of prevout
    let prev = &prevouts[input_index];
    buf.extend_from_slice(&prev.value.to_le_bytes());
    ser_bytes(&prev.script_pubkey, &mut buf);

    // sequence (current)
    buf.extend_from_slice(&tx.vin[input_index].sequence.to_le_bytes());

    // hashOutputs
    match sh.base() {
        SighashType::ALL => buf.extend_from_slice(&hash_outputs_all(&tx.vout)),
        SighashType::SINGLE => {
            buf.extend_from_slice(&hash_outputs_single(&tx.vout, input_index));
        }
        SighashType::NONE => buf.extend_from_slice(&[0u8; 32]),
        _ => unreachable!(),
    }

    // lock_time and sighash_type
    buf.extend_from_slice(&tx.lock_time.to_le_bytes());
    buf.extend_from_slice(&(sighash_type as u32).to_le_bytes());

    // CHAIN_ID
    buf.extend_from_slice(&CHAIN_ID);

    // ext_flag and optional leaf_hash
    buf.push(ext_flag);
    if ext_flag == 0x01 {
        let leaf = leaf_hash.ok_or(ConsensusError::InvalidSighashType)?; // placeholder error
        buf.extend_from_slice(&leaf);
    }

    // preimage = buf prefixed by nVersion
    let mut preimage = Vec::with_capacity(4 + buf.len());
    preimage.extend_from_slice(&tx.version.to_le_bytes());
    preimage.extend_from_slice(&buf);

    let tagged = tagged_hash("QPB/SIGHASH", &preimage);
    Ok(hash256(&tagged))
}
