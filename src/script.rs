use crate::constants::{
    MAX_SCRIPT_OPS, MAX_SCRIPT_SIZE, MAX_STACK_ITEMS, MAX_WITNESS_ITEM_BYTES, OP_CHECKPQSIG,
    OP_CTV, P2QPKH_VERSION, P2QTSH_VERSION,
};
use crate::errors::ConsensusError;
use crate::hashing::{hash256, tagged_hash};
use crate::pq::{AlgorithmId, pqsig_cost, verify_pq};
use crate::sighash::qpb_sighash;
use crate::types::{Prevout, Transaction};
use crate::varint::ser_bytes;

/// Parsed scriptPubKey variants supported at genesis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptType {
    P2QTSH([u8; 32]),
    P2QPKH([u8; 32]),
    OpReturn(Vec<u8>),
    Unknown,
}

/// Compute qpkh32 = HASH256(TaggedHash("QPB/QPKH", pk_ser)).
pub fn qpkh32(pk_ser: &[u8]) -> [u8; 32] {
    hash256(&tagged_hash("QPB/QPKH", pk_ser))
}

/// Build scriptPubKey for P2QPKH.
pub fn build_p2qpkh(hash: [u8; 32]) -> Vec<u8> {
    let mut spk = Vec::with_capacity(34);
    spk.push(0x50 + P2QPKH_VERSION); // OP_3 (0x53)
    spk.push(0x20);
    spk.extend_from_slice(&hash);
    spk
}

/// Build scriptPubKey for P2QTSH.
pub fn build_p2qtsh(root: [u8; 32]) -> Vec<u8> {
    let mut spk = Vec::with_capacity(34);
    spk.push(0x50 + P2QTSH_VERSION); // OP_2 (0x52)
    spk.push(0x20);
    spk.extend_from_slice(&root);
    spk
}

/// Parse genesis-valid scriptPubKey.
pub fn parse_script_pubkey(script: &[u8]) -> ScriptType {
    if script.len() == 34 && script[0] == 0x50 + P2QTSH_VERSION && script[1] == 0x20 {
        let mut h = [0u8; 32];
        h.copy_from_slice(&script[2..34]);
        ScriptType::P2QTSH(h)
    } else if script.len() == 34 && script[0] == 0x50 + P2QPKH_VERSION && script[1] == 0x20 {
        let mut h = [0u8; 32];
        h.copy_from_slice(&script[2..34]);
        ScriptType::P2QPKH(h)
    } else if script.first() == Some(&0x6a) {
        // OP_RETURN <push>
        if script.len() == 1 {
            return ScriptType::OpReturn(Vec::new());
        }
        let push_len = script[1] as usize;
        if script.len() == push_len + 2 && push_len <= 80 {
            return ScriptType::OpReturn(script[2..].to_vec());
        }
        ScriptType::Unknown
    } else {
        ScriptType::Unknown
    }
}

// ---------- QTap (P2QTSH) helpers ----------

pub fn qtap_leaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + script.len() + 9);
    buf.push(leaf_version);
    ser_bytes(script, &mut buf);
    tagged_hash("QPB/QTapLeaf", &buf)
}

pub fn qtap_branch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(lo);
    buf.extend_from_slice(hi);
    tagged_hash("QPB/QTapBranch", &buf)
}

/// Reconstruct merkle root from leaf_hash and control_block nodes.
pub fn qtap_reconstruct_root(leaf_hash: [u8; 32], merkle_path: &[[u8; 32]]) -> [u8; 32] {
    let mut h = leaf_hash;
    for node in merkle_path {
        h = qtap_branch_hash(&h, node);
    }
    h
}

// ---------- QScript v0 executor ----------

#[derive(Clone)]
pub struct QScriptCtx<'a> {
    pub tx: &'a Transaction,
    pub input_index: usize,
    pub prevouts: &'a [Prevout],
    pub ext_flag: u8, // 0x01 for QTSH, 0x00 for keypath (unused here)
    pub leaf_hash: Option<[u8; 32]>,
    pub pqsig_cost_acc: u32,   // accumulated cost during this tx
    pub pqsig_cost_limit: u32, // per-tx cap
}

pub fn execute_qscript(script: &[u8], ctx: &mut QScriptCtx) -> Result<(), ConsensusError> {
    if script.len() > MAX_SCRIPT_SIZE {
        return Err(ConsensusError::ScriptTooLarge);
    }

    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut ops_executed: usize = 0;

    let mut pc = 0usize;
    while pc < script.len() {
        let op = script[pc];
        pc += 1;

        // Pushdata handling
        if (0x01..=0x4b).contains(&op) {
            let n = op as usize;
            if pc + n > script.len() {
                return Err(ConsensusError::ScriptFailed);
            }
            let data = script[pc..pc + n].to_vec();
            pc += n;
            if data.len() > MAX_WITNESS_ITEM_BYTES {
                return Err(ConsensusError::WitnessItemTooLarge);
            }
            stack.push(data);
            if stack.len() > MAX_STACK_ITEMS {
                return Err(ConsensusError::TooManyStackItems);
            }
            continue;
        } else if op == 0x00 {
            stack.push(Vec::new());
            continue;
        } else if op == 0x4c {
            if pc >= script.len() {
                return Err(ConsensusError::ScriptFailed);
            }
            let n = script[pc] as usize;
            pc += 1;
            if pc + n > script.len() {
                return Err(ConsensusError::ScriptFailed);
            }
            let data = script[pc..pc + n].to_vec();
            pc += n;
            if data.len() > MAX_WITNESS_ITEM_BYTES {
                return Err(ConsensusError::WitnessItemTooLarge);
            }
            stack.push(data);
            if stack.len() > MAX_STACK_ITEMS {
                return Err(ConsensusError::TooManyStackItems);
            }
            continue;
        } else if op == 0x4d {
            if pc + 2 > script.len() {
                return Err(ConsensusError::ScriptFailed);
            }
            let n = u16::from_le_bytes([script[pc], script[pc + 1]]) as usize;
            pc += 2;
            if pc + n > script.len() {
                return Err(ConsensusError::ScriptFailed);
            }
            let data = script[pc..pc + n].to_vec();
            pc += n;
            if data.len() > MAX_WITNESS_ITEM_BYTES {
                return Err(ConsensusError::WitnessItemTooLarge);
            }
            stack.push(data);
            if stack.len() > MAX_STACK_ITEMS {
                return Err(ConsensusError::TooManyStackItems);
            }
            continue;
        } else if op == 0x4e {
            return Err(ConsensusError::ScriptFailed); // avoid giant pushes; spec limit is 10KB anyway
        }

        // Non-push opcode; count towards op limit.
        ops_executed += 1;
        if ops_executed > MAX_SCRIPT_OPS {
            return Err(ConsensusError::TooManyScriptOps);
        }

        match op {
            0x51..=0x60 => {
                // OP_1 .. OP_16
                let v = (op - 0x50) as i8;
                stack.push(vec![v as u8]);
            }
            0x75 => {
                // OP_DROP
                stack.pop().ok_or(ConsensusError::ScriptFailed)?;
            }
            0x76 => {
                // OP_DUP
                let top = stack.last().cloned().ok_or(ConsensusError::ScriptFailed)?;
                stack.push(top);
            }
            0x7c => {
                // OP_SWAP
                if stack.len() < 2 {
                    return Err(ConsensusError::ScriptFailed);
                }
                let len = stack.len();
                stack.swap(len - 1, len - 2);
            }
            0x87 => {
                // OP_EQUAL
                if stack.len() < 2 {
                    return Err(ConsensusError::ScriptFailed);
                }
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                stack.push(if a == b { vec![1] } else { vec![0] });
            }
            0x88 => {
                // OP_EQUALVERIFY
                if stack.len() < 2 {
                    return Err(ConsensusError::ScriptFailed);
                }
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                if a != b {
                    return Err(ConsensusError::ScriptFailed);
                }
            }
            0x69 => {
                // OP_VERIFY
                let v = stack.pop().ok_or(ConsensusError::ScriptFailed)?;
                if v.iter().all(|&b| b == 0) {
                    return Err(ConsensusError::ScriptFailed);
                }
            }
            0xa9 => {
                // OP_HASH160 (not strictly required, but cheap)
                use sha2::{Digest, Sha256};
                let v = stack.pop().ok_or(ConsensusError::ScriptFailed)?;
                let mut h = Sha256::new();
                h.update(&v);
                let first = h.finalize();
                let mut h2 = ripemd::Ripemd160::new();
                h2.update(first);
                let out = h2.finalize();
                stack.push(out.to_vec());
            }
            0xaa => {
                // OP_HASH256
                let v = stack.pop().ok_or(ConsensusError::ScriptFailed)?;
                stack.push(hash256(&v).to_vec());
            }
            OP_CTV => {
                // If stack empty: fail. If top size !=32 => NOP (do nothing).
                let top = stack.pop().ok_or(ConsensusError::ScriptFailed)?;
                if top.len() != 32 {
                    stack.push(top); // NOP: push back unchanged
                    continue;
                }
                let expected = top;
                // Serialize tx template per BIP119 subset implemented here.
                let tx = ctx.tx;
                let mut buf = Vec::new();
                buf.extend_from_slice(&tx.version.to_le_bytes());
                buf.extend_from_slice(&tx.lock_time.to_le_bytes());

                // hashPrevouts (scriptSigs hash if non-empty) -> here we hash scriptSigs as in BIP119
                let mut scriptsig_concat = Vec::new();
                for vin in &tx.vin {
                    ser_bytes(&vin.script_sig, &mut scriptsig_concat);
                }
                buf.extend_from_slice(&hash256(&scriptsig_concat));

                buf.extend_from_slice(&(tx.vin.len() as u32).to_le_bytes());
                // sequences hash
                let mut seqs = Vec::new();
                for vin in &tx.vin {
                    seqs.extend_from_slice(&vin.sequence.to_le_bytes());
                }
                buf.extend_from_slice(&hash256(&seqs));

                buf.extend_from_slice(&(tx.vout.len() as u32).to_le_bytes());
                // outputs hash
                let mut outs = Vec::new();
                for o in &tx.vout {
                    outs.extend_from_slice(&o.value.to_le_bytes());
                    ser_bytes(&o.script_pubkey, &mut outs);
                }
                buf.extend_from_slice(&hash256(&outs));

                buf.extend_from_slice(&(ctx.input_index as u32).to_le_bytes());

                let h = hash256(&buf);
                if h != expected.as_slice() {
                    return Err(ConsensusError::ScriptFailed);
                }
                // Success is NOP (no push).
            }
            OP_CHECKPQSIG => {
                // Pops: sig_ser, pk_ser
                let sig_ser = stack.pop().ok_or(ConsensusError::ScriptFailed)?;
                let pk_ser = stack.pop().ok_or(ConsensusError::ScriptFailed)?;

                // Sig parsing: last byte sighash_type
                if sig_ser.is_empty() || pk_ser.is_empty() {
                    stack.push(vec![0]);
                    continue;
                }
                let (&sighash_type, sig_bytes) = sig_ser
                    .split_last()
                    .ok_or(ConsensusError::InvalidSignature)?;
                let alg = match AlgorithmId::from_byte(pk_ser[0]) {
                    Ok(a) => a,
                    Err(_) => {
                        stack.push(vec![0]);
                        continue;
                    }
                };
                let pk_bytes = &pk_ser[1..];

                // Sighash
                let msg32 = match qpb_sighash(
                    ctx.tx,
                    ctx.input_index,
                    ctx.prevouts,
                    sighash_type,
                    ctx.ext_flag,
                    ctx.leaf_hash,
                ) {
                    Ok(m) => m,
                    Err(_) => {
                        stack.push(vec![0]);
                        continue;
                    }
                };

                let verify_res = verify_pq(alg, pk_bytes, &msg32, sig_bytes);

                // Cost accounting
                let add = pqsig_cost(alg);
                ctx.pqsig_cost_acc = ctx
                    .pqsig_cost_acc
                    .checked_add(add)
                    .ok_or(ConsensusError::PQSigCheckBudgetExceeded)?;
                if ctx.pqsig_cost_acc > ctx.pqsig_cost_limit {
                    return Err(ConsensusError::PQSigCheckBudgetExceeded);
                }

                if verify_res.is_ok() {
                    stack.push(vec![1]);
                } else {
                    stack.push(vec![0]);
                }
            }
            0x6a => {
                // OP_RETURN
                return Err(ConsensusError::ScriptFailed);
            }
            0x61 => {
                // OP_NOP
                continue;
            }
            _ => return Err(ConsensusError::Unimplemented("opcode")),
        }
    }

    if stack.len() != 1 {
        return Err(ConsensusError::CleanStack);
    }
    let final_top = stack.pop().unwrap();
    if final_top.iter().all(|&b| b == 0) {
        return Err(ConsensusError::ScriptFailed);
    }
    Ok(())
}
