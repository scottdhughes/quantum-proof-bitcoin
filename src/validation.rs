use crate::constants::{
    LOCKTIME_THRESHOLD, MAX_CONTROL_BLOCK_DEPTH, MAX_PQSIGCHECK_BUDGET, MAX_PQSIGCHECK_PER_TX,
    MAX_SCRIPT_SIZE, MAX_WITNESS_ITEM_BYTES, SCRIPT_LEAF_VERSION_V0, SEQUENCE_FINAL,
};
use crate::errors::ConsensusError;
use crate::pow::validate_pow;
use crate::pq::{AlgorithmId, pqsig_cost, verify_pq};
use crate::reward::block_subsidy;
use crate::script::{
    ScriptType, execute_qscript, parse_script_pubkey, qpkh32, qtap_leaf_hash, qtap_reconstruct_root,
};
use crate::sighash::qpb_sighash;
use crate::types::{Block, Prevout, Transaction};
use crate::weight::{block_weight_wu, effective_median, max_allowed_weight, penalty};

// ============================================================================
// Locktime validation (BIP68/BIP113)
// ============================================================================

/// Check if a transaction is "final" - meaning its locktime should be ignored.
/// A transaction is final if ALL inputs have sequence = 0xffffffff.
pub fn is_tx_final_by_sequence(tx: &Transaction) -> bool {
    tx.vin.iter().all(|input| input.sequence == SEQUENCE_FINAL)
}

/// Compute Median Time Past (MTP) from a list of block timestamps.
/// BIP113 defines MTP as the median of the last 11 block timestamps.
/// Returns 0 if the list is empty.
pub fn compute_mtp(timestamps: &[u32]) -> u32 {
    if timestamps.is_empty() {
        return 0;
    }
    let mut sorted: Vec<u32> = timestamps.to_vec();
    sorted.sort();
    sorted[sorted.len() / 2]
}

/// Check if a transaction's locktime is satisfied.
///
/// # Arguments
/// * `tx` - The transaction to check
/// * `block_height` - The height of the block containing this transaction
/// * `block_time` - The MTP (Median Time Past) for time-based locktimes (BIP113)
///
/// # Returns
/// * `Ok(())` if the locktime is satisfied
/// * `Err(ConsensusError::LocktimeNotSatisfied)` if the locktime is not satisfied
pub fn check_locktime(tx: &Transaction, block_height: u32, mtp: u32) -> Result<(), ConsensusError> {
    // If all inputs are final, locktime is ignored
    if is_tx_final_by_sequence(tx) {
        return Ok(());
    }

    let locktime = tx.lock_time;

    // locktime of 0 is always satisfied
    if locktime == 0 {
        return Ok(());
    }

    if locktime < LOCKTIME_THRESHOLD {
        // Height-based locktime: tx is valid when block_height >= locktime
        if block_height < locktime {
            return Err(ConsensusError::LocktimeNotSatisfied);
        }
    } else {
        // Time-based locktime: tx is valid when MTP >= locktime
        if mtp < locktime {
            return Err(ConsensusError::LocktimeNotSatisfied);
        }
    }

    Ok(())
}

/// Check locktime for mempool acceptance.
/// Uses next block height and current MTP.
pub fn check_locktime_for_mempool(
    tx: &Transaction,
    current_height: u32,
    current_mtp: u32,
) -> Result<(), ConsensusError> {
    // For mempool, we check against the *next* block height
    let next_height = current_height.saturating_add(1);
    check_locktime(tx, next_height, current_mtp)
}

/// Validate a single P2QPKH input; returns PQSigCheck cost units consumed.
pub fn validate_p2qpkh_input(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[Prevout],
) -> Result<u32, ConsensusError> {
    let vin = &tx.vin[input_index];

    if !vin.script_sig.is_empty() {
        return Err(ConsensusError::InvalidScriptPubKey);
    }

    // Witness must be [sig_ser, pk_ser]
    if vin.witness.len() != 2 {
        return Err(ConsensusError::InvalidSignature);
    }
    for item in &vin.witness {
        if item.len() > MAX_WITNESS_ITEM_BYTES {
            return Err(ConsensusError::WitnessItemTooLarge);
        }
    }

    let sig_ser = &vin.witness[0];
    let pk_ser = &vin.witness[1];

    if pk_ser.is_empty() {
        return Err(ConsensusError::InvalidPublicKey);
    }
    let alg = AlgorithmId::from_byte(pk_ser[0])?;
    let pk_bytes = &pk_ser[1..];

    if sig_ser.is_empty() {
        return Err(ConsensusError::InvalidSignature);
    }
    let (&sighash_type, sig_bytes) = sig_ser
        .split_last()
        .ok_or(ConsensusError::InvalidSignature)?;

    // Check qpkh32 commitment
    let script_hash = match parse_script_pubkey(&prevouts[input_index].script_pubkey) {
        ScriptType::P2QPKH(h) => h,
        _ => return Err(ConsensusError::InvalidScriptPubKey),
    };
    let computed = qpkh32(pk_ser);
    if computed != script_hash {
        return Err(ConsensusError::InvalidPublicKey);
    }

    // Compute sighash
    let msg32 = qpb_sighash(tx, input_index, prevouts, sighash_type, 0x00, None)?;

    // Verify (stub)
    verify_pq(alg, pk_bytes, &msg32, sig_bytes)?;

    Ok(pqsig_cost(alg))
}

/// Validate a single P2QTSH (witness v2) input; returns PQSigCheck cost units consumed.
pub fn validate_p2qtsh_input(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[Prevout],
) -> Result<u32, ConsensusError> {
    let vin = &tx.vin[input_index];
    if !vin.script_sig.is_empty() {
        return Err(ConsensusError::InvalidScriptPubKey);
    }
    if vin.witness.len() < 2 {
        return Err(ConsensusError::InvalidSignature);
    }
    for item in &vin.witness {
        if item.len() > MAX_WITNESS_ITEM_BYTES {
            return Err(ConsensusError::WitnessItemTooLarge);
        }
    }

    let leaf_script = vin.witness[vin.witness.len() - 2].clone();
    let control_block = vin.witness[vin.witness.len() - 1].clone();
    let stack_items = vin.witness[..vin.witness.len() - 2].to_vec();

    if leaf_script.len() > MAX_SCRIPT_SIZE {
        return Err(ConsensusError::ScriptTooLarge);
    }

    if control_block.is_empty() || !(control_block.len() - 1).is_multiple_of(32) {
        return Err(ConsensusError::InvalidControlBlock);
    }
    let m = (control_block.len() - 1) / 32;
    if m > MAX_CONTROL_BLOCK_DEPTH {
        return Err(ConsensusError::InvalidControlBlock);
    }
    let control_byte = control_block[0];
    if control_byte & 1 == 0 {
        return Err(ConsensusError::InvalidControlBlock);
    }
    let leaf_version = control_byte & 0xfe;
    if leaf_version != SCRIPT_LEAF_VERSION_V0 {
        return Err(ConsensusError::InvalidControlBlock);
    }

    // Extract merkle nodes
    let mut nodes = Vec::with_capacity(m);
    for i in 0..m {
        let start = 1 + i * 32;
        let mut n = [0u8; 32];
        n.copy_from_slice(&control_block[start..start + 32]);
        nodes.push(n);
    }

    let leaf_hash = qtap_leaf_hash(leaf_version, &leaf_script);
    let qroot = qtap_reconstruct_root(leaf_hash, &nodes);

    // Match scriptPubKey
    let script_hash = match parse_script_pubkey(&prevouts[input_index].script_pubkey) {
        ScriptType::P2QTSH(h) => h,
        _ => return Err(ConsensusError::InvalidScriptPubKey),
    };
    if qroot != script_hash {
        return Err(ConsensusError::InvalidControlBlock);
    }

    // Build script that pre-pushes witness stack items then executes leaf_script
    let mut script_with_witness = Vec::new();
    for item in &stack_items {
        if item.len() <= 0x4b {
            script_with_witness.push(item.len() as u8);
            script_with_witness.extend_from_slice(item);
        } else if item.len() <= 0xff {
            script_with_witness.push(0x4c);
            script_with_witness.push(item.len() as u8);
            script_with_witness.extend_from_slice(item);
        } else {
            script_with_witness.push(0x4d);
            let len = item.len() as u16;
            script_with_witness.extend_from_slice(&len.to_le_bytes());
            script_with_witness.extend_from_slice(item);
        }
    }
    script_with_witness.extend_from_slice(&leaf_script);

    let mut ctx = crate::script::QScriptCtx {
        tx,
        input_index,
        prevouts,
        ext_flag: 0x01,
        leaf_hash: Some(leaf_hash),
        pqsig_cost_acc: 0,
        pqsig_cost_limit: MAX_PQSIGCHECK_PER_TX,
    };

    execute_qscript(&script_with_witness, &mut ctx)?;
    Ok(ctx.pqsig_cost_acc)
}

/// Validate a transaction's inputs and return PQSigCheck cost.
pub fn validate_transaction_basic(
    tx: &Transaction,
    prevouts: &[Prevout],
) -> Result<u32, ConsensusError> {
    if prevouts.len() != tx.vin.len() {
        return Err(ConsensusError::PrevoutsLengthMismatch);
    }

    let mut cost: u32 = 0;
    for idx in 0..tx.vin.len() {
        let sc = parse_script_pubkey(&prevouts[idx].script_pubkey);
        match sc {
            ScriptType::P2QPKH(_) => {
                let add = validate_p2qpkh_input(tx, idx, prevouts)?;
                cost = cost
                    .checked_add(add)
                    .ok_or(ConsensusError::PQSigCheckBudgetExceeded)?;
                if cost > MAX_PQSIGCHECK_PER_TX {
                    return Err(ConsensusError::PQSigCheckBudgetExceeded);
                }
            }
            ScriptType::P2QTSH(_) => {
                let add = validate_p2qtsh_input(tx, idx, prevouts)?;
                cost = cost
                    .checked_add(add)
                    .ok_or(ConsensusError::PQSigCheckBudgetExceeded)?;
                if cost > MAX_PQSIGCHECK_PER_TX {
                    return Err(ConsensusError::PQSigCheckBudgetExceeded);
                }
            }
            ScriptType::OpReturn(_) | ScriptType::Unknown => {
                return Err(ConsensusError::InvalidScriptPubKey);
            }
        }
    }
    Ok(cost)
}

/// Compute witness merkle root (BIP141 style with wtxid[0]=0).
pub fn witness_merkle_root(block: &Block) -> [u8; 32] {
    if block.txdata.is_empty() {
        return [0u8; 32];
    }
    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(block.txdata.len());
    hashes.push([0u8; 32]); // coinbase
    for tx in block.txdata.iter().skip(1) {
        hashes.push(tx.wtxid());
    }
    // Merkle pairwise hash256
    while hashes.len() > 1 {
        let mut next = Vec::with_capacity(hashes.len().div_ceil(2));
        for i in (0..hashes.len()).step_by(2) {
            let a = hashes[i];
            let b = if i + 1 < hashes.len() {
                hashes[i + 1]
            } else {
                hashes[i]
            };
            let mut concat = Vec::with_capacity(64);
            concat.extend_from_slice(&a);
            concat.extend_from_slice(&b);
            next.push(crate::hashing::hash256(&concat));
        }
        hashes = next;
    }
    hashes[0]
}

/// Validate witness commitment per spec.
pub fn validate_witness_commitment(block: &Block) -> Result<(), ConsensusError> {
    if block.txdata.is_empty() {
        return Ok(());
    }
    let has_witness = block
        .txdata
        .iter()
        .any(|tx| tx.vin.iter().any(|i| !i.witness.is_empty()));
    if !has_witness {
        return Ok(());
    }

    // Coinbase witness must have exactly one 32-byte item.
    let coinbase = &block.txdata[0];
    if coinbase.vin.is_empty() {
        return Err(ConsensusError::WitnessCommitmentMismatch);
    }
    let cb_witness = &coinbase.vin[0].witness;
    if cb_witness.len() != 1 || cb_witness[0].len() != 32 {
        return Err(ConsensusError::WitnessCommitmentMismatch);
    }
    let reserved = &cb_witness[0];

    let wroot = witness_merkle_root(block);
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&wroot);
    buf.extend_from_slice(reserved);
    let commitment_hash = crate::hashing::hash256(&buf);

    // Find commitment output (last matching)
    let mut found = false;
    for txout in coinbase.vout.iter().rev() {
        let spk = &txout.script_pubkey;
        if spk.len() >= 38
            && spk[0] == 0x6a
            && spk[1] == 0x24
            && spk[2] == 0xaa
            && spk[3] == 0x21
            && spk[4] == 0xa9
            && spk[5] == 0xed
            && spk[6..38] == commitment_hash
        {
            found = true;
            break;
        }
    }
    if !found {
        return Err(ConsensusError::WitnessCommitmentMismatch);
    }
    Ok(())
}

/// Validate block weight, PQSigCheck budget, locktimes, and witness commitment.
///
/// # Arguments
/// * `block` - The block to validate
/// * `prevouts_by_tx` - Prevouts for each transaction (empty vec for coinbase)
/// * `stm` - Short-term median weight
/// * `ltm` - Long-term median weight
/// * `check_pow` - Whether to validate proof-of-work
/// * `height` - Height of this block
/// * `mtp` - Median Time Past for time-based locktime validation (BIP113)
pub fn validate_block_basic(
    block: &Block,
    prevouts_by_tx: &[Vec<Prevout>],
    stm: u32,
    ltm: u32,
    check_pow: bool,
    height: u32,
    mtp: u32,
) -> Result<(), ConsensusError> {
    if block.txdata.len() != prevouts_by_tx.len() {
        return Err(ConsensusError::PrevoutsLengthMismatch);
    }

    // Weight check
    let (base_bytes, wit_bytes) = block.byte_sizes();
    let weight = block_weight_wu(base_bytes, wit_bytes);
    let max_allowed = max_allowed_weight(stm, ltm);
    if weight > max_allowed {
        return Err(ConsensusError::ScriptFailed);
    }

    if check_pow {
        validate_pow(&block.header)?;
    }

    // PQSigCheck budget, fee tally, and locktime validation
    let mut fees: i128 = 0;
    let mut block_cost = 0u32;
    for (i, (tx, prevs)) in block.txdata.iter().zip(prevouts_by_tx.iter()).enumerate() {
        if i == 0 {
            // Coinbase tx input scripts are not validated here.
            continue;
        }

        // Validate locktime for non-coinbase transactions
        check_locktime(tx, height, mtp)?;

        let tx_cost = validate_transaction_basic(tx, prevs)?;
        block_cost = block_cost
            .checked_add(tx_cost)
            .ok_or(ConsensusError::PQSigCheckBudgetExceeded)?;
        if block_cost > MAX_PQSIGCHECK_BUDGET {
            return Err(ConsensusError::PQSigCheckBudgetExceeded);
        }

        // Fees = sum(prevouts) - sum(outputs)
        let input_sum: u64 = prevs.iter().map(|p| p.value).sum();
        let output_sum: u64 = tx.vout.iter().map(|o| o.value).sum();
        if output_sum > input_sum {
            return Err(ConsensusError::InvalidScriptPubKey);
        }
        fees += (input_sum as i128) - (output_sum as i128);
    }

    // Witness commitment
    validate_witness_commitment(block)?;

    // Subsidy, penalty, coinbase value check
    let coinbase_value: u64 = block.txdata[0].vout.iter().map(|o| o.value).sum();
    let subsidy = block_subsidy(height);
    let eff_median = effective_median(stm, ltm) as u64;
    let penalty_amt = penalty(subsidy, weight as u64, eff_median);

    let total_fees = fees.max(0) as u64;
    let available = subsidy
        .saturating_add(total_fees)
        .saturating_sub(penalty_amt);
    if coinbase_value > available {
        return Err(ConsensusError::ScriptFailed);
    }

    Ok(())
}
