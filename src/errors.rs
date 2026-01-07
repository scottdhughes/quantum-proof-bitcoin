use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsensusError {
    #[error("invalid sighash type")]
    InvalidSighashType,
    #[error("prevouts length mismatch vs inputs")]
    PrevoutsLengthMismatch,
    #[error("witness item too large")]
    WitnessItemTooLarge,
    #[error("script too large")]
    ScriptTooLarge,
    #[error("too many script operations")]
    TooManyScriptOps,
    #[error("too many stack items")]
    TooManyStackItems,
    #[error("unsupported or malformed scriptPubKey")]
    InvalidScriptPubKey,
    #[error("pk_ser malformed")]
    InvalidPublicKey,
    #[error("sig_ser malformed")]
    InvalidSignature,
    #[error("PQ algorithm not active at genesis")]
    InactiveAlgorithm,
    #[error("PQ signature verification failed (stub)")]
    PQSignatureInvalid,
    #[error("PQSigCheck budget exceeded")]
    PQSigCheckBudgetExceeded,
    #[error("unimplemented feature: {0}")]
    Unimplemented(&'static str),
    #[error("cleanstack violation")]
    CleanStack,
    #[error("script evaluation failed")]
    ScriptFailed,
    #[error("invalid control block")]
    InvalidControlBlock,
    #[error("witness commitment missing or mismatch")]
    WitnessCommitmentMismatch,
    #[error("transaction locktime not satisfied")]
    LocktimeNotSatisfied,
    #[error("BIP68 relative locktime not satisfied")]
    SequenceLockNotSatisfied,
    #[error("transaction has no inputs")]
    EmptyInputs,
    #[error("transaction has no outputs")]
    EmptyOutputs,
    #[error("invalid transaction version: {0}")]
    InvalidVersion(i32),
}
