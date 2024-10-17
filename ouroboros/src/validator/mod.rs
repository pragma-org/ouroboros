use thiserror::Error;

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("InvalidByteLength: {0}")]
    InvalidByteLength(String),
    #[error("Invalid VRF key for pool: expected: {0}, was: {1}")]
    InvalidVrfKeyForPool(String, String),
    #[error("Invalid block hash, expected: {0}, was: {1}")]
    InvalidBlockHash(String, String),
    #[error("Ledger error: {0}")]
    LedgerError(#[from] crate::ledger::Error),
    #[error("VrfVerificationError: {0}")]
    VrfVerificationError(#[from] pallas_crypto::vrf::VerificationError),
    #[error("InvalidVrfProofHash, expected: {0}, was: {1}")]
    InvalidVrfProofHash(String, String),
    #[error("InvalidVrfLeaderHash, expected: {0}, was: {1}")]
    InvalidVrfLeaderHash(String, String),
    #[error("InvalidOpcertSequenceNumber: {0}")]
    InvalidOpcertSequenceNumber(String),
    #[error("InvalidOpcertSignature")]
    InvalidOpcertSignature,
    #[error("KesVerificationError: {0}")]
    KesVerificationError(String),
    #[error("InsufficientPoolStake")]
    InsufficientPoolStake,
}

/// Generic trait for validating any type of data. Designed to be used across threads so validations
/// can be done in parallel.
pub trait Validator: Send + Sync {
    fn validate(&self) -> Result<(), ValidationError>;
}
