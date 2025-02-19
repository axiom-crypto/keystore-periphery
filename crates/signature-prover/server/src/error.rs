use jsonrpsee::types::error::ErrorCode;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignatureProverError {
    // Transaction errors
    #[error("Failed to decode transaction")]
    TransactionDecodeFailed,
    #[error("Missing required sponsor account")]
    MissingSponsorAccount,
    #[error("Transaction type not supported")]
    UnsupportedTransactionType,
    #[error("Unsupported verification key")]
    UnsupportedVerificationKey,
    #[error("Transaction already contains proof")]
    ProofAlreadyExists,
    #[error("Sponsor already set")]
    SponsorAlreadySet,

    #[error("AuthInputs decode failed: {0}")]
    AuthInputsDecodeError(String),
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    #[error("Server sponsorship not supported")]
    ServerSponsorshipNotSupported,

    #[error("Proof generation failed")]
    ProofGenerationFailed,
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<SignatureProverError> for jsonrpsee::types::ErrorObjectOwned {
    fn from(err: SignatureProverError) -> Self {
        let (code, msg, data) = match &err {
            SignatureProverError::Internal(msg) => (
                ErrorCode::InternalError.code(),
                err.to_string(),
                Some(msg.clone()),
            ),
            _ => (ErrorCode::InvalidParams.code(), err.to_string(), None),
        };

        jsonrpsee::types::ErrorObjectOwned::owned(code, msg, data)
    }
}
