// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::TpmPolicyExpression;
use thiserror::Error;
use tpm2_protocol::data::TpmCc;

/// Language interpretation and compilation errors.
#[derive(Debug, Error)]
pub enum TpmPolicyError {
    /// Authorization list is too long.
    #[error("authorization list is too long")]
    AuthListTooLong,

    /// A digest calculation failed.
    #[error("crypto: {0}")]
    Crypto(#[from] tpm2_crypto::TpmCryptoError),

    /// An invalid command code was encountered.
    #[error("invalid command code: {0:?}")]
    InvalidCc(TpmCc),

    /// An invalid expression was encountered.
    #[error("invalid expression: {0}")]
    InvalidExpression(Box<TpmPolicyExpression>),

    /// Handle type byte is not valid.
    #[error("invalid handle type: 0x{0:02x}")]
    InvalidHandleType(u8),

    /// An invalid token was encountered.
    #[error("invalid token: {0}")]
    InvalidToken(String),

    /// An invalid PCR digest was encountered.
    #[error("invalid PCR digest")]
    InvalidPcrDigest,

    /// An invalid PCR digest algorithm was encountered.
    #[error("invalid PCR digest algorithm")]
    InvalidPcrDigestAlgorithm,

    /// An invalid PCR selection was encountered.
    #[error("invalid PCR selection")]
    InvalidPcrSelection,

    /// An invalid policy digest algorithm was encountered.
    #[error("invalid policy digest algorithm")]
    InvalidPolicyDigestAlgorithm,

    /// Marshaling a TPM protocol encoded object failed.
    #[error("marshal: {0}")]
    Marshal(tpm2_protocol::TpmError),

    /// Operation failed because of internal error.
    #[error("operation failed")]
    OperationFailed,

    /// Parenthesis mismatch in expression.
    #[error("parenthesis mismatch")]
    ParenthesisMismatch,

    /// PCR bank is not available.
    #[error("PCR bank not available: {0}")]
    PcrBankNotAvailable(tpm2_crypto::TpmHash),

    /// PCR count mismatch.
    #[error("PCR count mismatch")]
    PcrCountMismatch,

    /// PCR digest is missing.
    #[error("PCR digest is missing")]
    PcrDigestMissing,

    /// PCR digest is too large.
    #[error("PCR digest is too large")]
    PcrDigestTooLarge,

    /// PCR index is too large.
    #[error("PCR index is too large")]
    PcrIndexTooLarge,

    /// PCR selection size is too large.
    #[error("PCR selection size is too large")]
    PcrSelectionTooLarge,

    /// Too many branches were provided.
    #[error("too many branches: {0}")]
    TooManyBranches(Box<TpmPolicyExpression>),

    /// After unmarshaling, there was still data left over.
    #[error("trailing data")]
    TrailingData,

    /// Unmarshaling could not be completed because there was not enough data.
    #[error("unexpected end")]
    UnexpectedEnd,
}
