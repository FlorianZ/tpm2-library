// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::TpmPolicyExpression;
use thiserror::Error;
use tpm2_protocol::data::TpmCc;

/// Language interpretation and compilation errors.
#[derive(Debug, Error)]
pub enum TpmPolicyError {
    #[error("authorization list is too long")]
    AuthListTooLong,

    /// A digest calculation failed.
    #[error("crypto: {0}")]
    Crypto(#[from] tpm2_crypto::TpmCryptoError),

    /// A handle operation failed.
    #[error("handle: {0}")]
    Handle(#[from] tpm2_vtpm::VtpmError),

    #[error("invalid command code: {0:?}")]
    InvalidCc(TpmCc),
    #[error("invalid expression: {0}")]
    InvalidExpression(Box<TpmPolicyExpression>),
    #[error("invalid token: {0}")]
    InvalidToken(String),
    #[error("invalid PCR digest")]
    InvalidPcrDigest,
    #[error("invalid PCR digest algorithm")]
    InvalidPcrDigestAlgorithm,
    #[error("invalid PCR selection")]
    InvalidPcrSelection,
    #[error("invalid policy digest algorithm")]
    InvalidPolicyDigestAlgorithm,

    /// Marshaling a TPM protocol encoded object failed.
    #[error("marshal: {0}")]
    Marshal(tpm2_protocol::TpmProtocolError),

    #[error("operation failed")]
    OperationFailed,
    #[error("parenthesis mismatch")]
    ParenthesisMismatch,
    #[error("PCR bank not available: {0}")]
    PcrBankNotAvailable(tpm2_crypto::TpmHash),
    #[error("PCR digest is missing")]
    PcrDigestMissing,
    #[error("PCR digest is too large")]
    PcrDigestTooLarge,
    #[error("PCR index is too large")]
    PcrIndexTooLarge,
    #[error("PCR selection size is too large")]
    PcrSelectionTooLarge,
    #[error("too many branches: {0}")]
    TooManyBranches(Box<TpmPolicyExpression>),
    #[error("trailing data")]
    TrailingData,
    #[error("unexpected end")]
    UnexpectedEnd,
}
