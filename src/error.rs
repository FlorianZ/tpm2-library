//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use thiserror::Error;
use tpm2_protocol::data::{TpmAlgId, TpmCc};

/// The top-level error type.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error(transparent)]
    Auth(#[from] crate::AuthError),
    #[error(transparent)]
    Handle(#[from] crate::HandleError),
    #[error(transparent)]
    Language(#[from] crate::LanguageError),
}

/// Language interpretation and compilation errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LanguageError {
    #[error("authorization list is too long")]
    AuthListTooLong,
    #[error("invalid expression: {0}")]
    InvalidExpression(String),
    #[error("invalid PCR digest")]
    InvalidPcrDigest,
    #[error("invalid PCR digest algorithm")]
    InvalidPcrDigestAlgorithm,
    #[error("PCR selection string is not valid: {0}")]
    InvalidPcrSelection(String),
    #[error("invalid policy digest algorithm")]
    InvalidPolicyDigestAlgorithm,
    #[error("operation failed")]
    OperationFailed,
    #[error("parenthesis mismatch")]
    ParenthesisMismatch,
    #[error("PCR bank not available: {0:?}")]
    PcrBankMissing(TpmAlgId),
    #[error("PCR digest is missing")]
    PcrDigestMissing,
    #[error("invalid digest size: {0}")]
    PcrDigestTooLarge(usize),
    #[error("index is too large: {0} in {1}")]
    PcrIndexTooLarge(usize, String),
    #[error("PCR selection size too large: {0}")]
    PcrSelectionTooLarge(String),
    #[error("PCR digest is missing")]
    PcrValueMissing,
    #[error("expression has too many branches: {0}")]
    TooManyBranches(String),
    #[error("trailing data")]
    TrailingData,
    #[error("unexpected non-policy command: {0:?}")]
    UnsupportedCommand(TpmCc),
    #[error("unexpected end of expression")]
    UnexpectedEnd,
    #[error("unexpected token: {0}")]
    UnexpectedToken(String),
    #[error("unsupported hash algorithm: {0:?}")]
    UnsupportedHashAlgorithm(TpmAlgId),
}
