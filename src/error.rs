//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::Expression;
use thiserror::Error;
use tpm2_crypto::Hash;
use tpm2_protocol::data::TpmCc;

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
    #[error("invalid command code: {0:?}")]
    InvalidCc(TpmCc),
    #[error("invalid expression: {0}")]
    InvalidExpression(Expression),
    #[error("invalid token: {0}")]
    InvalidToken(String),
    #[error("invalid PCR digest")]
    InvalidPcrDigest,
    #[error("invalid PCR digest algorithm")]
    InvalidPcrDigestAlgorithm,
    #[error("invalid secret call")]
    InvalidSecretCall,
    #[error("invalid PCR selection")]
    InvalidPcrSelection,
    #[error("invalid policy digest algorithm")]
    InvalidPolicyDigestAlgorithm,
    #[error("operation failed")]
    OperationFailed,
    #[error("parenthesis mismatch")]
    ParenthesisMismatch,
    #[error("PCR bank not available: {0}")]
    PcrBankNotAvailable(Hash),
    #[error("PCR digest is missing")]
    PcrDigestMissing,
    #[error("PCR digest is too large")]
    PcrDigestTooLarge,
    #[error("PCR index is too large")]
    PcrIndexTooLarge,
    #[error("PCR selection size is too large")]
    PcrSelectionTooLarge,
    #[error("too many branches: {0}")]
    TooManyBranches(Expression),
    #[error("trailing data")]
    TrailingData,
    #[error("unexpected end")]
    UnexpectedEnd,
}
