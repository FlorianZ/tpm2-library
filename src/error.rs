// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::TpmPolicyExpression;
use thiserror::Error;
use tpm2_crypto::Hash;
use tpm2_protocol::data::TpmCc;

/// Language interpretation and compilation errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TpmPolicyError {
    #[error("authorization list is too long")]
    AuthListTooLong,

    /// A digest calculation failed.
    #[error("crypto: {0}")]
    Crypto(#[from] tpm2_crypto::Error),

    #[error("handle has more than one asterisk")]
    HandleHasTooManyAsterisks,
    #[error("handle pattern is not allowed")]
    HandlePatternNotAllowed,
    #[error("handle prefix is missing")]
    HandlePrefixMissing,
    #[error("handle is less than eight characters")]
    HandleTooLong,
    #[error("handle has more than eight characters")]
    HandleTooShort,
    #[error("invalid command code: {0:?}")]
    InvalidCc(TpmCc),
    #[error("invalid expression: {0}")]
    InvalidExpression(Box<TpmPolicyExpression>),
    #[error("invalid handle character: {0}")]
    InvalidHandleCharacter(char),
    #[error("invalid handle prefix")]
    InvalidHandlePrefix,
    #[error("invalid handle type: 0x{0:02x}")]
    InvalidHandleType(u8),
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
    TooManyBranches(Box<TpmPolicyExpression>),
    #[error("trailing data")]
    TrailingData,
    #[error("unexpected end")]
    UnexpectedEnd,
}
