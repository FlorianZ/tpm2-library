// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use thiserror::Error;
use tpm2_protocol::data::{TpmAlgId, TpmCc};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("invalid authorization string prefix (expected 'password:', 'policy:', or 'vtpm:')")]
    InvalidPrefix,
    #[error("authorization data size too large: {0}")]
    SizeTooLarge(usize),
    #[error("invalid hex string for password or policy")]
    InvalidHex,
    #[error("invalid handle string for session: {0}")]
    InvalidHandleString(String),
    #[error("invalid handle type for session: 0x{0:02x}")]
    InvalidHandleType(u8),
    #[error("expected 'password:<hex>'")]
    ExpectedPassword,
    #[error("invalid digest size: {0}")]
    InvalidDigestSize(usize),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HandleError {
    #[error("handle has less than eight characters")]
    TooFewDigits,
    #[error("handle has more than one '*")]
    TooManyAsterisks,
    #[error("handle has more than eight characters")]
    TooManyDigits,
    #[error("invalid handle string: {0}")]
    InvalidString(String),
    #[error("invalid handle type: 0x{0:02x}")]
    InvalidType(u8),
    #[error("handle must be a persistent TPM handle ('tpm:81xxxxxx')")]
    MustBePersistent,
    #[error("handle is a pattern but a concrete value is required")]
    PatternNotAllowed,
    #[error("invalid handle value: {0:08x}")]
    InvalidValue(u32),
    #[error("invalid handle scheme (expected 'tpm:' or 'vtpm:')")]
    InvalidScheme,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PcrError {
    #[error("PCR selection string is not valid: {0}")]
    InvalidSelectionString(String),
    #[error("PCR selection index overflow: {0}")]
    IndexOverflow(usize),
    #[error("PCR selection size too large: {0}")]
    SelectionTooLarge(usize),
    #[error("PCR value (digest) is missing")]
    ValueMissing,
    #[error("PCR bank not available: {0:?}")]
    BankMissing(TpmAlgId),
    #[error("invalid digest size: {0}")]
    InvalidDigestSize(usize),
    #[error("invalid hex digest format")]
    InvalidDigestFormat,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretError {
    #[error("secret() expects 1 to 3 arguments")]
    ArgumentCount,
    #[error("a handle name for {0:08x} was not provided in the policy state")]
    HandleNameMissing(u32),
    #[error("invalid digest size: {0}")]
    InvalidDigestSize(usize),
    #[error("invalid hex digest format")]
    InvalidDigestFormat,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExpressionError {
    #[error("malformed policy command: {0}")]
    MalformedPolicyCommand(String),
    #[error("parser state is malformed")]
    MalformedState,
    #[error("unexpected end of expression")]
    UnexpectedEnd,
    #[error("unexpected token: {0}")]
    UnexpectedToken(String),
    #[error("parenthesis mismatch")]
    ParenthesisMismatch,
    #[error("trailing data")]
    TrailingData,
    #[error("invalid expression node: {0}")]
    InvalidNode(String),
    #[error(transparent)]
    Pcr(#[from] PcrError),
    #[error("invalid hex digest format")]
    InvalidDigestFormat,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommandError {
    #[error("unexpected non-policy command: {0:?}")]
    UnexpectedCommand(TpmCc),
    #[error("failed to build command: {0}")]
    BuildFailed(String),
    #[error("failed to parse command: {0}")]
    ParseFailed(String),
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedHashAlgorithm(String),
    #[error("invalid digest size: {0}")]
    InvalidDigestSize(usize),
}

/// The primary error type for this crate.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Command(#[from] CommandError),
    #[error(transparent)]
    Expression(#[from] ExpressionError),
    #[error(transparent)]
    Handle(#[from] HandleError),
    #[error(transparent)]
    Pcr(#[from] PcrError),
    #[error(transparent)]
    Secret(#[from] SecretError),
}
