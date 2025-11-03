//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use thiserror::Error;
use tpm2_crypto::CryptoError;
use tpm2_protocol::data::{TpmAlgId, TpmCc, TpmRcBase};
use tpm2_protocol::{TpmMarshalError, TpmUnmarshalError};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("expected 'password:<hex>'")]
    ExpectedPassword,
    #[error("invalid password string")]
    InvalidPasswordString,
    #[error("invalid handle string: {0}")]
    InvalidHandleString(String),
    #[error("invalid handle type: 0x{0:02x}")]
    InvalidHandleType(u8),
    #[error("invalid policy string: {0}")]
    InvalidPolicyString(String),
    #[error("invalid prefix, expected 'password:', 'policy:', or 'vtpm:'")]
    InvalidPrefix,
    #[error("too large digest size: {0}")]
    TooLargeDigest(usize),
    #[error("too large auth size: {0}")]
    TooLargeAuth(usize),
    #[error("unmarshal error: {0}")]
    Unmarshal(TpmUnmarshalError),
}

impl From<TpmUnmarshalError> for AuthError {
    fn from(err: TpmUnmarshalError) -> Self {
        Self::Unmarshal(err)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HandleError {
    #[error("invalid prefix, expected 'tpm:' or 'vtpm:'")]
    InvalidPrefix,
    #[error("invalid handle string: {0}")]
    InvalidString(String),
    #[error("invalid handle type: 0x{0:02x}")]
    InvalidType(u8),
    #[error("invalid handle value: {0:08x}")]
    InvalidValue(u32),
    #[error("handle pattern is not allowed")]
    PatternNotAllowed,
    #[error("handle has less than eight characters")]
    TooFewDigits,
    #[error("handle has more than one asterisk")]
    TooManyAsterisks,
    #[error("handle has more than eight characters")]
    TooManyDigits,
    #[error("protocol unmarshal error: {0}")]
    Unmarshal(TpmUnmarshalError),
}

impl From<TpmUnmarshalError> for HandleError {
    fn from(err: TpmUnmarshalError) -> Self {
        Self::Unmarshal(err)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PcrError {
    #[error("invalid digest string: {0}")]
    InvalidDigestString(String),
    #[error("invalid PCR selection string: {0}")]
    InvalidSelectionString(String),
    #[error("invalid digest size: {0}")]
    Marshal(TpmMarshalError),
    #[error("PCR bank not available: {0:?}")]
    MissingBank(TpmAlgId),
    #[error("missing PCR digest")]
    MissingPcrDigest,
    #[error("too large digest size: {0}")]
    TooLargeDigest(usize),
    #[error("PCR index too large: {0}")]
    TooLargeIndex(usize),
    #[error("PCR selection size too large: {0}")]
    TooLargeSelection(usize),
    #[error("protocol unmarshal error: {0}")]
    Unmarshal(TpmUnmarshalError),
}

impl From<TpmMarshalError> for PcrError {
    fn from(err: TpmMarshalError) -> Self {
        Self::Marshal(err)
    }
}

impl From<TpmUnmarshalError> for PcrError {
    fn from(err: TpmUnmarshalError) -> Self {
        Self::Unmarshal(err)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretError {
    #[error("secret() expects 1 to 3 arguments")]
    ArgumentCount,
    #[error("a handle name for {0:08x} was not provided in the policy state")]
    HandleNameMissing(u32),
    #[error("invalid digest size: {0}")]
    InvalidDigestSize(usize),
    #[error("invalid digest string: {0}")]
    InvalidDigestString(String),
    #[error("protocol unmarshal error: {0}")]
    Unmarshal(TpmUnmarshalError),
}

impl From<TpmUnmarshalError> for SecretError {
    fn from(err: TpmUnmarshalError) -> Self {
        Self::Unmarshal(err)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExpressionError {
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
    #[error(transparent)]
    Secret(#[from] SecretError),
    #[error("invalid digest string: {0}")]
    InvalidDigestString(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommandError {
    #[error("crypto error: {0}")]
    Crypto(TpmRcBase),
    #[error("invalid algorithm: {0}")]
    InvalidAlgorithm(String),
    #[error("invalid digest size: {0}")]
    InvalidDigestSize(usize),
    #[error("protocol marshal error: {0}")]
    Marshal(TpmMarshalError),
    #[error("protocol unmarshal error: {0}")]
    Unmarshal(TpmUnmarshalError),
    #[error("too many or-branches: {0}")]
    TooManyOrBranches(usize),
    #[error("unexpected non-policy command: {0:?}")]
    UnexpectedCommand(TpmCc),
}

impl From<CryptoError> for CommandError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::Rc(rc) => Self::Crypto(rc),
            CryptoError::Marshal(e) => Self::Marshal(e),
            CryptoError::Unmarshal(e) => Self::Unmarshal(e),
        }
    }
}

impl From<TpmMarshalError> for CommandError {
    fn from(err: TpmMarshalError) -> Self {
        Self::Marshal(err)
    }
}

impl From<TpmUnmarshalError> for CommandError {
    fn from(err: TpmUnmarshalError) -> Self {
        Self::Unmarshal(err)
    }
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
