//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use thiserror::Error;
use tpm2_policy_language::Error as PolicyLanguageError;
use tpm2_protocol::{TpmMarshalError, TpmUnmarshalError};

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid algorithm: {0}")]
    InvalidAlgorithm(String),
    #[error("unsupported policy command: 0x{0:08x}")]
    UnsupportedPolicyCommand(u32),
    #[error("unknown OID: {0}")]
    UnknownOid(String),
}

#[derive(Debug, Error)]
pub enum PemError {
    #[error("invalid PEM tag: {0}")]
    InvalidTag(String),
    #[error("malformed PEM data: {0}")]
    MalformedData(String),
    #[error("invalid data for PEM encoding: {0}")]
    InvalidData(String),
}

#[derive(Debug, Error)]
pub enum DerError {
    #[error("malformed DER data: {0}")]
    MalformedData(String),
    #[error("invalid data for DER encoding: {0}")]
    InvalidData(String),
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("key error: {0}")]
    Key(#[from] KeyError),
    #[error("pem error: {0}")]
    Pem(#[from] PemError),
    #[error("der error: {0}")]
    Der(#[from] DerError),
    #[error("marshal error: {0}")]
    Marshal(TpmMarshalError),
    #[error("unmarshal error: {0}")]
    Unmarshal(TpmUnmarshalError),
    #[error("policy language: {0}")]
    PolicyLanguage(#[from] PolicyLanguageError),
}

impl From<TpmMarshalError> for Error {
    fn from(err: TpmMarshalError) -> Self {
        Self::Marshal(err)
    }
}

impl From<TpmUnmarshalError> for Error {
    fn from(err: TpmUnmarshalError) -> Self {
        Self::Unmarshal(err)
    }
}
