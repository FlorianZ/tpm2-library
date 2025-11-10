//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use thiserror::Error;
use tpm2_policy_language::Error as PolicyLanguageError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("key error: {0}")]
    Key(#[from] KeyError),
    #[error("policy language: {0}")]
    PolicyLanguage(#[from] PolicyLanguageError),
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid key type")]
    InvalidKeyType,
    #[error("invalid command code: {0:08x}")]
    InvalidCc(u32),
    #[error("invalid DER tag: {0}")]
    InvalidDerTag(String),
    #[error("invalid DER data")]
    InvalidDer,
    #[error("invalid PEM tag: {0}")]
    InvalidPemTag(String),
    #[error("invalid PEM data")]
    InvalidPem,
    #[error("operation failed")]
    OperationFailed,
}
