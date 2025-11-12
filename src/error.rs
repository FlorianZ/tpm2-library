// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2024-2025 Jarkko Sakkinen

use thiserror::Error;

/// Error type for encoding/decoding and data validation.
#[derive(Debug, Error)]
pub enum Error {
    /// Unsupported or inconsistent key type for this container.
    #[error("invalid key type")]
    InvalidKeyType,

    /// Command code in a policy command is not a valid `TPM_CC`.
    #[error("invalid command code: {0:08x}")]
    InvalidCc(u32),

    /// ASN.1 object identifier is not one of the supported TPM key OIDs.
    #[error("invalid DER tag: {0}")]
    InvalidDerTag(String),

    /// ASN.1 / TPM inner data are malformed or have an unexpected layout.
    #[error("invalid DER data")]
    InvalidDer,

    /// Importable key is missing its encrypted seed (`secret`).
    #[error("missing secret for importable key")]
    MissingSecret,

    /// Internal operation failed (e.g., buffer marshal overflow).
    #[error("operation failed")]
    OperationFailed,
}
