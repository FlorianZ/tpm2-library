// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Error types for the `tpm2-crypto` crate.

use thiserror::Error;
use tpm2_protocol::{
    data::{TpmAlgId, TpmEccCurve},
    TpmProtocolError,
};

/// Top-level error type for the crate.
#[derive(Debug, Error)]
pub enum Error {
    /// A TPM protocol marshaling error.
    #[error("protocol marshal error: {0}")]
    Marshal(TpmProtocolError),
    /// A TPM protocol unmarshaling error.
    #[error("protocol unmarshal error: {0}")]
    Unmarshal(TpmProtocolError),
    /// Hash algorithm is not supported.
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedHashAlgorithm(TpmAlgId),
    /// ECC curve is not supported.
    #[error("unsupported ECC curve: {0}")]
    UnsupportedEccCurve(TpmEccCurve),
    /// A cryptographic operation failed.
    #[error("operation failed")]
    OperationFailed,
    /// The provided HMAC is invalid.
    #[error("permission denied")]
    PermissionDenied,
    /// Not enough memory available.
    #[error("out of memory")]
    OutOfMemory,
    /// The provided key has an invalid length.
    #[error("invalid key length: {0}")]
    InvalidKeyLength(usize),
}
