// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use thiserror::Error;

/// The top-level error type for cryptographic operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TpmCryptoError {
    /// ECC curve is not supported in the context of use.
    #[error("invalid ECC curve")]
    InvalidEccCurve,

    /// Invalid ECC public parameters.
    #[error("invalid ECC parameters")]
    InvalidEccParameters,

    /// Hash algorithm is not supported in the context of use.
    #[error("invalid hash algorithm")]
    InvalidHash,

    /// Invalid RSA key bits.
    #[error("invalid RSA key bits: {0}")]
    InvalidKeyBits(u16),

    /// Invalid object type.
    #[error("invalid object type")]
    InvalidObjectType,

    /// Invalid RSA public parameters.
    #[error("invalid RSA parameters")]
    InvalidRsaParameters,

    /// A zero-length key was provided.
    #[error("the provided key has zero length")]
    KeyIsEmpty,

    /// Marshaling a TPM protocol encoded object failed.
    #[error("marshal: {0}")]
    Marshal(tpm2_protocol::TpmProtocolError),

    /// A cryptographic operation failed.
    #[error("operation failed")]
    OperationFailed,

    /// Not enough memory available.
    #[error("out of memory")]
    OutOfMemory,

    /// The provided HMAC does not match to the expected value.
    #[error("permission denied")]
    PermissionDenied,

    /// Unmarshaling a TPM protocol encoded object failed.
    #[error("unmarshal: {0}")]
    Unmarshal(tpm2_protocol::TpmProtocolError),
}
