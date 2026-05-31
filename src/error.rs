// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use openssl::nid::Nid;
use thiserror::Error;
use tpm2_protocol::{
    basic::TpmUint32,
    data::{TpmAlgId, TpmEccCurve},
};

/// The public area field that failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmPublicAreaField {
    /// The public area object type did not match the requested key type.
    ObjectType,

    /// The public area parameters union did not match the requested key type.
    Parameters,

    /// The public area unique union did not match the requested key type.
    Unique,
}

/// The top-level error type for cryptographic operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TpmCryptoError {
    /// The output buffer is too small for the requested operation.
    #[error("buffer too small: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },

    /// ECC curve is not supported in the context of use.
    #[error("invalid ECC curve: {0:?}")]
    InvalidEccCurve(TpmEccCurve),

    /// OpenSSL ECC NID is not supported in the context of use.
    #[error("invalid ECC NID: {0:?}")]
    InvalidEccNid(Nid),

    /// Invalid ECC public area.
    #[error("invalid ECC public area: {field:?} for object type {object_type:?}")]
    InvalidEccPublicArea {
        /// Object type reported by the public area.
        object_type: TpmAlgId,

        /// Field that failed validation.
        field: TpmPublicAreaField,
    },

    /// Invalid ECC point shape.
    #[error(
        "invalid ECC point for {curve:?}: expected {expected_len}-byte coordinates, got x={x_len}, y={y_len}"
    )]
    InvalidEccPoint {
        /// TPM ECC curve associated with the point.
        curve: TpmEccCurve,

        /// Actual x coordinate length.
        x_len: usize,

        /// Actual y coordinate length.
        y_len: usize,

        /// Expected coordinate length.
        expected_len: usize,
    },

    /// Invalid ECC private scalar size.
    #[error("invalid ECC private scalar: {len} bytes exceeds {max} bytes")]
    InvalidEccPrivateScalar {
        /// Actual scalar length.
        len: usize,

        /// Maximum scalar length accepted by the TPM buffer type.
        max: usize,
    },

    /// Invalid ECC key structure.
    #[error("invalid ECC key")]
    InvalidEccKey,

    /// Hash algorithm is not supported in the context of use.
    #[error("invalid hash algorithm")]
    InvalidHash,

    /// Invalid RSA key bits.
    #[error("invalid RSA key bits: {0}")]
    InvalidKeyBits(u16),

    /// Invalid object type.
    #[error("invalid object type")]
    InvalidObjectType,

    /// Invalid RSA public area.
    #[error("invalid RSA public area: {field:?} for object type {object_type:?}")]
    InvalidRsaPublicArea {
        /// Object type reported by the public area.
        object_type: TpmAlgId,

        /// Field that failed validation.
        field: TpmPublicAreaField,
    },

    /// Invalid RSA key structure.
    #[error("invalid RSA key")]
    InvalidRsaKey,

    /// Invalid RSA public modulus.
    #[error("invalid RSA modulus")]
    InvalidRsaModulus(Vec<u8>),

    /// Invalid RSA public exponent.
    #[error("invalid RSA exponent: {0:?}")]
    InvalidRsaExponent(TpmUint32),

    /// Invalid RSA private prime size.
    #[error("invalid RSA private prime: {len} bytes exceeds {max} bytes")]
    InvalidRsaPrivatePrime {
        /// Actual private prime length.
        len: usize,

        /// Maximum private prime length accepted by the TPM buffer type.
        max: usize,
    },

    /// A zero-length key was provided.
    #[error("the provided key has zero length")]
    KeyIsEmpty,

    /// Marshaling a TPM protocol encoded object failed.
    #[error("marshal: {0}")]
    Marshal(tpm2_protocol::TpmError),

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
    Unmarshal(tpm2_protocol::TpmError),
}
