// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use openssl::{error::ErrorStack, nid::Nid};
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
#[derive(Debug, Error)]
pub enum TpmCryptoError {
    /// The output buffer is too small for the requested operation.
    #[error("buffer too small: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },

    /// A libcrypto operation failed.
    #[error("crypto: {0}")]
    Crypto(ErrorStack),

    /// ECC curve is not supported in the context of use.
    #[error("invalid ECC curve: {0:?}")]
    InvalidEccCurve(TpmEccCurve),

    /// OpenSSL ECC NID is not supported in the context of use.
    #[error("invalid ECC NID: {0:?}")]
    InvalidEccNid(Nid),

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

    /// Invalid ECC key structure.
    #[error("invalid ECC key")]
    InvalidEccKey,

    /// Invalid ECC group degree.
    #[error("invalid ECC group degree: {0}")]
    InvalidEccGroupDegree(u32),

    /// Hash algorithm is not supported in the context of use.
    #[error("invalid hash algorithm")]
    InvalidHash,

    /// OpenSSL message digest NID is not supported in the context of use.
    #[error("invalid message digest NID: {0:?}")]
    InvalidMessageDigestNid(Nid),

    /// Invalid RSA key bits.
    #[error("invalid RSA key bits: {0}")]
    InvalidKeyBits(u16),

    /// Invalid KDF key bits.
    #[error("invalid KDF key bits: {0} exceeds TPM UINT32")]
    InvalidKdfKeyBits(usize),

    /// Invalid object type.
    #[error("invalid object type")]
    InvalidObjectType,

    /// Invalid public area.
    #[error("invalid public area: {field:?} for object type {object_type:?}")]
    InvalidPublicArea {
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

    /// Invalid private key size.
    #[error("invalid private key: {len} bytes exceeds {max} bytes")]
    InvalidPrivateKeySize {
        /// Actual private key length.
        len: usize,

        /// Maximum length accepted by the TPM buffer type.
        max: usize,
    },

    /// RSA private prime is missing.
    #[error("missing RSA private prime")]
    MissingRsaPrivatePrime,

    /// A zero-length key was provided.
    #[error("the provided key has zero length")]
    KeyIsEmpty,

    /// Marshaling a TPM protocol encoded object failed.
    #[error("marshal: {0}")]
    Marshal(tpm2_protocol::TpmError),

    /// The provided HMAC does not match to the expected value.
    #[error("permission denied")]
    PermissionDenied,

    /// Unmarshaling a TPM protocol encoded object failed.
    #[error("unmarshal: {0}")]
    Unmarshal(tpm2_protocol::TpmError),
}

impl PartialEq for TpmCryptoError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::BufferTooSmall {
                    expected: expected_a,
                    actual: actual_a,
                },
                Self::BufferTooSmall {
                    expected: expected_b,
                    actual: actual_b,
                },
            ) => expected_a == expected_b && actual_a == actual_b,
            (Self::Crypto(a), Self::Crypto(b)) => crypto_error_stack_eq(a, b),
            (Self::InvalidEccCurve(a), Self::InvalidEccCurve(b)) => a == b,
            (Self::InvalidEccNid(a), Self::InvalidEccNid(b))
            | (Self::InvalidMessageDigestNid(a), Self::InvalidMessageDigestNid(b)) => a == b,
            (
                Self::InvalidPublicArea {
                    object_type: object_type_a,
                    field: field_a,
                },
                Self::InvalidPublicArea {
                    object_type: object_type_b,
                    field: field_b,
                },
            ) => object_type_a == object_type_b && field_a == field_b,
            (
                Self::InvalidEccPoint {
                    curve: curve_a,
                    x_len: x_len_a,
                    y_len: y_len_a,
                    expected_len: expected_len_a,
                },
                Self::InvalidEccPoint {
                    curve: curve_b,
                    x_len: x_len_b,
                    y_len: y_len_b,
                    expected_len: expected_len_b,
                },
            ) => {
                curve_a == curve_b
                    && x_len_a == x_len_b
                    && y_len_a == y_len_b
                    && expected_len_a == expected_len_b
            }
            (
                Self::InvalidPrivateKeySize {
                    len: len_a,
                    max: max_a,
                },
                Self::InvalidPrivateKeySize {
                    len: len_b,
                    max: max_b,
                },
            ) => len_a == len_b && max_a == max_b,
            (Self::InvalidEccKey, Self::InvalidEccKey)
            | (Self::InvalidHash, Self::InvalidHash)
            | (Self::InvalidObjectType, Self::InvalidObjectType)
            | (Self::InvalidRsaKey, Self::InvalidRsaKey)
            | (Self::KeyIsEmpty, Self::KeyIsEmpty)
            | (Self::MissingRsaPrivatePrime, Self::MissingRsaPrivatePrime)
            | (Self::PermissionDenied, Self::PermissionDenied) => true,
            (Self::InvalidEccGroupDegree(a), Self::InvalidEccGroupDegree(b)) => a == b,
            (Self::InvalidKeyBits(a), Self::InvalidKeyBits(b)) => a == b,
            (Self::InvalidKdfKeyBits(a), Self::InvalidKdfKeyBits(b)) => a == b,
            (Self::InvalidRsaModulus(a), Self::InvalidRsaModulus(b)) => a == b,
            (Self::InvalidRsaExponent(a), Self::InvalidRsaExponent(b)) => a == b,
            (Self::Marshal(a), Self::Marshal(b)) | (Self::Unmarshal(a), Self::Unmarshal(b)) => {
                a == b
            }
            _ => false,
        }
    }
}

impl Eq for TpmCryptoError {}

fn crypto_error_stack_eq(a: &ErrorStack, b: &ErrorStack) -> bool {
    a.errors().len() == b.errors().len()
        && a.errors().iter().zip(b.errors()).all(|(a, b)| {
            a.code() == b.code()
                && a.file() == b.file()
                && a.line() == b.line()
                && a.function() == b.function()
                && a.data() == b.data()
        })
}
