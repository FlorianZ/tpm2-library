// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use core::fmt;
use openssl::{error::ErrorStack, nid::Nid};
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
///
/// `Display` renders only the variant name as lowercase space-separated words
/// (e.g. `BufferTooSmall` becomes `buffer too small`).
#[derive(Debug, strum::AsRefStr)]
#[strum(serialize_all = "title_case")]
#[non_exhaustive]
pub enum TpmCryptoError {
    /// The output buffer is too small for the requested operation.
    BufferTooSmall { expected: usize, actual: usize },

    /// A libcrypto operation failed.
    Crypto(ErrorStack),

    /// ECC curve is not supported in the context of use.
    InvalidEccCurve(TpmEccCurve),

    /// OpenSSL ECC NID is not supported in the context of use.
    InvalidEccNid(Nid),

    /// Invalid ECC point shape.
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
    InvalidEccKey,

    /// Invalid ECC group degree.
    InvalidEccGroupDegree(u32),

    /// Hash algorithm is not supported in the context of use.
    InvalidHash,

    /// OpenSSL message digest NID is not supported in the context of use.
    InvalidMessageDigestNid(Nid),

    /// Invalid RSA key bits.
    InvalidKeyBits(u16),

    /// Invalid KDF key bits.
    InvalidKdfKeyBits(usize),

    /// Invalid object type.
    InvalidObjectType,

    /// Invalid public area.
    InvalidPublicArea {
        /// Object type reported by the public area.
        object_type: TpmAlgId,

        /// Field that failed validation.
        field: TpmPublicAreaField,
    },

    /// Invalid RSA key structure.
    InvalidRsaKey,

    /// Invalid RSA public modulus.
    InvalidRsaModulus(Vec<u8>),

    /// Invalid RSA public exponent.
    InvalidRsaExponent(TpmUint32),

    /// Invalid private key size.
    InvalidPrivateKeySize {
        /// Actual private key length.
        len: usize,

        /// Maximum length accepted by the TPM buffer type.
        max: usize,
    },

    /// RSA private prime is missing.
    MissingRsaPrivatePrime,

    /// A zero-length key was provided.
    KeyIsEmpty,

    /// Marshaling a TPM protocol encoded object failed.
    Marshal(tpm2_protocol::TpmError),

    /// The computed message authentication code does not match the expected value.
    MacMismatch,

    /// Unmarshaling a TPM protocol encoded object failed.
    Unmarshal(tpm2_protocol::TpmError),
}

impl fmt::Display for TpmCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_ref().to_lowercase())
    }
}

impl std::error::Error for TpmCryptoError {}

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
            | (Self::MacMismatch, Self::MacMismatch) => true,
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
