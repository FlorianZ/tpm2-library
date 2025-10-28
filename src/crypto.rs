// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! This file contains cryptographic algorithms shared by tpm2sh and `MockTPM`.

use crate::write_object;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;
use tpm2_protocol::{
    data::{Tpm2bName, TpmAlgId, TpmtPublic},
    TpmError,
};

pub const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

pub const KDF_LABEL_DUPLICATE: &str = "DUPLICATE";
pub const KDF_LABEL_INTEGRITY: &str = "INTEGRITY";
pub const KDF_LABEL_STORAGE: &str = "STORAGE";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid ECC point")]
    InvalidEccPoint,
    #[error("invalid HMAC")]
    InvalidHmac,
    #[error("invalid cryptographic key")]
    InvalidKey,
    #[error("unsupported or invalid cryptographic scheme")]
    InvalidScheme,
    #[error("invalid RSA exponent")]
    InvalidRsaExponent,
    #[error("RSA-OAEP failed: {0}")]
    RsaOaepEncryptFailed(String),
    #[error("unsupported elliptic curve")]
    UnsupportedEccCurve,
    #[error("unsupported hash algorithm")]
    UnsupportedHashAlgorithm,
    #[error("TPM: {0}")]
    Tpm(TpmError),
}

impl From<TpmError> for CryptoError {
    fn from(err: TpmError) -> Self {
        Self::Tpm(err)
    }
}

/// Returns the size of the digest for a given hash algorithm.
///
/// # Errors
///
/// Returns a [`InvalidHashAlgorihm`](crate::crypto::CryptoError) when the hash
/// algorithm is not supported.
pub fn crypto_hash_size(alg: TpmAlgId) -> Result<usize, CryptoError> {
    match alg {
        TpmAlgId::Sha1 => Ok(20),
        TpmAlgId::Sha256 | TpmAlgId::Sm3_256 => Ok(32),
        TpmAlgId::Sha384 => Ok(48),
        TpmAlgId::Sha512 => Ok(64),
        _ => Err(CryptoError::UnsupportedHashAlgorithm),
    }
}

/// Computes a cryptographic digest over a series of data chunks.
///
/// # Errors
///
/// Returns a `CryptoError` if the algorithm is unsupported.
pub fn crypto_digest(alg: TpmAlgId, data_chunks: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    macro_rules! digest {
        ($hasher:ty) => {{
            let mut hasher = <$hasher>::new();
            for chunk in data_chunks {
                hasher.update(chunk);
            }
            Ok(hasher.finalize().to_vec())
        }};
    }

    match alg {
        TpmAlgId::Sha1 => digest!(Sha1),
        TpmAlgId::Sha256 => digest!(Sha256),
        TpmAlgId::Sha384 => digest!(Sha384),
        TpmAlgId::Sha512 => digest!(Sha512),
        _ => Err(CryptoError::UnsupportedHashAlgorithm),
    }
}

/// Computes an HMAC digest over a series of data chunks.
///
/// # Errors
///
/// Returns a `CryptoError` if the key is invalid or the algorithm is unsupported.
pub fn crypto_hmac(
    alg: TpmAlgId,
    key: &[u8],
    data_chunks: &[&[u8]],
) -> Result<Vec<u8>, CryptoError> {
    macro_rules! hmac {
        ($digest:ty) => {{
            let mut mac =
                <Hmac<$digest> as Mac>::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
            for chunk in data_chunks {
                mac.update(chunk);
            }
            Ok(mac.finalize().into_bytes().to_vec())
        }};
    }

    match alg {
        TpmAlgId::Sha256 => hmac!(Sha256),
        TpmAlgId::Sha384 => hmac!(Sha384),
        TpmAlgId::Sha512 => hmac!(Sha512),
        _ => Err(CryptoError::UnsupportedHashAlgorithm),
    }
}

/// Verifies an HMAC signature over a series of data chunks.
///
/// # Errors
///
/// Returns a `CryptoError` if the key is invalid, the algorithm is unsupported,
/// or the signature does not match.
pub fn crypto_hmac_verify(
    alg: TpmAlgId,
    key: &[u8],
    data_chunks: &[&[u8]],
    signature: &[u8],
) -> Result<(), CryptoError> {
    macro_rules! verify_hmac {
        ($digest:ty) => {{
            let mut mac =
                <Hmac<$digest> as Mac>::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
            for chunk in data_chunks {
                mac.update(chunk);
            }
            mac.verify_slice(signature)
                .map_err(|_| CryptoError::InvalidHmac)
        }};
    }

    match alg {
        TpmAlgId::Sha256 => verify_hmac!(Sha256),
        TpmAlgId::Sha384 => verify_hmac!(Sha384),
        TpmAlgId::Sha512 => verify_hmac!(Sha512),
        _ => Err(CryptoError::UnsupportedHashAlgorithm),
    }
}

/// Implements the `KDFa` key derivation function from the TPM specification.
///
/// # Errors
///
/// Returns a `CryptoError` on failure.
pub fn crypto_kdfa(
    auth_hash: TpmAlgId,
    hmac_key: &[u8],
    label: &str,
    context_a: &[u8],
    context_b: &[u8],
    key_bits: u16,
) -> Result<Vec<u8>, CryptoError> {
    let mut key_stream = Vec::new();
    let key_bytes = (key_bits as usize).div_ceil(8);
    let label_bytes = {
        let mut bytes = label.as_bytes().to_vec();
        bytes.push(0);
        bytes
    };

    let mut counter: u32 = 1;
    while key_stream.len() < key_bytes {
        let counter_bytes = counter.to_be_bytes();
        let key_bits_bytes = u32::from(key_bits).to_be_bytes();
        let hmac_payload = [
            counter_bytes.as_slice(),
            label_bytes.as_slice(),
            context_a,
            context_b,
            key_bits_bytes.as_slice(),
        ];

        let result = crypto_hmac(auth_hash, hmac_key, &hmac_payload)?;
        let remaining = key_bytes - key_stream.len();
        let to_take = remaining.min(result.len());
        key_stream.extend_from_slice(&result[..to_take]);

        counter += 1;
    }

    Ok(key_stream)
}

/// Implements the `KDFe` key derivation function from SP 800-56A for ECDH.
///
/// # Errors
///
/// Returns a `CryptoError` on failure.
pub fn crypto_kdfe(
    hash_alg: TpmAlgId,
    z: &[u8],
    label: &str,
    context_u: &[u8],
    context_v: &[u8],
    key_bits: u16,
) -> Result<Vec<u8>, CryptoError> {
    let mut key_stream = Vec::new();
    let key_bytes = (key_bits as usize).div_ceil(8);
    let mut label_bytes = label.as_bytes().to_vec();
    if label_bytes.last() != Some(&0) {
        label_bytes.push(0);
    }

    let other_info = [label_bytes.as_slice(), context_u, context_v].concat();

    let mut counter: u32 = 1;
    while key_stream.len() < key_bytes {
        let counter_bytes = counter.to_be_bytes();
        let digest_payload = [&counter_bytes, z, &other_info];

        let result = crypto_digest(hash_alg, &digest_payload)?;
        let remaining = key_bytes - key_stream.len();
        let to_take = remaining.min(result.len());
        key_stream.extend_from_slice(&result[..to_take]);

        counter += 1;
    }

    Ok(key_stream)
}

/// Calculates the TPM name of a public object.
///
/// # Errors
///
/// Returns a `CryptoError` on failure.
pub fn crypto_make_name(public: &TpmtPublic) -> Result<Tpm2bName, CryptoError> {
    let mut name_buf = Vec::new();
    let name_alg = public.name_alg;
    name_buf.extend_from_slice(&(name_alg as u16).to_be_bytes());
    let public_area_bytes = write_object(public)?;
    let digest = crypto_digest(name_alg, &[&public_area_bytes])?;
    name_buf.extend_from_slice(&digest);
    Tpm2bName::try_from(name_buf.as_slice()).map_err(Into::into)
}
