// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

//! TPM 2.0 cryptographic for TPM 2.0 interactions.

use elliptic_curve::{
    ecdh::{diffie_hellman, SharedSecret},
    group::Curve as GroupCurve,
    point::PointCompression,
    rand_core::{CryptoRng, RngCore},
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffinePoint, Curve, CurveArithmetic, Group, PrimeCurve, ProjectivePoint, PublicKey, SecretKey,
};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bEccParameter, Tpm2bName, TpmAlgId, TpmsEccPoint, TpmtPublic},
    TpmBuild, TpmWriter,
};

pub const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

pub const KDF_LABEL_DUPLICATE: &str = "DUPLICATE";
pub const KDF_LABEL_INTEGRITY: &str = "INTEGRITY";
pub const KDF_LABEL_STORAGE: &str = "STORAGE";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid ECC point")]
    InvalidEccPoint,
    #[error("invalid hash algorithm")]
    InvalidHashAlgorithm,
    #[error("HMAC mismatch")]
    HmacMismatch,
    #[error("invalid public area")]
    InvalidPublicArea,
    #[error("malformed ECC parameter")]
    MalformedEccParameter,
    #[error("malformed ECDH seed")]
    MalformedEcdhSeed,
    #[error("malformed HMAC key")]
    MalformedHmacKey,
    #[error("malformed name")]
    MalformedName,
}

/// Returns the size of the digest for a given hash algorithm.
///
/// # Errors
///
/// Returns [`InvalidHashAlgorithm`](crate::CryptoError::InvalidHashAlgorithm)
/// when the hash algorithm is not recognized.
pub fn hash_size(alg: TpmAlgId) -> Result<usize, CryptoError> {
    match alg {
        TpmAlgId::Sha1 => Ok(20),
        TpmAlgId::Sha256 | TpmAlgId::Sm3_256 => Ok(32),
        TpmAlgId::Sha384 => Ok(48),
        TpmAlgId::Sha512 => Ok(64),
        _ => Err(CryptoError::InvalidHashAlgorithm),
    }
}

/// Computes a cryptographic digest over a series of data chunks.
///
/// # Errors
///
/// Returns [`InvalidHashAlgorithm`](crate::CryptoError::InvalidHashAlgorithm)
/// when the hash algorithm is not recognized.
pub fn digest(alg: TpmAlgId, data_chunks: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    macro_rules! digest_internal {
        ($hasher:ty) => {{
            let mut hasher = <$hasher>::new();
            for chunk in data_chunks {
                hasher.update(chunk);
            }
            Ok(hasher.finalize().to_vec())
        }};
    }

    match alg {
        TpmAlgId::Sha1 => digest_internal!(Sha1),
        TpmAlgId::Sha256 => digest_internal!(Sha256),
        TpmAlgId::Sha384 => digest_internal!(Sha384),
        TpmAlgId::Sha512 => digest_internal!(Sha512),
        _ => Err(CryptoError::InvalidHashAlgorithm),
    }
}

/// Computes an HMAC digest over a series of data chunks.
///
/// # Errors
///
/// Returns [`InvalidHashAlgorithm`](crate::CryptoError::InvalidHashAlgorithm)
/// when the hash algorithm is not recognized.
/// Returns [`MalformedHmacKey`](crate::CryptoError::MalformedHmacKey) when the
/// resulting HMAC key is malformed.
pub fn hmac(alg: TpmAlgId, key: &[u8], data_chunks: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    macro_rules! hmac_internal {
        ($digest:ty) => {{
            let mut mac = <Hmac<$digest> as Mac>::new_from_slice(key)
                .map_err(|_| CryptoError::MalformedHmacKey)?;
            for chunk in data_chunks {
                mac.update(chunk);
            }
            Ok(mac.finalize().into_bytes().to_vec())
        }};
    }

    match alg {
        TpmAlgId::Sha256 => hmac_internal!(Sha256),
        TpmAlgId::Sha384 => hmac_internal!(Sha384),
        TpmAlgId::Sha512 => hmac_internal!(Sha512),
        _ => Err(CryptoError::InvalidHashAlgorithm),
    }
}

/// Verifies an HMAC signature over a series of data chunks.
///
/// # Errors
///
/// Returns [`HmacMismatch`](crate::CryptoError::HmacMismatch) when the HMAC does
/// not match the expected value.
/// Returns [`InvalidHashAlgorithm`](crate::CryptoError::InvalidHashAlgorithm)
/// when the hash algorithm is not recognized.
/// Returns [`MalformedHmacKey`](crate::CryptoError::MalformedHmacKey) when the
/// resulting HMAC key is malformed.
pub fn hmac_verify(
    alg: TpmAlgId,
    key: &[u8],
    data_chunks: &[&[u8]],
    signature: &[u8],
) -> Result<(), CryptoError> {
    macro_rules! verify_hmac_internal {
        ($digest:ty) => {{
            let mut mac = <Hmac<$digest> as Mac>::new_from_slice(key)
                .map_err(|_| CryptoError::MalformedHmacKey)?;
            for chunk in data_chunks {
                mac.update(chunk);
            }
            mac.verify_slice(signature)
                .map_err(|_| CryptoError::HmacMismatch)
        }};
    }

    match alg {
        TpmAlgId::Sha256 => verify_hmac_internal!(Sha256),
        TpmAlgId::Sha384 => verify_hmac_internal!(Sha384),
        TpmAlgId::Sha512 => verify_hmac_internal!(Sha512),
        _ => Err(CryptoError::InvalidHashAlgorithm),
    }
}

/// Implements the `KDFa` key derivation function from the TPM specification.
///
/// # Errors
///
/// Returns [`InvalidHashAlgorithm`](crate::CryptoError::InvalidHashAlgorithm)
/// when the hash algorithm is not recognized.
/// Returns [`MalformedHmacKey`](crate::CryptoError::MalformedHmacKey) when the
/// resulting HMAC key is malformed.
pub fn kdfa(
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

        let result = hmac(auth_hash, hmac_key, &hmac_payload)?;
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
/// Returns [`InvalidHashAlgorithm`](crate::CryptoError::InvalidHashAlgorithm)
/// when the hash algorithm is not recognized.
/// Returns [`MalformedHmacKey`](crate::CryptoError::MalformedHmacKey) when the
/// resulting HMAC key is malformed.
pub fn kdfe(
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

        let result = digest(hash_alg, &digest_payload)?;
        let remaining = key_bytes - key_stream.len();
        let to_take = remaining.min(result.len());
        key_stream.extend_from_slice(&result[..to_take]);

        counter += 1;
    }

    Ok(key_stream)
}

/// Calculates the cryptographics name of a transient or persistent TPM object.
///
/// # Errors
///
/// Returns [`InvalidPublicArea`](crate::CryptoError::InvalidPublicArea) when
/// the provided public area is has invalid parameters.
/// Returns [`MalformedName`](crate::CryptoError::MalformedName) when the
/// resulting object is malformed.
pub fn make_name(public: &TpmtPublic) -> Result<Tpm2bName, CryptoError> {
    let name_alg = public.name_alg;

    let mut name_buf = Vec::new();
    name_buf.extend_from_slice(&(name_alg as u16).to_be_bytes());

    let mut public_bytes = vec![0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut public_bytes);
        public
            .build(&mut writer)
            .map_err(|_| CryptoError::InvalidPublicArea)?;
        writer.len()
    };
    public_bytes.truncate(len);

    let digest = digest(name_alg, &[&public_bytes])?;
    name_buf.extend_from_slice(&digest);

    Tpm2bName::try_from(name_buf.as_slice()).map_err(|_| CryptoError::MalformedName)
}

/// Performs ECDH and derives a seed using `KDFe` key derivation function from
/// TCG TPM 2.0 Architeture specification. The function is generic over the
/// elliptic curve.
///
/// # Errors
///
/// Returns [`InvalidEccPoint`](crate::CryptoError::InvalidEccPoint) when the
/// parent ECC point is not valid.
/// Returns [`InvalidHashAlgorithm`](crate::CryptoError::InvalidHashAlgorithm)
/// when the hash algorithm is not recognized.
/// Returns [`MalformedEcdhSeed`](crate::CryptoError::MalformedEcdhSeed) when
/// the resulting ECDH seed is malformed.
/// Returns [`MalformedEccParameter`](crate::CryptoError::MalformedEccParameter)
/// when the resulting ECC parameters are malformed.
pub fn ecdh<C>(
    parent_point: &TpmsEccPoint,
    name_alg: TpmAlgId,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(Vec<u8>, TpmsEccPoint), CryptoError>
where
    C: Curve + PrimeCurve + CurveArithmetic + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    PublicKey<C>:,
    SecretKey<C>:,
    SharedSecret<C>:,
    <C as Curve>::FieldBytesSize: ModulusSize,
    ProjectivePoint<C>: From<AffinePoint<C>> + GroupCurve<AffineRepr = AffinePoint<C>>,
{
    let encoded_parent_point = elliptic_curve::sec1::EncodedPoint::<C>::from_affine_coordinates(
        parent_point.x.as_ref().into(),
        parent_point.y.as_ref().into(),
        false,
    );
    let parent_affine_point = AffinePoint::<C>::from_encoded_point(&encoded_parent_point)
        .into_option()
        .ok_or(CryptoError::InvalidEccPoint)?;

    if ProjectivePoint::<C>::from(parent_affine_point)
        .is_identity()
        .into()
    {
        return Err(CryptoError::InvalidEccPoint);
    }
    let parent_public_key = PublicKey::<C>::from_affine(parent_affine_point)
        .map_err(|_| CryptoError::InvalidEccPoint)?;

    let ephemeral_secret_key = SecretKey::<C>::random(rng);
    let ephemeral_public_key = ephemeral_secret_key.public_key();
    let ephemeral_public_key_affine = ephemeral_public_key.as_affine();
    let ephemeral_public_key_encoded = ephemeral_public_key_affine.to_encoded_point(false);
    let ephemeral_public_key_bytes = ephemeral_public_key_encoded.as_bytes();

    if ephemeral_public_key_bytes.is_empty()
        || ephemeral_public_key_bytes[0] != UNCOMPRESSED_POINT_TAG
    {
        return Err(CryptoError::InvalidEccPoint);
    }

    let coord_len = (ephemeral_public_key_bytes.len() - 1) / 2;
    let ephemeral_x = &ephemeral_public_key_bytes[1..=coord_len];
    let ephemeral_y = &ephemeral_public_key_bytes[1 + coord_len..];

    let parent_affine_ref = parent_public_key.as_affine();

    let shared_secret = diffie_hellman(ephemeral_secret_key.to_nonzero_scalar(), parent_affine_ref);

    let z_array = shared_secret.raw_secret_bytes();
    let z = z_array.as_ref();

    let seed_bits =
        u16::try_from(hash_size(name_alg)? * 8).map_err(|_| CryptoError::MalformedEcdhSeed)?;

    let context_u = ephemeral_x;
    let context_v = parent_point.x.as_ref();

    let seed = kdfe(
        name_alg,
        z,
        KDF_LABEL_DUPLICATE,
        context_u,
        context_v,
        seed_bits,
    )?;

    let ephemeral_point_tpm = TpmsEccPoint {
        x: Tpm2bEccParameter::try_from(ephemeral_x)
            .map_err(|_| CryptoError::MalformedEccParameter)?,
        y: Tpm2bEccParameter::try_from(ephemeral_y)
            .map_err(|_| CryptoError::MalformedEccParameter)?,
    };

    Ok((seed, ephemeral_point_tpm))
}
