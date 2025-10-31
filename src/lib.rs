// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! TPM 2.0 cryptographic for TPM 2.0 interactions.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use num_bigint::{BigUint, RandBigInt};
use openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    hash::{Hasher, MessageDigest},
    memcmp,
    nid::Nid,
    pkey::PKey,
    sign::Signer,
};
use rand::{CryptoRng, RngCore};
use thiserror::Error;
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bEccParameter, Tpm2bName, TpmAlgId, TpmEccCurve, TpmsEccPoint, TpmtPublic},
    TpmBuild, TpmWriter,
};

pub const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

pub const KDF_LABEL_DUPLICATE: &str = "DUPLICATE";
pub const KDF_LABEL_INTEGRITY: &str = "INTEGRITY";
pub const KDF_LABEL_STORAGE: &str = "STORAGE";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("big number conversion failed")]
    BigNumConversion,
    #[error("HMAC mismatch")]
    HmacMismatch,
    #[error("invalid ECC point")]
    InvalidEccPoint,
    #[error("invalid hash algorithm")]
    InvalidHashAlgorithm,
    #[error("invalid data chunk")]
    InvalidChunk,
    #[error("invalid parent ECC point")]
    InvalidParent,
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
    #[error("unsupported ECC curve")]
    UnsupportedEccCurve,
}

/// Maps a TPM algorithm ID to an OpenSSL message digest.
fn map_tpm_alg_to_md(alg: TpmAlgId) -> Result<MessageDigest, CryptoError> {
    match alg {
        TpmAlgId::Sha1 => Ok(MessageDigest::sha1()),
        TpmAlgId::Sha256 | TpmAlgId::Sm3_256 => Ok(MessageDigest::sha256()),
        TpmAlgId::Sha384 => Ok(MessageDigest::sha384()),
        TpmAlgId::Sha512 => Ok(MessageDigest::sha512()),
        _ => Err(CryptoError::InvalidHashAlgorithm),
    }
}

/// Maps a TPM ECC curve ID to an OpenSSL NID.
fn map_ecc_curve_to_nid(curve_id: TpmEccCurve) -> Result<Nid, CryptoError> {
    match curve_id {
        TpmEccCurve::NistP256 => Ok(Nid::X9_62_PRIME256V1),
        TpmEccCurve::NistP384 => Ok(Nid::SECP384R1),
        TpmEccCurve::NistP521 => Ok(Nid::SECP521R1),
        _ => Err(CryptoError::UnsupportedEccCurve),
    }
}

/// Converts a TPM ECC parameter (big-endian bytes) to an OpenSSL `BigNum`.
fn tpm_ecc_param_to_bignum(param: &Tpm2bEccParameter) -> Result<BigNum, CryptoError> {
    BigNum::from_slice(param.as_ref()).map_err(|_| CryptoError::BigNumConversion)
}

/// Returns the size of the digest for a given hash algorithm.
///
/// # Errors
///
/// Returns [`InvalidHashAlgorithm`](crate::CryptoError::InvalidHashAlgorithm)
/// when the hash algorithm is not recognized.
pub fn hash_size(alg: TpmAlgId) -> Result<usize, CryptoError> {
    Ok(map_tpm_alg_to_md(alg)?.size())
}

/// Computes a cryptographic digest over a series of data chunks.
///
/// # Errors
///
/// Returns [`InvalidHashAlgorithm`](crate::CryptoError::InvalidHashAlgorithm)
/// when the hash algorithm is not recognized.
pub fn digest(alg: TpmAlgId, data_chunks: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    let md = map_tpm_alg_to_md(alg).map_err(|_| CryptoError::InvalidHashAlgorithm)?;
    let mut hasher = Hasher::new(md).map_err(|_| CryptoError::InvalidChunk)?;
    for chunk in data_chunks {
        hasher
            .update(chunk)
            .map_err(|_| CryptoError::InvalidChunk)?;
    }
    Ok(hasher
        .finish()
        .map_err(|_| CryptoError::InvalidChunk)?
        .to_vec())
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
    if key.is_empty() {
        return Err(CryptoError::MalformedHmacKey);
    }
    let md = map_tpm_alg_to_md(alg).map_err(|_| CryptoError::InvalidHashAlgorithm)?;
    let public_key = PKey::hmac(key).map_err(|_| CryptoError::MalformedHmacKey)?;
    let mut signer = Signer::new(md, &public_key).map_err(|_| CryptoError::MalformedHmacKey)?;
    for chunk in data_chunks {
        signer
            .update(chunk)
            .map_err(|_| CryptoError::MalformedHmacKey)?;
    }
    Ok(signer
        .sign_to_vec()
        .map_err(|_| CryptoError::MalformedHmacKey)?)
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
    let expected = hmac(alg, key, data_chunks)?;
    if memcmp::eq(&expected, signature) {
        Ok(())
    } else {
        Err(CryptoError::HmacMismatch)
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
/// Returns [`UnsupportedEccCurve`](crate::CryptoError::UnsupportedEccCurve)
/// when the curve is not supported.
pub fn ecdh(
    curve_id: TpmEccCurve,
    parent_point: &TpmsEccPoint,
    name_alg: TpmAlgId,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(Vec<u8>, TpmsEccPoint), CryptoError> {
    let nid = map_ecc_curve_to_nid(curve_id).map_err(|_| CryptoError::UnsupportedEccCurve)?;
    let group = EcGroup::from_curve_name(nid).map_err(|_| CryptoError::UnsupportedEccCurve)?;
    let mut ctx = BigNumContext::new().map_err(|_| CryptoError::MalformedEccParameter)?;

    let parent_x =
        tpm_ecc_param_to_bignum(&parent_point.x).map_err(|_| CryptoError::InvalidParent)?;
    let parent_y =
        tpm_ecc_param_to_bignum(&parent_point.y).map_err(|_| CryptoError::InvalidParent)?;
    let parent_key = EcKey::from_public_key_affine_coordinates(&group, &parent_x, &parent_y)
        .map_err(|_| CryptoError::InvalidParent)?;
    let parent_public_key =
        PKey::from_ec_key(parent_key).map_err(|_| CryptoError::InvalidParent)?;

    let mut order = BigNum::new().map_err(|_| CryptoError::MalformedEccParameter)?;
    group
        .order(&mut order, &mut ctx)
        .map_err(|_| CryptoError::MalformedEccParameter)?;
    let order_uint = BigUint::from_bytes_be(&order.to_vec());
    let one = BigUint::from(1u8);

    let priv_uint = rng.gen_biguint_range(&one, &order_uint);
    let priv_bn = BigNum::from_slice(&priv_uint.to_bytes_be())
        .map_err(|_| CryptoError::MalformedEccParameter)?;

    let mut ephemeral_pub_point =
        EcPoint::new(&group).map_err(|_| CryptoError::MalformedEccParameter)?;
    ephemeral_pub_point
        .mul_generator(&group, &priv_bn, &ctx)
        .map_err(|_| CryptoError::MalformedEccParameter)?;
    let ephemeral_key = EcKey::from_private_components(&group, &priv_bn, &ephemeral_pub_point)
        .map_err(|_| CryptoError::MalformedEccParameter)?;

    let ephemeral_public_key =
        PKey::from_ec_key(ephemeral_key).map_err(|_| CryptoError::MalformedEccParameter)?;
    let mut deriver =
        Deriver::new(&ephemeral_public_key).map_err(|_| CryptoError::MalformedEcdhSeed)?;
    deriver
        .set_peer(&parent_public_key)
        .map_err(|_| CryptoError::MalformedEcdhSeed)?;
    let z = deriver
        .derive_to_vec()
        .map_err(|_| CryptoError::MalformedEcdhSeed)?;

    let ephemeral_pub_bytes = ephemeral_pub_point
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(|_| CryptoError::MalformedEccParameter)?;

    if ephemeral_pub_bytes.is_empty() || ephemeral_pub_bytes[0] != UNCOMPRESSED_POINT_TAG {
        return Err(CryptoError::InvalidEccPoint);
    }

    let coord_len = (ephemeral_pub_bytes.len() - 1) / 2;
    let ephemeral_x = &ephemeral_pub_bytes[1..=coord_len];
    let ephemeral_y = &ephemeral_pub_bytes[1 + coord_len..];

    let seed_bits =
        u16::try_from(hash_size(name_alg)? * 8).map_err(|_| CryptoError::MalformedEcdhSeed)?;

    let context_u = ephemeral_x;
    let context_v = parent_point.x.as_ref();

    let seed = kdfe(
        name_alg,
        &z,
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
