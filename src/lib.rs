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
    data::{
        Tpm2bEccParameter, Tpm2bName, TpmAlgId, TpmEccCurve, TpmRcBase, TpmsEccPoint, TpmtPublic,
    },
    TpmMarshal, TpmMarshalError, TpmUnmarshalError, TpmWriter,
};

pub const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

pub const KDF_LABEL_DUPLICATE: &str = "DUPLICATE";
pub const KDF_LABEL_INTEGRITY: &str = "INTEGRITY";
pub const KDF_LABEL_STORAGE: &str = "STORAGE";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("tpm: {0}")]
    Rc(TpmRcBase),
    #[error("marshal: {0}")]
    Marshal(TpmMarshalError),
    #[error("unmarshal: {0}")]
    Unmarshal(TpmUnmarshalError),
}

impl From<TpmRcBase> for CryptoError {
    fn from(err: TpmRcBase) -> Self {
        Self::Rc(err)
    }
}

impl From<TpmMarshalError> for CryptoError {
    fn from(err: TpmMarshalError) -> Self {
        Self::Marshal(err)
    }
}

impl From<TpmUnmarshalError> for CryptoError {
    fn from(err: TpmUnmarshalError) -> Self {
        Self::Unmarshal(err)
    }
}

impl From<&[u8]> for CryptoError {
    fn from(_err: &[u8]) -> Self {
        Self::Rc(TpmRcBase::Size)
    }
}

/// Maps a TPM algorithm ID to an OpenSSL message digest.
fn map_tpm_alg_to_md(alg: TpmAlgId) -> Result<MessageDigest, CryptoError> {
    match alg {
        TpmAlgId::Sha1 => Ok(MessageDigest::sha1()),
        TpmAlgId::Sha256 => Ok(MessageDigest::sha256()),
        TpmAlgId::Sm3_256 => Ok(MessageDigest::sm3()),
        TpmAlgId::Sha384 => Ok(MessageDigest::sha384()),
        TpmAlgId::Sha512 => Ok(MessageDigest::sha512()),
        _ => Err(CryptoError::Rc(TpmRcBase::Hash)),
    }
}

/// Maps a TPM ECC curve ID to an OpenSSL NID.
fn map_ecc_curve_to_nid(curve_id: TpmEccCurve) -> Result<Nid, CryptoError> {
    match curve_id {
        TpmEccCurve::NistP256 => Ok(Nid::X9_62_PRIME256V1),
        TpmEccCurve::NistP384 => Ok(Nid::SECP384R1),
        TpmEccCurve::NistP521 => Ok(Nid::SECP521R1),
        _ => Err(CryptoError::Rc(TpmRcBase::Curve)),
    }
}

/// Converts a TPM ECC parameter (big-endian bytes) to an OpenSSL `BigNum`.
fn tpm_ecc_param_to_bignum(param: &Tpm2bEccParameter) -> Result<BigNum, CryptoError> {
    BigNum::from_slice(param.as_ref()).map_err(|_| CryptoError::Rc(TpmRcBase::Failure))
}

/// Returns the size of the digest for a given hash algorithm.
///
/// # Errors
///
/// Returns [`TpmRcBase::Hash`](tpm2_protocol::data::TpmRcBase::Hash)
/// when the hash algorithm is not recognized.
pub fn hash_size(alg: TpmAlgId) -> Result<usize, CryptoError> {
    Ok(map_tpm_alg_to_md(alg)?.size())
}

/// Computes a cryptographic digest over a series of data chunks.
///
/// # Errors
///
/// Returns [`TpmRcBase::Hash`](tpm2_protocol::data::TpmRcBase::Hash)
/// when the hash algorithm is not recognized.
/// Returns [`TpmRcBase::Failure`](tpm2_protocol::data::TpmRcBase::Failure)
/// when the digest computation fails.
pub fn digest(alg: TpmAlgId, data_chunks: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    let md = map_tpm_alg_to_md(alg)?;
    let mut hasher = Hasher::new(md).map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;
    for chunk in data_chunks {
        hasher
            .update(chunk)
            .map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;
    }
    Ok(hasher
        .finish()
        .map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?
        .to_vec())
}

/// Computes an HMAC digest over a series of data chunks.
///
/// # Errors
///
/// Returns [`TpmRcBase::Hash`](tpm2_protocol::data::TpmRcBase::Hash)
/// when the hash algorithm is not recognized.
/// Returns [`TpmRcBase::Failure`](tpm2_protocol::data::TpmRcBase::Failure) when the
/// HMAC computation fails.
pub fn hmac(alg: TpmAlgId, key: &[u8], data_chunks: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    if key.is_empty() {
        return Err(CryptoError::Rc(TpmRcBase::Failure));
    }
    let md = map_tpm_alg_to_md(alg)?;
    let public_key = PKey::hmac(key).map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;
    let mut signer =
        Signer::new(md, &public_key).map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;
    for chunk in data_chunks {
        signer
            .update(chunk)
            .map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;
    }
    signer
        .sign_to_vec()
        .map_err(|_| CryptoError::Rc(TpmRcBase::Failure))
}

/// Verifies an HMAC signature over a series of data chunks.
///
/// # Errors
///
/// Returns [`TpmRcBase::BadAuth`](tpm2_protocol::data::TpmRcBase::BadAuth) when the HMAC does
/// not match the expected value.
/// Returns [`TpmRcBase::Hash`](tpm2_protocol::data::TpmRcBase::Hash)
/// when the hash algorithm is not recognized.
/// Returns [`TpmRcBase::Failure`](tpm2_protocol::data::TpmRcBase::Failure) when the
/// HMAC computation fails.
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
        Err(CryptoError::Rc(TpmRcBase::BadAuth))
    }
}

/// Implements the `KDFa` key derivation function from the TPM specification.
///
/// # Errors
///
/// Returns [`TpmRcBase::Hash`](tpm2_protocol::data::TpmRcBase::Hash)
/// when the hash algorithm is not recognized.
/// Returns [`TpmRcBase::Failure`](tpm2_protocol::data::TpmRcBase::Failure) when the
/// HMAC computation fails.
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
/// Returns [`TpmRcBase::Hash`](tpm2_protocol::data::TpmRcBase::Hash)
/// when the hash algorithm is not recognized.
/// Returns [`TpmRcBase::Failure`](tpm2_protocol::data::TpmRcBase::Failure) when the
/// digest computation fails.
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
/// Returns [`TpmMarshalError`](tpm2_protocol::TpmMarshalError) when
/// the provided public area fails to marshal.
/// Returns [`TpmRcBase::Size`](tpm2_protocol::data::TpmRcBase::Size) when the
/// resulting name is malformed (invalid size).
pub fn make_name(public: &TpmtPublic) -> Result<Tpm2bName, CryptoError> {
    let name_alg = public.name_alg;

    let mut name_buf = Vec::new();
    name_buf.extend_from_slice(&(name_alg as u16).to_be_bytes());

    let mut public_bytes = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
    let len = {
        let mut writer = TpmWriter::new(&mut public_bytes);
        public.marshal(&mut writer)?;
        writer.len()
    };
    public_bytes.truncate(len);

    let digest = digest(name_alg, &[&public_bytes])?;
    name_buf.extend_from_slice(&digest);

    Ok(Tpm2bName::try_from(name_buf.as_slice())?)
}

/// Performs ECDH and derives a seed using `KDFe` key derivation function from
/// TCG TPM 2.0 Architeture specification. The function is generic over the
/// elliptic curve.
///
/// # Errors
///
/// Returns [`TpmRcBase::Curve`](tpm2_protocol::data::TpmRcBase::Curve)
/// when the curve is not supported.
/// Returns [`TpmRcBase::EccPoint`](tpm2_protocol::data::TpmRcBase::EccPoint) when the
/// parent ECC point is not valid.
/// Returns [`TpmRcBase::Hash`](tpm2_protocol::data::TpmRcBase::Hash)
/// when the hash algorithm is not recognized.
/// Returns [`TpmRcBase::Failure`](tpm2_protocol::data::TpmRcBase::Failure) when
/// an internal cryptographic operation fails.
/// Returns [`TpmRcBase::Size`](tpm2_protocol::data::TpmRcBase::Size) when
/// an ECC parameter fails to unmarshal (invalid size).
pub fn ecdh(
    curve_id: TpmEccCurve,
    parent_point: &TpmsEccPoint,
    name_alg: TpmAlgId,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(Vec<u8>, TpmsEccPoint), CryptoError> {
    let nid = map_ecc_curve_to_nid(curve_id)?;
    let group = EcGroup::from_curve_name(nid).map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;
    let mut ctx = BigNumContext::new().map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;

    let parent_x = tpm_ecc_param_to_bignum(&parent_point.x)?;
    let parent_y = tpm_ecc_param_to_bignum(&parent_point.y)?;
    let parent_key = EcKey::from_public_key_affine_coordinates(&group, &parent_x, &parent_y)
        .map_err(|_| CryptoError::Rc(TpmRcBase::EccPoint))?;
    let parent_public_key =
        PKey::from_ec_key(parent_key).map_err(|_| CryptoError::Rc(TpmRcBase::EccPoint))?;

    let mut order = BigNum::new().map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;
    group
        .order(&mut order, &mut ctx)
        .map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;
    let order_uint = BigUint::from_bytes_be(&order.to_vec());
    let one = BigUint::from(1u8);

    let priv_uint = rng.gen_biguint_range(&one, &order_uint);
    let priv_bn = BigNum::from_slice(&priv_uint.to_bytes_be())
        .map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;

    let mut ephemeral_pub_point =
        EcPoint::new(&group).map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;
    ephemeral_pub_point
        .mul_generator(&group, &priv_bn, &ctx)
        .map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;
    let ephemeral_key = EcKey::from_private_components(&group, &priv_bn, &ephemeral_pub_point)
        .map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;

    let ephemeral_public_key =
        PKey::from_ec_key(ephemeral_key).map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;
    let mut deriver =
        Deriver::new(&ephemeral_public_key).map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;
    deriver
        .set_peer(&parent_public_key)
        .map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;
    let z = deriver
        .derive_to_vec()
        .map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;

    let ephemeral_pub_bytes = ephemeral_pub_point
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;

    if ephemeral_pub_bytes.is_empty() || ephemeral_pub_bytes[0] != UNCOMPRESSED_POINT_TAG {
        return Err(CryptoError::Rc(TpmRcBase::Failure));
    }

    let coord_len = (ephemeral_pub_bytes.len() - 1) / 2;
    let ephemeral_x = &ephemeral_pub_bytes[1..=coord_len];
    let ephemeral_y = &ephemeral_pub_bytes[1 + coord_len..];

    let seed_bits =
        u16::try_from(hash_size(name_alg)? * 8).map_err(|_| CryptoError::Rc(TpmRcBase::Failure))?;

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
        x: Tpm2bEccParameter::try_from(ephemeral_x)?,
        y: Tpm2bEccParameter::try_from(ephemeral_y)?,
    };

    Ok((seed, ephemeral_point_tpm))
}
