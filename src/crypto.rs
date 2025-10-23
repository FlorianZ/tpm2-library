// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! This file contains cryptographic algorithms shared by tpm2sh and `MockTPM`.

use crate::convert::from_tpm_object_to_vec;
use hmac::{Hmac, Mac};
use num_traits::FromPrimitive;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use rand::{CryptoRng, RngCore};
use rsa::Oaep;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;
use tpm2_protocol::{
    data::{
        Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bName, TpmAlgId, TpmEccCurve, TpmsEccPoint,
        TpmtPublic, TpmuPublicId, TpmuPublicParms,
    },
    TpmError,
};

pub const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

pub const KDF_LABEL_DUPLICATE: &str = "DUPLICATE";
pub const KDF_LABEL_INTEGRITY: &str = "INTEGRITY";
pub const KDF_LABEL_STORAGE: &str = "STORAGE";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("DER encoding failed: {0}")]
    EncodingDerFailed(String),
    #[error("invalid ECC point")]
    InvalidEccPoint,
    #[error("unsupported or invalid hash algorithm")]
    InvalidHashAlgorithm,
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
    #[error("TPM: {0}")]
    Tpm(TpmError),
}

impl From<TpmError> for CryptoError {
    fn from(err: TpmError) -> Self {
        Self::Tpm(err)
    }
}

/// Returns the size of the digest for a given hash algorithm.
#[must_use]
pub fn crypto_hash_size(alg: TpmAlgId) -> Option<usize> {
    match alg {
        TpmAlgId::Sha1 => Some(20),
        TpmAlgId::Sha256 | TpmAlgId::Sm3_256 => Some(32),
        TpmAlgId::Sha384 => Some(48),
        TpmAlgId::Sha512 => Some(64),
        _ => None,
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
        _ => Err(CryptoError::InvalidHashAlgorithm),
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
        _ => Err(CryptoError::InvalidHashAlgorithm),
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
        _ => Err(CryptoError::InvalidHashAlgorithm),
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
    if crypto_hash_size(auth_hash).is_none() {
        return Err(CryptoError::InvalidHashAlgorithm);
    }

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
    if crypto_hash_size(hash_alg).is_none() {
        return Err(CryptoError::InvalidHashAlgorithm);
    }

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

/// Dispatches RSA OAEP encryption based on the `TpmAlgId`.
fn dispatch_rsa_oaep_encrypt(
    key: &rsa::RsaPublicKey,
    rng: &mut (impl CryptoRng + RngCore),
    name_alg: TpmAlgId,
    label: &str,
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let result = match name_alg {
        TpmAlgId::Sha1 => key.encrypt(rng, Oaep::new_with_label::<Sha1, _>(label), data),
        TpmAlgId::Sha256 => key.encrypt(rng, Oaep::new_with_label::<Sha256, _>(label), data),
        TpmAlgId::Sha384 => key.encrypt(rng, Oaep::new_with_label::<Sha384, _>(label), data),
        TpmAlgId::Sha512 => key.encrypt(rng, Oaep::new_with_label::<Sha512, _>(label), data),
        _ => return Err(CryptoError::InvalidScheme),
    };
    result.map_err(|e| CryptoError::RsaOaepEncryptFailed(e.to_string()))
}

/// Encrypts a seed using the parent's RSA public key for duplication.
///
/// See Table 27 in TCG TPM 2.0 Architectures specification for more information.
///
/// # Errors
///
/// Returns a `CryptoError` on failure.
pub fn protect_seed_with_rsa(
    parent_public: &TpmtPublic,
    seed: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Tpm2bEncryptedSecret, CryptoError> {
    let n = match &parent_public.unique {
        TpmuPublicId::Rsa(data) => Ok(data.as_ref()),
        _ => Err(CryptoError::InvalidKey),
    }?;
    let e_raw = match &parent_public.parameters {
        TpmuPublicParms::Rsa(params) => Ok(params.exponent),
        _ => Err(CryptoError::InvalidKey),
    }?;
    let e = if e_raw == 0 { 65537 } else { e_raw };
    let rsa_pub_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(n),
        rsa::BigUint::from_u32(e).ok_or(CryptoError::InvalidRsaExponent)?,
    )
    .map_err(|e| CryptoError::RsaOaepEncryptFailed(e.to_string()))?;

    let label = "DUPLICATE\0";

    let encrypted_seed =
        dispatch_rsa_oaep_encrypt(&rsa_pub_key, rng, parent_public.name_alg, label, seed)?;

    Tpm2bEncryptedSecret::try_from(encrypted_seed.as_slice())
        .map_err(|_| CryptoError::InvalidRsaExponent)
}

/// Derives a `seed` and an ephemeral public key using ECDH with the parent's ECC public key.
///
/// # Errors
///
/// Returns a `CryptoError` on failure.
pub fn derive_seed_with_ecc(
    parent_public: &TpmtPublic,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(Vec<u8>, TpmsEccPoint), CryptoError> {
    let (parent_point, curve_id) = match (&parent_public.unique, &parent_public.parameters) {
        (TpmuPublicId::Ecc(point), TpmuPublicParms::Ecc(params)) => Ok((point, params.curve_id)),
        _ => Err(CryptoError::InvalidKey),
    }?;

    match curve_id {
        TpmEccCurve::NistP256 => crypto_ecdh_p256(parent_point, parent_public.name_alg, rng),
        TpmEccCurve::NistP384 => crypto_ecdh_p384(parent_point, parent_public.name_alg, rng),
        TpmEccCurve::NistP521 => crypto_ecdh_p521(parent_point, parent_public.name_alg, rng),
        _ => Err(CryptoError::UnsupportedEccCurve),
    }
}

macro_rules! ecdh {
    (
        $vis:vis $fn_name:ident,
        $pk_ty:ty, $sk_ty:ty, $affine_ty:ty, $dh_fn:path, $encoded_point_ty:ty
    ) => {
        #[allow(clippy::similar_names, clippy::missing_errors_doc)]
        $vis fn $fn_name(
            parent_point: &TpmsEccPoint,
            name_alg: TpmAlgId,
            rng: &mut (impl RngCore + CryptoRng),
        ) -> Result<(Vec<u8>, TpmsEccPoint), CryptoError> {
            let encoded_point = <$encoded_point_ty>::from_affine_coordinates(
                parent_point.x.as_ref().into(),
                parent_point.y.as_ref().into(),
                false,
            );
            let affine_point_opt: Option<$affine_ty> =
                <$affine_ty>::from_encoded_point(&encoded_point).into();
            let affine_point = affine_point_opt.ok_or(CryptoError::InvalidEccPoint)?;

            if affine_point.is_identity().into() {
                return Err(CryptoError::InvalidEccPoint);
            }

            let parent_pk =
                <$pk_ty>::from_affine(affine_point).map_err(|_| CryptoError::InvalidEccPoint)?;

            let ephemeral_sk = <$sk_ty>::random(rng);
            let ephemeral_pk_bytes_encoded = ephemeral_sk.public_key().to_encoded_point(false);
            let ephemeral_pk_bytes = ephemeral_pk_bytes_encoded.as_bytes();
            if ephemeral_pk_bytes.is_empty() || ephemeral_pk_bytes[0] != UNCOMPRESSED_POINT_TAG {
                return Err(CryptoError::InvalidEccPoint);
            }
            let coord_len = (ephemeral_pk_bytes.len() - 1) / 2;
            let x = &ephemeral_pk_bytes[1..=coord_len];
            let y = &ephemeral_pk_bytes[1 + coord_len..];

            let context_u = x;
            let context_v = parent_point.x.as_ref();

            let shared_secret = $dh_fn(ephemeral_sk.to_nonzero_scalar(), parent_pk.as_affine());
            let z = shared_secret.raw_secret_bytes();
            let seed_bits =
                u16::try_from(crypto_hash_size(name_alg).ok_or(CryptoError::InvalidHashAlgorithm)? * 8)
                    .map_err(|_| CryptoError::InvalidKey)?;
            let seed =
                crypto_kdfe(name_alg, &z, KDF_LABEL_DUPLICATE, context_u, context_v, seed_bits)?;

            let ephemeral_point = TpmsEccPoint {
                x: Tpm2bEccParameter::try_from(x)?,
                y: Tpm2bEccParameter::try_from(y)?
            };

            Ok((seed, ephemeral_point))
        }
    };
}

ecdh!(
    pub crypto_ecdh_p256,
    p256::PublicKey,
    p256::SecretKey,
    p256::AffinePoint,
    p256::ecdh::diffie_hellman,
    p256::EncodedPoint
);

ecdh!(
    pub crypto_ecdh_p384,
    p384::PublicKey,
    p384::SecretKey,
    p384::AffinePoint,
    p384::ecdh::diffie_hellman,
    p384::EncodedPoint
);

ecdh!(
    pub crypto_ecdh_p521,
    p521::PublicKey,
    p521::SecretKey,
    p521::AffinePoint,
    p521::ecdh::diffie_hellman,
    p521::EncodedPoint
);

/// Calculates the TPM name of a public object.
///
/// # Errors
///
/// Returns a `CryptoError` on failure.
pub fn crypto_make_name(public: &TpmtPublic) -> Result<Tpm2bName, CryptoError> {
    let mut name_buf = Vec::new();
    let name_alg = public.name_alg;
    name_buf.extend_from_slice(&(name_alg as u16).to_be_bytes());
    let public_area_bytes =
        from_tpm_object_to_vec(public).map_err(|_| CryptoError::InvalidRsaExponent)?;
    let digest = crypto_digest(name_alg, &[&public_area_bytes])?;
    name_buf.extend_from_slice(&digest);
    Tpm2bName::try_from(name_buf.as_slice()).map_err(Into::into)
}
