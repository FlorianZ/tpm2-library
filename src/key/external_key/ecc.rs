// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

#![allow(clippy::no_effect_underscore_binding)]

use crate::{
    crypto::UNCOMPRESSED_POINT_TAG,
    key::{external_key::ExternalKey, KeyError},
};

use std::borrow::Cow;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use rasn::{
    types::{BitString, ObjectIdentifier, OctetString},
    AsnType, Decode, Decoder, Encode, Encoder,
};
use rsa::traits::PrivateKeyParts;
use tpm2_protocol::data::{
    Tpm2bDigest, Tpm2bEccParameter, TpmAlgId, TpmEccCurve, TpmaObject, TpmsEccParms, TpmsEccPoint,
    TpmtEccScheme, TpmtKdfScheme, TpmtPublic, TpmtSymDefObject, TpmuAsymScheme, TpmuPublicId,
    TpmuPublicParms,
};

pub const SECP_256_R_1: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 10045, 3, 1, 7]));
pub const SECP_384_R_1: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 132, 0, 34]));
pub const SECP_521_R_1: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 3, 132, 0, 35]));

#[allow(clippy::no_effect_underscore_binding)]
#[derive(AsnType, Decode, Encode, Debug)]
pub struct Sec1EcPrivateKey {
    pub version: u8,
    pub private_key: OctetString,
    #[rasn(tag(explicit(context, 0)))]
    pub parameters: Option<ObjectIdentifier>,
    #[rasn(tag(explicit(context, 1)))]
    pub public_key: Option<BitString>,
}

/// Parses a SEC1 DER-encoded ECC private key.
///
/// An optional `inherited_oid` can be provided, which is necessary when parsing
/// a key from a PKCS#8 wrapper where the curve parameters are in the outer
/// structure.
///
/// # Errors
///
/// Returns a `KeyError` if the DER data is malformed, the OID is unsupported,
/// or the key is invalid for the specified curve.
pub fn parse_ecc_from_der(
    der_bytes: &[u8],
    inherited_oid: Option<&ObjectIdentifier>,
) -> Result<ExternalKey, KeyError> {
    let sec1_key = rasn::der::decode::<Sec1EcPrivateKey>(der_bytes)?;

    let oid =
        sec1_key
            .parameters
            .as_ref()
            .or(inherited_oid)
            .ok_or(KeyError::ValueConversionFailed(
                "missing ECC parameters".to_string(),
            ))?;

    let key_bytes = sec1_key.private_key.as_ref();

    if oid == &SECP_256_R_1 {
        Ok(ExternalKey::EccP256(Box::new(
            p256::SecretKey::from_slice(key_bytes)
                .map_err(|e| KeyError::ValueConversionFailed(e.to_string()))?,
        )))
    } else if oid == &SECP_384_R_1 {
        Ok(ExternalKey::EccP384(Box::new(
            p384::SecretKey::from_slice(key_bytes)
                .map_err(|e| KeyError::ValueConversionFailed(e.to_string()))?,
        )))
    } else if oid == &SECP_521_R_1 {
        Ok(ExternalKey::EccP521(Box::new(
            p521::SecretKey::from_slice(key_bytes)
                .map_err(|e| KeyError::ValueConversionFailed(e.to_string()))?,
        )))
    } else {
        Err(KeyError::UnsupportedOid(oid.to_string()))
    }
}

/// Converts ECC public key bytes to a `TpmtPublic` structure.
///
/// # Errors
///
/// Returns a `KeyError` if the public key bytes do not represent a valid
/// uncompressed ECC point or if conversion to TPM types fails.
pub fn ecc_to_public(
    pub_bytes: &[u8],
    curve_id: TpmEccCurve,
    hash_alg: TpmAlgId,
    symmetric: TpmtSymDefObject,
) -> Result<TpmtPublic, KeyError> {
    if pub_bytes.is_empty() || pub_bytes[0] != UNCOMPRESSED_POINT_TAG {
        return Err(KeyError::InvalidEccPoint(hex::encode(pub_bytes)));
    }

    let coord_len = (pub_bytes.len() - 1) / 2;
    let x = &pub_bytes[1..=coord_len];
    let y = &pub_bytes[1 + coord_len..];

    Ok(TpmtPublic {
        object_type: TpmAlgId::Ecc,
        name_alg: hash_alg,
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parameters: TpmuPublicParms::Ecc(TpmsEccParms {
            symmetric,
            scheme: TpmtEccScheme {
                scheme: TpmAlgId::Ecdh,
                details: TpmuAsymScheme::Any(tpm2_protocol::data::TpmsSchemeHash { hash_alg }),
            },
            curve_id,
            kdf: TpmtKdfScheme::default(),
        }),
        unique: TpmuPublicId::Ecc(TpmsEccPoint {
            x: Tpm2bEccParameter::try_from(x)?,
            y: Tpm2bEccParameter::try_from(y)?,
        }),
    })
}

impl ExternalKey {
    /// Converts key to `TpmtPublic`.
    ///
    /// # Errors
    ///
    /// Returns a `KeyError` on failure.
    pub fn to_public(&self, hash_alg: TpmAlgId) -> Result<TpmtPublic, KeyError> {
        let symmetric = TpmtSymDefObject::default();

        match self {
            ExternalKey::Rsa2048(key) => super::rsa::rsa_to_public(key, 2048, hash_alg, symmetric),
            ExternalKey::Rsa3072(key) => super::rsa::rsa_to_public(key, 3072, hash_alg, symmetric),
            ExternalKey::Rsa4096(key) => super::rsa::rsa_to_public(key, 4096, hash_alg, symmetric),
            ExternalKey::EccP256(secret_key) => {
                let encoded_point = secret_key.public_key().to_encoded_point(false);
                ecc_to_public(
                    encoded_point.as_bytes(),
                    TpmEccCurve::NistP256,
                    hash_alg,
                    symmetric,
                )
            }
            ExternalKey::EccP384(secret_key) => {
                let encoded_point = secret_key.public_key().to_encoded_point(false);
                ecc_to_public(
                    encoded_point.as_bytes(),
                    TpmEccCurve::NistP384,
                    hash_alg,
                    symmetric,
                )
            }
            ExternalKey::EccP521(secret_key) => {
                let encoded_point = secret_key.public_key().to_encoded_point(false);
                ecc_to_public(
                    encoded_point.as_bytes(),
                    TpmEccCurve::NistP521,
                    hash_alg,
                    symmetric,
                )
            }
        }
    }

    /// Returns the sensitive part of the private key required for import.
    #[must_use]
    pub fn sensitive_blob(&self) -> Vec<u8> {
        match self {
            ExternalKey::Rsa2048(key) | ExternalKey::Rsa3072(key) | ExternalKey::Rsa4096(key) => {
                key.primes()[0].to_bytes_be()
            }
            ExternalKey::EccP256(secret_key) => secret_key.to_bytes().to_vec(),
            ExternalKey::EccP384(secret_key) => secret_key.to_bytes().to_vec(),
            ExternalKey::EccP521(secret_key) => secret_key.to_bytes().to_vec(),
        }
    }
}
