//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy

#![allow(clippy::no_effect_underscore_binding)]

use crate::key::{KeyError, RsaKey};
use num_bigint::{BigUint, ToBigInt};
use num_traits::ToPrimitive;
use openssl::pkey::{PKey, Private};
use rasn::{
    types::{Integer, SequenceOf},
    AsnType, Decode, Decoder, Encode,
};
use std::borrow::Cow;
use tpm2_protocol::data::{
    Tpm2bDigest, Tpm2bPublicKeyRsa, TpmAlgId, TpmaObject, TpmsRsaParms, TpmsSchemeHash,
    TpmtRsaScheme, TpmtSymDefObject, TpmuAsymScheme, TpmuPublicId, TpmuPublicParms,
};

pub const OID_RSA_ENCRYPTION: rasn::types::ObjectIdentifier =
    rasn::types::ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 113_549, 1, 1, 1]));

#[derive(AsnType, Decode, Encode, Debug)]
pub struct OtherPrimeInfo {
    pub prime: Integer,
    pub exponent: Integer,
    pub coefficient: Integer,
}

/// A struct representing the full 9-field PKCS#1 `RSAPrivateKey` structure.
#[allow(clippy::no_effect_underscore_binding)]
#[derive(AsnType, Decode, Encode, Debug)]
pub struct RsaPrivateKeyAsn1 {
    pub version: Integer,
    pub modulus: Integer,
    pub public_exponent: Integer,
    pub private_exponent: Integer,
    pub prime1: Integer,
    pub prime2: Integer,
    pub exponent1: Integer,
    pub exponent2: Integer,
    pub coefficient: Integer,
    pub other_prime_infos: Option<SequenceOf<OtherPrimeInfo>>,
}

/// A struct representing an 8-field PKCS#1 `RSAPrivateKey` structure,
/// for compatibility with encoders that omit the `version` field when it is 0.
#[allow(clippy::no_effect_underscore_binding)]
#[derive(AsnType, Decode, Encode, Debug)]
pub struct RsaPrivateKeyPkcs1V0 {
    pub modulus: Integer,
    pub public_exponent: Integer,
    pub private_exponent: Integer,
    pub prime1: Integer,
    pub prime2: Integer,
    pub exponent1: Integer,
    pub exponent2: Integer,
    pub coefficient: Integer,
    pub other_prime_infos: Option<SequenceOf<OtherPrimeInfo>>,
}

/// Builds a `RsaKey` from ASN.1 integer components.
fn build_logical_key(
    modulus: &Integer,
    public_exponent: &Integer,
    prime1: &Integer,
    prime2: &Integer,
) -> Result<RsaKey, KeyError> {
    let e_biguint = public_exponent
        .to_bigint()
        .ok_or(KeyError::InvalidFormat)?
        .to_biguint()
        .ok_or(KeyError::InvalidFormat)?;

    if e_biguint != BigUint::from(65537u32) {
        return Err(KeyError::InvalidRsaExponent);
    }

    let n = modulus
        .to_bigint()
        .ok_or(KeyError::InvalidFormat)?
        .to_bytes_be()
        .1;
    let e = public_exponent
        .to_bigint()
        .ok_or(KeyError::InvalidFormat)?
        .to_bytes_be()
        .1;
    let p = prime1
        .to_bigint()
        .ok_or(KeyError::InvalidFormat)?
        .to_bytes_be()
        .1;
    let q = prime2
        .to_bigint()
        .ok_or(KeyError::InvalidFormat)?
        .to_bytes_be()
        .1;

    match n.len() * 8 {
        2048 | 3072 | 4096 => Ok(RsaKey { n, e, p, q }),
        bits => Err(KeyError::InvalidRsaKeyBits(bits.to_string())),
    }
}

/// Parses a PKCS#1 DER-encoded RSA private key with fallback logic.
fn parse_pkcs1_rsa_from_der(der_bytes: &[u8]) -> Result<RsaKey, KeyError> {
    if let Ok(pkcs1_key) = rasn::der::decode::<RsaPrivateKeyAsn1>(der_bytes) {
        let version = pkcs1_key.version.to_u8().ok_or(KeyError::InvalidFormat)?;
        if version != 0 || pkcs1_key.other_prime_infos.is_some() {
            return Err(KeyError::UnsupportedFileFormat);
        }
        return build_logical_key(
            &pkcs1_key.modulus,
            &pkcs1_key.public_exponent,
            &pkcs1_key.prime1,
            &pkcs1_key.prime2,
        );
    }

    if let Ok(pkcs1_v0_key) = rasn::der::decode::<RsaPrivateKeyPkcs1V0>(der_bytes) {
        if pkcs1_v0_key.other_prime_infos.is_some() {
            return Err(KeyError::UnsupportedFileFormat);
        }
        return build_logical_key(
            &pkcs1_v0_key.modulus,
            &pkcs1_v0_key.public_exponent,
            &pkcs1_v0_key.prime1,
            &pkcs1_v0_key.prime2,
        );
    }

    Err(KeyError::InvalidFormat)
}

/// Parses a DER-encoded RSA private key, supporting only the PKCS#1 format.
///
/// # Errors
///
/// Returns a `KeyError` if the DER data is malformed or the key parameters are unsupported.
pub fn parse_rsa_from_der(der_bytes: &[u8]) -> Result<RsaKey, KeyError> {
    parse_pkcs1_rsa_from_der(der_bytes)
}

/// Converts an `openssl::PKey` to a `TpmtPublic` structure.
///
/// # Errors
///
/// Returns a `KeyError` if the key's public modulus cannot be converted to the
/// `Tpm2bPublicKeyRsa` type.
pub fn rsa_to_public_id(
    pkey: &PKey<Private>,
    hash_alg: TpmAlgId,
    symmetric: TpmtSymDefObject,
) -> Result<tpm2_protocol::data::TpmtPublic, KeyError> {
    let rsa = pkey.rsa()?;
    let key_bits = u16::try_from(rsa.size() * 8)?;

    Ok(tpm2_protocol::data::TpmtPublic {
        object_type: TpmAlgId::Rsa,
        name_alg: hash_alg,
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parameters: TpmuPublicParms::Rsa(TpmsRsaParms {
            symmetric,
            scheme: TpmtRsaScheme {
                scheme: TpmAlgId::Oaep,
                details: TpmuAsymScheme::Any(TpmsSchemeHash { hash_alg }),
            },
            key_bits,
            exponent: 0,
        }),
        unique: TpmuPublicId::Rsa(
            Tpm2bPublicKeyRsa::try_from(rsa.n().to_vec().as_slice())
                .map_err(|_| KeyError::CapacityExceeded)?,
        ),
    })
}
