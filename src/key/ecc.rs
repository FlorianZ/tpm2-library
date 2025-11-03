//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy

#![allow(clippy::no_effect_underscore_binding)]

use crate::key::{EccKey, KeyError};

use openssl::{
    bn::BigNumContext,
    ec::PointConversionForm,
    nid::Nid,
    pkey::{PKey, Private},
};
use rasn::{
    types::{BitString, ObjectIdentifier, OctetString},
    AsnType, Decode, Decoder, Encode, Encoder,
};
use std::borrow::Cow;
use tpm2_crypto::UNCOMPRESSED_POINT_TAG;
use tpm2_protocol::data::{
    Tpm2bDigest, Tpm2bEccParameter, TpmAlgId, TpmEccCurve, TpmaObject, TpmsEccParms, TpmsEccPoint,
    TpmtEccScheme, TpmtKdfScheme, TpmtPublic, TpmtSymDefObject, TpmuAsymScheme, TpmuPublicId,
    TpmuPublicParms,
};

pub const OID_EC_PUBLIC_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 10_045, 2, 1]));
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
    inherited_oid: Option<ObjectIdentifier>,
) -> Result<EccKey, KeyError> {
    let sec1_key = rasn::der::decode::<Sec1EcPrivateKey>(der_bytes)?;

    let curve_oid =
        sec1_key
            .parameters
            .or(inherited_oid)
            .ok_or(KeyError::ValueConversionFailed(
                "missing ECC parameters".to_string(),
            ))?;

    if curve_oid == SECP_256_R_1 || curve_oid == SECP_384_R_1 || curve_oid == SECP_521_R_1 {
        Ok(EccKey {
            curve_oid,
            d: sec1_key.private_key.as_ref().to_vec(),
        })
    } else {
        Err(KeyError::UnsupportedOid(curve_oid.to_string()))
    }
}

/// Converts ECC public key bytes to a `TpmtPublic` structure.
///
/// # Errors
///
/// Returns a `KeyError` if the public key bytes do not represent a valid
/// uncompressed ECC point or if conversion to TPM types fails.
pub fn ecc_to_public_id(
    pkey: &PKey<Private>,
    hash_alg: TpmAlgId,
    symmetric: TpmtSymDefObject,
) -> Result<TpmtPublic, KeyError> {
    let ec_key = pkey.ec_key()?;
    let group = ec_key.group();
    let nid = group.curve_name().ok_or(KeyError::InvalidFormat)?;

    let curve_id = match nid {
        Nid::X9_62_PRIME256V1 => TpmEccCurve::NistP256,
        Nid::SECP384R1 => TpmEccCurve::NistP384,
        Nid::SECP521R1 => TpmEccCurve::NistP521,
        _ => return Err(KeyError::InvalidEccCurve(nid.long_name()?.to_string())),
    };

    let mut ctx = BigNumContext::new()?;
    let pub_bytes =
        ec_key
            .public_key()
            .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;

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
            x: Tpm2bEccParameter::try_from(x).map_err(|_| KeyError::CapacityExceeded)?,
            y: Tpm2bEccParameter::try_from(y).map_err(|_| KeyError::CapacityExceeded)?,
        }),
    })
}
