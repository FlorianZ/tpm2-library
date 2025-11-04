//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy

#![allow(clippy::no_effect_underscore_binding)]

use crate::key::KeyError;

use openssl::{
    bn::BigNumContext,
    ec::PointConversionForm,
    nid::Nid,
    pkey::{PKey, Private},
};
use tpm2_crypto::UNCOMPRESSED_POINT_TAG;
use tpm2_protocol::data::{
    Tpm2bDigest, Tpm2bEccParameter, TpmAlgId, TpmEccCurve, TpmaObject, TpmsEccParms, TpmsEccPoint,
    TpmtEccScheme, TpmtKdfScheme, TpmtPublic, TpmtSymDefObject, TpmuAsymScheme, TpmuPublicId,
    TpmuPublicParms,
};

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
