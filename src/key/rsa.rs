//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy

#![allow(clippy::no_effect_underscore_binding)]

use crate::key::KeyError;
use openssl::pkey::{PKey, Private};
use tpm2_protocol::data::{
    Tpm2bDigest, Tpm2bPublicKeyRsa, TpmAlgId, TpmaObject, TpmsRsaParms, TpmsSchemeHash,
    TpmtRsaScheme, TpmtSymDefObject, TpmuAsymScheme, TpmuPublicId, TpmuPublicParms,
};

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
