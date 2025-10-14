// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::key::{Alg, AlgInfo};
use tpm2_protocol::{
    data::{
        Tpm2bDigest, TpmAlgId, TpmaObject, TpmsEccParms, TpmsKeyedhashParms, TpmsRsaParms,
        TpmtEccScheme, TpmtKdfScheme, TpmtKeyedhashScheme, TpmtPublic, TpmtRsaScheme,
        TpmtSymDefObject, TpmuKeyedhashScheme, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits,
        TpmuSymMode,
    },
    TpmBuffer,
};

/// Builds a `TpmtPublic` template for creating new objects.
///
/// This function centralizes the logic for constructing the public area of a TPM
/// object, handling RSA, ECC, and `KeyedHash` types based on the provided `Alg`.
#[must_use]
pub fn build_public_template(
    alg_desc: &Alg,
    auth_policy: Tpm2bDigest,
    object_attributes: TpmaObject,
) -> TpmtPublic {
    let symmetric = TpmtSymDefObject {
        algorithm: TpmAlgId::Aes,
        key_bits: TpmuSymKeyBits::Aes(128),
        mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
    };

    let (parameters, unique) = match alg_desc.params {
        AlgInfo::Rsa { key_bits } => (
            TpmuPublicParms::Rsa(TpmsRsaParms {
                symmetric,
                scheme: TpmtRsaScheme::default(),
                key_bits,
                exponent: 0,
            }),
            TpmuPublicId::Rsa(TpmBuffer::default()),
        ),
        AlgInfo::Ecc { curve_id } => (
            TpmuPublicParms::Ecc(TpmsEccParms {
                symmetric,
                scheme: TpmtEccScheme::default(),
                curve_id,
                kdf: TpmtKdfScheme::default(),
            }),
            TpmuPublicId::Ecc(tpm2_protocol::data::TpmsEccPoint::default()),
        ),
        AlgInfo::KeyedHash => (
            TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
                scheme: TpmtKeyedhashScheme {
                    scheme: TpmAlgId::Null,
                    details: TpmuKeyedhashScheme::Null,
                },
            }),
            TpmuPublicId::KeyedHash(TpmBuffer::default()),
        ),
    };

    TpmtPublic {
        object_type: alg_desc.object_type,
        name_alg: alg_desc.name_alg,
        object_attributes,
        auth_policy,
        parameters,
        unique,
    }
}

/// Builds the default attributes for a new TPM object.
#[must_use]
pub fn default_attributes(alg: &Alg, user_with_auth: bool) -> TpmaObject {
    let mut attributes = TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT;

    if alg.object_type != TpmAlgId::KeyedHash {
        attributes |=
            TpmaObject::SENSITIVE_DATA_ORIGIN | TpmaObject::DECRYPT | TpmaObject::RESTRICTED;
    }

    if user_with_auth {
        attributes |= TpmaObject::USER_WITH_AUTH;
    }

    attributes
}
