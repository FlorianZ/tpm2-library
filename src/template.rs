// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::alg::{TpmPublicKind, TpmPublicTemplate};
use tpm2_protocol::{
    basic::TpmBuffer,
    data::{
        Tpm2bDigest, TpmAlgId, TpmaObject, TpmsEccParms, TpmsKeyedhashParms, TpmsRsaParms,
        TpmtEccScheme, TpmtKdfScheme, TpmtKeyedhashScheme, TpmtPublic, TpmtRsaScheme,
        TpmtSymDefObject, TpmuKeyedhashScheme, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits,
        TpmuSymMode,
    },
};

/// Builds a `TpmtPublic` template for creating new objects.
///
/// Centralizes the logic for constructing the public area of a TPM object,
/// handling RSA, ECC, and `KeyedHash` types based on the provided `Alg`.
#[must_use]
pub fn build_public(
    alg_desc: &TpmPublicTemplate,
    auth_policy: Tpm2bDigest,
    object_attributes: TpmaObject,
) -> TpmtPublic {
    let symmetric = TpmtSymDefObject {
        algorithm: TpmAlgId::Aes,
        key_bits: TpmuSymKeyBits::Aes(128),
        mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
    };

    let (parameters, unique) = match alg_desc.kind {
        TpmPublicKind::Rsa { key_bits } => (
            TpmuPublicParms::Rsa(TpmsRsaParms {
                symmetric,
                scheme: TpmtRsaScheme::default(),
                key_bits,
                exponent: 0,
            }),
            TpmuPublicId::Rsa(TpmBuffer::default()),
        ),
        TpmPublicKind::Ecc { curve_id } => (
            TpmuPublicParms::Ecc(TpmsEccParms {
                symmetric,
                scheme: TpmtEccScheme::default(),
                curve_id,
                kdf: TpmtKdfScheme::default(),
            }),
            TpmuPublicId::Ecc(tpm2_protocol::data::TpmsEccPoint::default()),
        ),
        TpmPublicKind::KeyedHash => (
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
        object_type: alg_desc.alg_id(),
        name_alg: alg_desc.hash,
        object_attributes,
        auth_policy,
        parameters,
        unique,
    }
}
