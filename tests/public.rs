// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Tests for `TpmtPublic` generation.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use rstest::rstest;
use tpm2_crypto::{TpmEccExternalKey, TpmEllipticCurve, TpmExternalKey, TpmRsaExternalKey};
use tpm2_protocol::data::{
    Tpm2bEccParameter, Tpm2bPublicKeyRsa, TpmAlgId, TpmaObject, TpmtSymDefObject, TpmuAsymScheme,
    TpmuPublicId, TpmuPublicParms,
};

const TEST_MODULUS: [u8; 256] = [1; 256];
const TEST_COORD: [u8; 32] = [2; 32];

#[rstest]
#[case(TpmAlgId::Sha256, 2048)]
#[case(TpmAlgId::Sha384, 3072)]
fn test_rsa_to_public(#[case] hash_alg: TpmAlgId, #[case] key_bits: u16) {
    let n = Tpm2bPublicKeyRsa::try_from(TEST_MODULUS.as_slice()).unwrap();
    let rsa_key = TpmRsaExternalKey {
        n,
        e: 65537,
        key_bits,
    };
    let symmetric = TpmtSymDefObject::default();

    let public = rsa_key.to_public(
        hash_alg,
        TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT,
        symmetric,
    );
    let default_attr = TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT;

    assert_eq!(public.object_type, TpmAlgId::Rsa);
    assert_eq!(public.name_alg, hash_alg);
    assert_eq!(public.object_attributes, default_attr);
    assert_eq!(public.auth_policy.len(), 0);

    if let TpmuPublicParms::Rsa(params) = public.parameters {
        assert_eq!(params.key_bits, key_bits);
        assert_eq!(params.exponent, 0);
        assert_eq!(params.scheme.scheme, TpmAlgId::Oaep);
        if let TpmuAsymScheme::Hash(details) = params.scheme.details {
            assert_eq!(details.hash_alg, hash_alg);
        } else {
            panic!("Incorrect scheme details type: expected Hash");
        }
        assert_eq!(params.symmetric, symmetric);
    } else {
        panic!("Incorrect parameters type: expected RSA");
    }

    if let TpmuPublicId::Rsa(modulus) = public.unique {
        assert_eq!(modulus.as_ref(), TEST_MODULUS);
    } else {
        panic!("Incorrect unique ID type: expected RSA");
    }
}

#[rstest]
#[case(TpmAlgId::Sha256, TpmEllipticCurve::NistP256, &TEST_COORD, &TEST_COORD)]
#[case(TpmAlgId::Sha1, TpmEllipticCurve::NistP192, &[3; 24], &[4; 24])]
fn test_ecc_to_public(
    #[case] hash_alg: TpmAlgId,
    #[case] curve: TpmEllipticCurve,
    #[case] x_bytes: &[u8],
    #[case] y_bytes: &[u8],
) {
    let x = Tpm2bEccParameter::try_from(x_bytes).unwrap();
    let y = Tpm2bEccParameter::try_from(y_bytes).unwrap();
    let ecc_key = TpmEccExternalKey { curve, x, y };
    let symmetric = TpmtSymDefObject::default();

    let default_attr = TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT;
    let public = ecc_key.to_public(hash_alg, default_attr, symmetric);

    assert_eq!(public.object_type, TpmAlgId::Ecc);
    assert_eq!(public.name_alg, hash_alg);
    assert_eq!(public.object_attributes, default_attr);
    assert_eq!(public.auth_policy.len(), 0);

    if let TpmuPublicParms::Ecc(params) = public.parameters {
        assert_eq!(params.curve_id, curve.into());
        assert_eq!(params.scheme.scheme, TpmAlgId::Ecdh);
        if let TpmuAsymScheme::Hash(details) = params.scheme.details {
            assert_eq!(details.hash_alg, hash_alg);
        } else {
            panic!("Incorrect scheme details type: expected Hash");
        }
        assert_eq!(params.symmetric, symmetric);
    } else {
        panic!("Incorrect parameters type: expected ECC");
    }

    if let TpmuPublicId::Ecc(point) = public.unique {
        assert_eq!(point.x.as_ref(), x_bytes);
        assert_eq!(point.y.as_ref(), y_bytes);
    } else {
        panic!("Incorrect unique ID type: expected ECC");
    }
}
