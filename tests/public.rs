// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Tests for `TpmtPublic` generation.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use rstest::rstest;
use tpm2_crypto::{TpmEccExternalKey, TpmEllipticCurve, TpmExternalKey, TpmRsaExternalKey};
use tpm2_protocol::{
    basic::{TpmBuffer, TpmUint16, TpmUint32},
    data::{
        Tpm2bEccParameter, Tpm2bPublicKeyRsa, TpmAlgId, TpmEccCurve, TpmaObject, TpmsEccParms,
        TpmsEccPoint, TpmsKeyedhashParms, TpmtEccScheme, TpmtKdfScheme, TpmtKeyedhashScheme,
        TpmtPublic, TpmtSymDefObject, TpmuAsymScheme, TpmuKeyedhashScheme, TpmuPublicId,
        TpmuPublicParms, TpmuSymKeyBits, TpmuSymMode,
    },
};

const TEST_MODULUS: [u8; 256] = [1; 256];
const TEST_COORD: [u8; 32] = [2; 32];

#[rstest]
#[case(TpmAlgId::Sha256, 2048)]
#[case(TpmAlgId::Sha384, 3072)]
fn test_rsa_to_public(#[case] hash_alg: TpmAlgId, #[case] key_bits: u16) {
    let public_key = Tpm2bPublicKeyRsa::try_from(TEST_MODULUS.as_slice()).unwrap();
    let rsa_key = TpmRsaExternalKey::new(public_key, TpmUint32(0), key_bits.into());
    let symmetric = TpmtSymDefObject::default();

    let template = tpm2_crypto::TpmPublicTemplate::new()
        .with_name_alg(hash_alg)
        .with_object_attributes(TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT)
        .with_symmetric(symmetric);

    let public = rsa_key.to_public(&template);
    let default_attr = TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT;

    assert_eq!(public.object_type, TpmAlgId::Rsa);
    assert_eq!(public.name_alg, hash_alg);
    assert_eq!(public.object_attributes, default_attr);
    assert_eq!(public.auth_policy.len(), 0);

    if let TpmuPublicParms::Rsa(params) = public.parameters {
        assert_eq!(u16::from(params.key_bits), key_bits);
        assert_eq!(u32::from(params.exponent), 0);
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
    let unique = TpmsEccPoint { x, y };
    let ecc_key = TpmEccExternalKey::new(curve, unique);
    let symmetric = TpmtSymDefObject::default();

    let template = tpm2_crypto::TpmPublicTemplate::new()
        .with_name_alg(hash_alg)
        .with_object_attributes(TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT)
        .with_symmetric(symmetric);
    let public = ecc_key.to_public(&template);

    assert_eq!(public.object_type, TpmAlgId::Ecc);
    assert_eq!(public.name_alg, hash_alg);
    assert_eq!(
        public.object_attributes,
        TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT
    );
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

#[test]
fn keyedhash_template_to_public() {
    let parms = TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
        scheme: TpmtKeyedhashScheme {
            scheme: TpmAlgId::Null,
            details: TpmuKeyedhashScheme::Null,
        },
    });
    let unique = TpmuPublicId::KeyedHash(TpmBuffer::default());

    let template = tpm2_crypto::TpmPublicTemplate::new()
        .with_public(unique, parms)
        .expect("valid keyedhash components")
        .with_name_alg(TpmAlgId::Sha256);

    let public = TpmtPublic::try_from(template).expect("template to public");

    assert_eq!(public.object_type, TpmAlgId::KeyedHash);
    assert_eq!(public.name_alg, TpmAlgId::Sha256);
    assert_eq!(public.auth_policy.len(), 0);

    if let TpmuPublicParms::KeyedHash(params) = public.parameters {
        assert_eq!(params.scheme.scheme, TpmAlgId::Null);
        assert!(matches!(params.scheme.details, TpmuKeyedhashScheme::Null));
    } else {
        panic!("Incorrect parameters type: expected KEYEDHASH");
    }

    if let TpmuPublicId::KeyedHash(buf) = public.unique {
        assert_eq!(buf.len(), 0);
    } else {
        panic!("Incorrect unique ID type: expected KEYEDHASH");
    }
}

#[test]
fn mismatched_public_types_rejected() {
    let unique = TpmuPublicId::Rsa(Tpm2bPublicKeyRsa::default());
    let parms = TpmuPublicParms::Ecc(TpmsEccParms {
        symmetric: TpmtSymDefObject::default(),
        scheme: TpmtEccScheme::default(),
        curve_id: TpmEccCurve::NistP256,
        kdf: TpmtKdfScheme::default(),
    });

    let result = tpm2_crypto::TpmPublicTemplate::new().with_public(unique, parms);

    assert!(matches!(
        result,
        Err(tpm2_crypto::TpmCryptoError::InvalidObjectType)
    ));
}

#[test]
fn rsa_to_public_with_aes_symmetric() {
    let public_key = Tpm2bPublicKeyRsa::try_from(TEST_MODULUS.as_slice()).unwrap();
    let rsa_key = TpmRsaExternalKey::new(public_key, TpmUint32(0), TpmUint16::from(2048));

    let symmetric = TpmtSymDefObject {
        algorithm: TpmAlgId::Aes,
        key_bits: TpmuSymKeyBits::Aes(TpmUint16::from(128)),
        mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
    };

    let template = tpm2_crypto::TpmPublicTemplate::new()
        .with_name_alg(TpmAlgId::Sha256)
        .with_object_attributes(TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT)
        .with_symmetric(symmetric);

    let public = rsa_key.to_public(&template);

    if let TpmuPublicParms::Rsa(params) = public.parameters {
        assert_eq!(params.symmetric, symmetric);
    } else {
        panic!("Incorrect parameters type: expected RSA");
    }
}
