// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Tests for `TpmtPublic` generation.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use openssl::nid::Nid;
use rstest::rstest;
use std::str::FromStr;
use tpm2_crypto::{
    TpmCryptoError, TpmEccExternalKey, TpmEllipticCurve, TpmExternalKey, TpmHash,
    TpmPublicTemplate, TpmRsaExternalKey,
};
use tpm2_protocol::{
    basic::TpmUint32,
    data::{
        Tpm2bDigest, Tpm2bEccParameter, Tpm2bPublicKeyRsa, Tpm2bSymKey, TpmAlgId, TpmEccCurve,
        TpmaObject, TpmsEccPoint, TpmsKeyedhashParms, TpmsSymcipherParms, TpmtKeyedhashScheme,
        TpmtPublic, TpmtSymDefObject, TpmuAsymScheme, TpmuKeyedhashScheme, TpmuPublicId,
        TpmuPublicParms, TpmuSymMode,
    },
};

const TEST_MODULUS: [u8; 256] = [1; 256];
const TEST_COORD: [u8; 32] = [2; 32];

#[rstest]
#[case(TpmHash::Sha256, 2048)]
#[case(TpmHash::Sha384, 3072)]
fn test_rsa_to_public(#[case] hash_alg: TpmHash, #[case] key_bits: u16) {
    let public_key = Tpm2bPublicKeyRsa::try_from(TEST_MODULUS.as_slice()).unwrap();
    let rsa_key = TpmRsaExternalKey::new(public_key, TpmUint32::new(0), key_bits.into());
    let symmetric = TpmtSymDefObject::default();

    let template = tpm2_crypto::TpmPublicTemplate::new()
        .with_name_alg(hash_alg)
        .with_object_attributes(TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT)
        .with_symmetric(symmetric);

    let public = rsa_key.to_public(&template);
    let default_attr = TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT;
    let hash_alg_id = TpmAlgId::from(hash_alg);

    assert_eq!(public.object_type, TpmAlgId::Rsa);
    assert_eq!(public.name_alg, hash_alg_id);
    assert_eq!(public.object_attributes, default_attr);
    assert_eq!(public.auth_policy.len(), 0);

    if let TpmuPublicParms::Rsa(params) = public.parameters {
        assert_eq!(u16::from(params.key_bits), key_bits);
        assert_eq!(u32::from(params.exponent), 0);
        assert_eq!(params.scheme.scheme, TpmAlgId::Oaep);
        if let TpmuAsymScheme::Hash(details) = params.scheme.details {
            assert_eq!(details.hash_alg, hash_alg_id);
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
#[case(TpmHash::Sha256, TpmEllipticCurve::NistP256, &TEST_COORD, &TEST_COORD)]
#[case(TpmHash::Sha1, TpmEllipticCurve::NistP192, &[3; 24], &[4; 24])]
fn test_ecc_to_public(
    #[case] hash_alg: TpmHash,
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
    let hash_alg_id = TpmAlgId::from(hash_alg);

    assert_eq!(public.object_type, TpmAlgId::Ecc);
    assert_eq!(public.name_alg, hash_alg_id);
    assert_eq!(
        public.object_attributes,
        TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT
    );
    assert_eq!(public.auth_policy.len(), 0);

    if let TpmuPublicParms::Ecc(params) = public.parameters {
        assert_eq!(params.curve_id, curve.into());
        assert_eq!(params.scheme.scheme, TpmAlgId::Ecdh);
        if let TpmuAsymScheme::Hash(details) = params.scheme.details {
            assert_eq!(details.hash_alg, hash_alg_id);
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

#[rstest]
#[case("keyedhash-null:sha256", TpmAlgId::Null)]
#[case("keyedhash-xor:sha256", TpmAlgId::Xor)]
#[case("keyedhash-hmac:sha256", TpmAlgId::Hmac)]
fn test_keyedhash_parsing(#[case] input: &str, #[case] expected_scheme: TpmAlgId) {
    let template = TpmPublicTemplate::from_str(input).expect("parse failed");
    let public = TpmtPublic::try_from(template.clone()).expect("template to public");

    assert_eq!(public.object_type, TpmAlgId::KeyedHash);
    assert_eq!(public.name_alg, TpmAlgId::Sha256);

    if let TpmuPublicParms::KeyedHash(params) = public.parameters {
        assert_eq!(params.scheme.scheme, expected_scheme);
        match expected_scheme {
            TpmAlgId::Null => assert!(matches!(params.scheme.details, TpmuKeyedhashScheme::Null)),
            TpmAlgId::Xor => assert!(matches!(params.scheme.details, TpmuKeyedhashScheme::Xor(_))),
            TpmAlgId::Hmac => {
                assert!(matches!(
                    params.scheme.details,
                    TpmuKeyedhashScheme::Hmac(_)
                ));
            }
            _ => panic!("Unexpected scheme"),
        }
    } else {
        panic!("Incorrect parameters type: expected KEYEDHASH");
    }

    let output_str: String = template.try_into().expect("to string failed");
    assert_eq!(output_str, input);
}

#[test]
fn mismatched_public_types_rejected() {
    let unique = TpmuPublicId::Rsa(Tpm2bPublicKeyRsa::default());
    let parms = TpmuPublicParms::Ecc(tpm2_protocol::data::TpmsEccParms {
        symmetric: TpmtSymDefObject::default(),
        scheme: tpm2_protocol::data::TpmtEccScheme::default(),
        curve_id: TpmEccCurve::NistP256,
        kdf: tpm2_protocol::data::TpmtKdfScheme::default(),
    });

    let result = tpm2_crypto::TpmPublicTemplate::new().with_public(unique, parms);

    assert!(matches!(
        result,
        Err(tpm2_crypto::TpmCryptoError::InvalidObjectType)
    ));
}

#[test]
fn template_string_rejects_unknown_keyedhash_scheme() {
    let template = TpmPublicTemplate::new()
        .with_public(
            TpmuPublicId::KeyedHash(Tpm2bDigest::default()),
            TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
                scheme: TpmtKeyedhashScheme {
                    scheme: TpmAlgId::Oaep,
                    details: TpmuKeyedhashScheme::Null,
                },
            }),
        )
        .unwrap()
        .with_name_alg(TpmHash::Sha256);

    let result = String::try_from(template);

    assert!(matches!(result, Err(TpmCryptoError::InvalidObjectType)));
}

#[test]
fn template_string_rejects_unsupported_public_parameters() {
    let template = TpmPublicTemplate::new()
        .with_public(
            TpmuPublicId::SymCipher(Tpm2bSymKey::default()),
            TpmuPublicParms::SymCipher(TpmsSymcipherParms {
                sym: TpmtSymDefObject::default(),
            }),
        )
        .unwrap()
        .with_name_alg(TpmHash::Sha256);

    let result = String::try_from(template);

    assert!(matches!(result, Err(TpmCryptoError::InvalidObjectType)));
}

#[test]
fn rsa_to_public_with_aes_symmetric() {
    let public_key = Tpm2bPublicKeyRsa::try_from(TEST_MODULUS.as_slice()).unwrap();
    let rsa_key = TpmRsaExternalKey::new(public_key, TpmUint32::new(0), 2048.into());

    let symmetric = TpmtSymDefObject {
        algorithm: TpmAlgId::Aes,
        key_bits: tpm2_protocol::data::TpmuSymKeyBits::Aes(128.into()),
        mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
    };

    let template = tpm2_crypto::TpmPublicTemplate::new()
        .with_name_alg(TpmHash::Sha256)
        .with_object_attributes(TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT)
        .with_symmetric(symmetric);

    let public = rsa_key.to_public(&template);

    if let TpmuPublicParms::Rsa(params) = public.parameters {
        assert_eq!(params.symmetric, symmetric);
    } else {
        panic!("Incorrect parameters type: expected RSA");
    }
}

#[test]
fn rsa_to_public_preserves_auth_policy() {
    let public_key = Tpm2bPublicKeyRsa::try_from(TEST_MODULUS.as_slice()).unwrap();
    let rsa_key = TpmRsaExternalKey::new(public_key, TpmUint32::new(0), 2048.into());
    let auth_policy = Tpm2bDigest::try_from([0xa5; 32].as_slice()).unwrap();

    let template = TpmPublicTemplate::new()
        .with_name_alg(TpmHash::Sha256)
        .with_auth_policy(auth_policy);

    let public = rsa_key.to_public(&template);

    assert_eq!(public.auth_policy, auth_policy);
}

#[test]
fn ecc_to_public_preserves_auth_policy() {
    let x = Tpm2bEccParameter::try_from(TEST_COORD.as_slice()).unwrap();
    let y = Tpm2bEccParameter::try_from(TEST_COORD.as_slice()).unwrap();
    let unique = TpmsEccPoint { x, y };
    let ecc_key = TpmEccExternalKey::new(TpmEllipticCurve::NistP256, unique);
    let auth_policy = Tpm2bDigest::try_from([0x5a; 32].as_slice()).unwrap();

    let template = TpmPublicTemplate::new()
        .with_name_alg(TpmHash::Sha256)
        .with_auth_policy(auth_policy);

    let public = ecc_key.to_public(&template);

    assert_eq!(public.auth_policy, auth_policy);
}

#[test]
fn invalid_curve_conversions_fail() {
    assert!(matches!(
        TpmEllipticCurve::try_from(TpmEccCurve::None),
        Err(TpmCryptoError::InvalidEccCurve)
    ));
    assert!(matches!(
        TpmEllipticCurve::try_from(Nid::UNDEF),
        Err(TpmCryptoError::InvalidEccCurve)
    ));
    assert!(matches!(
        Nid::try_from(TpmEllipticCurve::BnP256),
        Err(TpmCryptoError::InvalidEccCurve)
    ));
}
