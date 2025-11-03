//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

mod ecc;
mod rsa;

pub use ecc::*;
pub use rsa::*;

use crate::key::KeyError;
use rasn::{
    types::{Any, Integer, ObjectIdentifier, OctetString, SetOf},
    AsnType, Decode, Decoder, Encode,
};
use std::{borrow::Cow, fmt};

pub const OID_EC_PUBLIC_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 10_045, 2, 1]));
pub const OID_SHA1_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 113_549, 1, 1, 5]));
pub const OID_SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 113_549, 1, 1, 11]));
pub const OID_SHA384_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 113_549, 1, 1, 12]));
pub const OID_SHA512_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 113_549, 1, 1, 13]));
pub const OID_ECDSA_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 10045, 4, 3, 2]));
pub const OID_ECDSA_WITH_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 10045, 4, 3, 3]));
pub const OID_ECDSA_WITH_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 10045, 4, 3, 4]));
pub const OID_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unchecked(Cow::Borrowed(&[1, 2, 840, 113_549, 1, 1, 1]));

#[derive(AsnType, Decode, Encode, Debug)]
pub struct Pkcs8AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Any>,
}

#[derive(AsnType, Decode, Encode, Debug)]
pub struct Pkcs8PrivateKeyInfo {
    pub version: Integer,
    pub private_key_algorithm: Pkcs8AlgorithmIdentifier,
    pub private_key: OctetString,
    #[rasn(tag(context, 0))]
    pub attributes: Option<SetOf<Any>>,
}

#[derive(Clone)]
pub enum ExternalKey {
    Rsa2048(Box<::rsa::RsaPrivateKey>),
    Rsa3072(Box<::rsa::RsaPrivateKey>),
    Rsa4096(Box<::rsa::RsaPrivateKey>),
    EccP256(Box<::p256::SecretKey>),
    EccP384(Box<::p384::SecretKey>),
    EccP521(Box<::p521::SecretKey>),
}

impl fmt::Debug for ExternalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa2048(_) => f.debug_tuple("rsa-2048").field(&"<sensitive>").finish(),
            Self::Rsa3072(_) => f.debug_tuple("rsa-3072").field(&"<sensitive>").finish(),
            Self::Rsa4096(_) => f.debug_tuple("rsa-4096").field(&"<sensitive>").finish(),
            Self::EccP256(_) => f
                .debug_tuple("ecc-nist-p256")
                .field(&"<sensitive>")
                .finish(),
            Self::EccP384(_) => f
                .debug_tuple("ecc-nist-p384")
                .field(&"<sensitive>")
                .finish(),
            Self::EccP521(_) => f
                .debug_tuple("ecc-nist-p521")
                .field(&"<sensitive>")
                .finish(),
        }
    }
}

impl ExternalKey {
    /// Load and parse a DER-encoded private key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns `KeyError` on parsing failure.
    pub fn from_der(der_bytes: &[u8]) -> Result<ExternalKey, KeyError> {
        if let Ok(pkcs8_key) = rasn::der::decode::<Pkcs8PrivateKeyInfo>(der_bytes) {
            let oid = &pkcs8_key.private_key_algorithm.algorithm;
            let inner_key_bytes = pkcs8_key.private_key.as_ref();

            if oid == &OID_RSA_ENCRYPTION {
                return parse_rsa_from_der(inner_key_bytes);
            }
            if oid == &OID_EC_PUBLIC_KEY {
                let params_any = pkcs8_key.private_key_algorithm.parameters.as_ref().ok_or(
                    KeyError::ValueConversionFailed(
                        "missing curve OID in AlgorithmIdentifier".to_string(),
                    ),
                )?;
                let curve_oid: ObjectIdentifier = rasn::der::decode(params_any.as_ref())?;
                return parse_ecc_from_der(inner_key_bytes, Some(&curve_oid));
            }
            return Err(KeyError::UnsupportedOid(oid.to_string()));
        }

        if let Ok(key) = parse_rsa_from_der(der_bytes) {
            return Ok(key);
        }

        if let Ok(key) = parse_ecc_from_der(der_bytes, None) {
            return Ok(key);
        }

        Err(KeyError::InvalidFormat)
    }
}
