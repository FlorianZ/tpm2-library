// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! TPM 2.0 public key templates.

use crate::{TpmCryptoError, TpmEllipticCurve, TpmHash};
use std::str::FromStr;
use tpm2_protocol::{
    basic::{TpmBuffer, TpmUint16, TpmUint32},
    data::{
        Tpm2bDigest, TpmAlgId, TpmEccCurve, TpmaObject, TpmsEccParms, TpmsKeyedhashParms,
        TpmsRsaParms, TpmtEccScheme, TpmtKdfScheme, TpmtKeyedhashScheme, TpmtPublic, TpmtRsaScheme,
        TpmtSymDefObject, TpmuKeyedhashScheme, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits,
        TpmuSymMode,
    },
};

/// A template describing a TPM public area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmPublicTemplate {
    object_type: TpmAlgId,
    name_alg: TpmAlgId,
    key_bits: TpmUint16,
    curve_id: TpmEccCurve,
    auth_policy: Tpm2bDigest,
    object_attributes: TpmaObject,
    symmetric: TpmtSymDefObject,
}

impl Default for TpmPublicTemplate {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmPublicTemplate {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            object_type: TpmAlgId::Null,
            name_alg: TpmAlgId::Null,
            key_bits: TpmUint16(0),
            curve_id: TpmEccCurve::None,
            auth_policy: Tpm2bDigest::new(),
            object_attributes: TpmaObject::empty(),
            symmetric: TpmtSymDefObject {
                algorithm: TpmAlgId::Null,
                key_bits: TpmuSymKeyBits::Null,
                mode: TpmuSymMode::Null,
            },
        }
    }

    #[must_use]
    pub const fn with_object_type(mut self, object_type: TpmAlgId) -> Self {
        self.object_type = object_type;
        self
    }

    #[must_use]
    pub const fn with_name_alg(mut self, name_alg: TpmAlgId) -> Self {
        self.name_alg = name_alg;
        self
    }

    #[must_use]
    pub const fn with_key_bits(mut self, key_bits: TpmUint16) -> Self {
        self.key_bits = key_bits;
        self
    }

    #[must_use]
    pub const fn with_curve_id(mut self, curve_id: TpmEccCurve) -> Self {
        self.curve_id = curve_id;
        self
    }

    #[must_use]
    pub const fn with_auth_policy(mut self, auth_policy: Tpm2bDigest) -> Self {
        self.auth_policy = auth_policy;
        self
    }

    #[must_use]
    pub const fn with_object_attributes(mut self, object_attributes: TpmaObject) -> Self {
        self.object_attributes = object_attributes;
        self
    }

    #[must_use]
    pub const fn with_symmetric(mut self, symmetric: TpmtSymDefObject) -> Self {
        self.symmetric = symmetric;
        self
    }

    /// Returns the object type.
    #[must_use]
    pub const fn object_type(&self) -> TpmAlgId {
        self.object_type
    }

    /// Returns the name algorithm.
    #[must_use]
    pub const fn name_alg(&self) -> TpmAlgId {
        self.name_alg
    }

    /// Returns the key bits.
    #[must_use]
    pub const fn key_bits(&self) -> TpmUint16 {
        self.key_bits
    }

    /// Returns the curve ID.
    #[must_use]
    pub const fn curve_id(&self) -> TpmEccCurve {
        self.curve_id
    }

    /// Returns the authentication policy.
    #[must_use]
    pub const fn auth_policy(&self) -> Tpm2bDigest {
        self.auth_policy
    }

    /// Returns the object attributes.
    #[must_use]
    pub const fn object_attributes(&self) -> TpmaObject {
        self.object_attributes
    }

    /// Returns the symmetric algorithm definition.
    #[must_use]
    pub const fn symmetric(&self) -> TpmtSymDefObject {
        self.symmetric
    }
}

impl TryFrom<TpmPublicTemplate> for TpmtPublic {
    type Error = TpmCryptoError;

    fn try_from(template: TpmPublicTemplate) -> Result<Self, TpmCryptoError> {
        let (parameters, unique) = match template.object_type {
            TpmAlgId::Rsa => {
                let key_bits = template.key_bits;

                if key_bits.value() == 0 {
                    return Err(TpmCryptoError::InvalidRsaParameters);
                }

                (
                    TpmuPublicParms::Rsa(TpmsRsaParms {
                        symmetric: template.symmetric,
                        scheme: TpmtRsaScheme::default(),
                        key_bits,
                        exponent: TpmUint32::from(0),
                    }),
                    TpmuPublicId::Rsa(TpmBuffer::default()),
                )
            }
            TpmAlgId::Ecc => {
                let curve_id = template.curve_id;

                if curve_id == TpmEccCurve::None {
                    return Err(TpmCryptoError::InvalidEccParameters);
                }

                (
                    TpmuPublicParms::Ecc(TpmsEccParms {
                        symmetric: template.symmetric,
                        scheme: TpmtEccScheme::default(),
                        curve_id,
                        kdf: TpmtKdfScheme::default(),
                    }),
                    TpmuPublicId::Ecc(tpm2_protocol::data::TpmsEccPoint::default()),
                )
            }
            TpmAlgId::KeyedHash => (
                TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
                    scheme: TpmtKeyedhashScheme {
                        scheme: TpmAlgId::Null,
                        details: TpmuKeyedhashScheme::Null,
                    },
                }),
                TpmuPublicId::KeyedHash(TpmBuffer::default()),
            ),
            _ => return Err(TpmCryptoError::InvalidObjectType),
        };

        Ok(TpmtPublic {
            object_type: template.object_type,
            name_alg: template.name_alg,
            object_attributes: template.object_attributes,
            auth_policy: template.auth_policy,
            parameters,
            unique,
        })
    }
}

impl TryFrom<TpmPublicTemplate> for String {
    type Error = TpmCryptoError;

    fn try_from(template: TpmPublicTemplate) -> Result<Self, TpmCryptoError> {
        let name_alg_str = TpmHash::from(template.name_alg).to_string();
        match template.object_type {
            TpmAlgId::Rsa => {
                let key_bits = template.key_bits;

                if key_bits.value() == 0 {
                    return Err(TpmCryptoError::InvalidRsaParameters);
                }

                Ok(format!("rsa-{key_bits}:{name_alg_str}"))
            }
            TpmAlgId::Ecc => {
                let curve = template.curve_id;
                let curve_str = TpmEllipticCurve::from(curve).to_string();

                if curve == TpmEccCurve::None {
                    return Err(TpmCryptoError::InvalidEccParameters);
                }

                Ok(format!("ecc-{curve_str}:{name_alg_str}"))
            }
            TpmAlgId::KeyedHash => Ok(format!("keyedhash:{name_alg_str}")),
            _ => Ok(format!("unknown:{name_alg_str}")),
        }
    }
}

impl FromStr for TpmPublicTemplate {
    type Err = TpmCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("rsa-") {
            parse_rsa(rest)
        } else if let Some(rest) = s.strip_prefix("ecc-") {
            parse_ecc(rest)
        } else if let Some(name_alg_str) = s.strip_prefix("keyedhash:") {
            parse_keyedhash(name_alg_str)
        } else {
            Err(TpmCryptoError::InvalidObjectType)
        }
    }
}

fn parse_rsa(suffix: &str) -> Result<TpmPublicTemplate, TpmCryptoError> {
    let (bits_str, name_alg_str) = suffix
        .split_once(':')
        .ok_or(TpmCryptoError::InvalidObjectType)?;
    let key_bits: u16 = bits_str
        .parse()
        .map_err(|_| TpmCryptoError::InvalidObjectType)?;
    let name_alg = TpmHash::from_str(name_alg_str)
        .map_err(|_| TpmCryptoError::InvalidObjectType)?
        .into();

    Ok(TpmPublicTemplate::new()
        .with_object_type(TpmAlgId::Rsa)
        .with_name_alg(name_alg)
        .with_key_bits(TpmUint16(key_bits)))
}

fn parse_ecc(suffix: &str) -> Result<TpmPublicTemplate, TpmCryptoError> {
    let (curve_str, name_alg_str) = suffix
        .split_once(':')
        .ok_or(TpmCryptoError::InvalidObjectType)?;
    let curve_id: TpmEccCurve = TpmEllipticCurve::from_str(curve_str)
        .map_err(|_| TpmCryptoError::InvalidObjectType)?
        .into();
    let name_alg = TpmHash::from_str(name_alg_str)
        .map_err(|_| TpmCryptoError::InvalidObjectType)?
        .into();

    Ok(TpmPublicTemplate::new()
        .with_object_type(TpmAlgId::Ecc)
        .with_name_alg(name_alg)
        .with_curve_id(curve_id))
}

fn parse_keyedhash(hash_alg: &str) -> Result<TpmPublicTemplate, TpmCryptoError> {
    let name_alg = TpmHash::from_str(hash_alg)
        .map_err(|_| TpmCryptoError::InvalidObjectType)?
        .into();

    Ok(TpmPublicTemplate::new()
        .with_object_type(TpmAlgId::KeyedHash)
        .with_name_alg(name_alg))
}
