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
    auth_policy: Tpm2bDigest,
    object_attributes: TpmaObject,
    symmetric: TpmtSymDefObject,
    public_id: TpmuPublicId,
    public_parms: TpmuPublicParms,
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
            object_type: TpmAlgId::KeyedHash,
            name_alg: TpmAlgId::Null,
            auth_policy: Tpm2bDigest::new(),
            object_attributes: TpmaObject::empty(),
            symmetric: TpmtSymDefObject {
                algorithm: TpmAlgId::Null,
                key_bits: TpmuSymKeyBits::Null,
                mode: TpmuSymMode::Null,
            },
            public_id: TpmuPublicId::KeyedHash(TpmBuffer::new()),
            public_parms: TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
                scheme: TpmtKeyedhashScheme {
                    scheme: TpmAlgId::Null,
                    details: TpmuKeyedhashScheme::Null,
                },
            }),
        }
    }

    /// Sets the public ID and parameters.
    ///
    /// This method implicitly sets the object type.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidObjectType`](crate::TpmCryptoError::InvalidObjectType)
    /// if the public ID and parameters do not match.
    pub fn with_public(
        mut self,
        public_id: TpmuPublicId,
        public_parms: TpmuPublicParms,
    ) -> Result<Self, TpmCryptoError> {
        self.object_type = match (&public_id, &public_parms) {
            (TpmuPublicId::Rsa(_), TpmuPublicParms::Rsa(_)) => TpmAlgId::Rsa,
            (TpmuPublicId::Ecc(_), TpmuPublicParms::Ecc(_)) => TpmAlgId::Ecc,
            (TpmuPublicId::KeyedHash(_), TpmuPublicParms::KeyedHash(_)) => TpmAlgId::KeyedHash,
            (TpmuPublicId::SymCipher(_), TpmuPublicParms::SymCipher(_)) => TpmAlgId::SymCipher,
            _ => return Err(TpmCryptoError::InvalidObjectType),
        };

        self.public_id = public_id;
        self.public_parms = public_parms;
        Ok(self)
    }

    #[must_use]
    pub const fn with_name_alg(mut self, name_alg: TpmAlgId) -> Self {
        self.name_alg = name_alg;
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
        let mut parameters = template.public_parms;

        match &mut parameters {
            TpmuPublicParms::Rsa(p) => p.symmetric = template.symmetric,
            TpmuPublicParms::Ecc(p) => p.symmetric = template.symmetric,
            TpmuPublicParms::SymCipher(p) => p.sym = template.symmetric,
            _ => {}
        }

        Ok(TpmtPublic {
            object_type: template.object_type,
            name_alg: template.name_alg,
            object_attributes: template.object_attributes,
            auth_policy: template.auth_policy,
            parameters,
            unique: template.public_id,
        })
    }
}

impl TryFrom<TpmPublicTemplate> for String {
    type Error = TpmCryptoError;

    fn try_from(template: TpmPublicTemplate) -> Result<Self, TpmCryptoError> {
        let name_alg_str = TpmHash::from(template.name_alg).to_string();
        match template.public_parms {
            TpmuPublicParms::Rsa(parms) => {
                let key_bits = parms.key_bits;
                if key_bits.value() == 0 {
                    return Err(TpmCryptoError::InvalidRsaParameters);
                }
                Ok(format!("rsa-{key_bits}:{name_alg_str}"))
            }
            TpmuPublicParms::Ecc(parms) => {
                let curve = parms.curve_id;
                let curve_str = TpmEllipticCurve::from(curve).to_string();
                if curve == TpmEccCurve::None {
                    return Err(TpmCryptoError::InvalidEccParameters);
                }
                Ok(format!("ecc-{curve_str}:{name_alg_str}"))
            }
            TpmuPublicParms::KeyedHash(_) => Ok(format!("keyedhash:{name_alg_str}")),
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

    let parms = TpmuPublicParms::Rsa(TpmsRsaParms {
        symmetric: TpmtSymDefObject::default(),
        scheme: TpmtRsaScheme::default(),
        key_bits: TpmUint16(key_bits),
        exponent: TpmUint32(0),
    });
    let unique = TpmuPublicId::Rsa(TpmBuffer::default());

    TpmPublicTemplate::new()
        .with_public(unique, parms)
        .map(|t| t.with_name_alg(name_alg))
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

    let parms = TpmuPublicParms::Ecc(TpmsEccParms {
        symmetric: TpmtSymDefObject::default(),
        scheme: TpmtEccScheme::default(),
        curve_id,
        kdf: TpmtKdfScheme::default(),
    });
    let unique = TpmuPublicId::Ecc(tpm2_protocol::data::TpmsEccPoint::default());

    TpmPublicTemplate::new()
        .with_public(unique, parms)
        .map(|t| t.with_name_alg(name_alg))
}

fn parse_keyedhash(hash_alg: &str) -> Result<TpmPublicTemplate, TpmCryptoError> {
    let name_alg = TpmHash::from_str(hash_alg)
        .map_err(|_| TpmCryptoError::InvalidObjectType)?
        .into();

    let parms = TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
        scheme: TpmtKeyedhashScheme {
            scheme: TpmAlgId::Null,
            details: TpmuKeyedhashScheme::Null,
        },
    });
    let unique = TpmuPublicId::KeyedHash(TpmBuffer::default());

    TpmPublicTemplate::new()
        .with_public(unique, parms)
        .map(|t| t.with_name_alg(name_alg))
}
