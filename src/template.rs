// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! TPM 2.0 public key templates.

use crate::{TpmCryptoError, TpmEllipticCurve, TpmHash};
use std::str::FromStr;
use tpm2_protocol::{
    basic::TpmBuffer,
    data::{
        Tpm2bDigest, TpmAlgId, TpmEccCurve, TpmaObject, TpmsEccParms, TpmsKeyedhashParms,
        TpmsRsaParms, TpmtEccScheme, TpmtKdfScheme, TpmtKeyedhashScheme, TpmtPublic, TpmtRsaScheme,
        TpmtSymDefObject, TpmuKeyedhashScheme, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits,
        TpmuSymMode,
    },
};

/// The specific kind of public key or object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmPublicTemplateType {
    Rsa { key_bits: u16 },
    Ecc { curve_id: TpmEccCurve },
    KeyedHash,
}

/// A template describing a TPM public area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmPublicTemplate {
    pub name: String,
    pub hash: TpmAlgId,
    pub kind: TpmPublicTemplateType,
}

impl TpmPublicTemplate {
    /// Creates a new template for an RSA object.
    #[must_use]
    pub fn new_rsa(key_bits: u16, name_alg: TpmAlgId) -> Self {
        let name_alg_str = TpmHash::from(name_alg).to_string();
        Self {
            name: format!("rsa-{key_bits}:{name_alg_str}"),
            hash: name_alg,
            kind: TpmPublicTemplateType::Rsa { key_bits },
        }
    }

    /// Creates a new template for an ECC object.
    #[must_use]
    pub fn new_ecc(curve_id: TpmEccCurve, name_alg: TpmAlgId) -> Self {
        let curve_str = TpmEllipticCurve::from(curve_id).to_string();
        let name_alg_str = TpmHash::from(name_alg).to_string();
        Self {
            name: format!("ecc-{curve_str}:{name_alg_str}"),
            hash: name_alg,
            kind: TpmPublicTemplateType::Ecc { curve_id },
        }
    }

    /// Creates a new template for a `KeyedHash` object.
    #[must_use]
    pub fn new_keyedhash(name_alg: TpmAlgId) -> Self {
        let name_alg_str = TpmHash::from(name_alg).to_string();
        Self {
            name: format!("keyedhash:{name_alg_str}"),
            hash: name_alg,
            kind: TpmPublicTemplateType::KeyedHash,
        }
    }

    /// Returns the `TpmAlgId` matching the key type.
    #[must_use]
    pub fn alg_id(&self) -> TpmAlgId {
        match self.kind {
            TpmPublicTemplateType::Ecc { .. } => TpmAlgId::Ecc,
            TpmPublicTemplateType::Rsa { .. } => TpmAlgId::Rsa,
            TpmPublicTemplateType::KeyedHash => TpmAlgId::KeyedHash,
        }
    }

    /// Constructs a `TpmtPublic` structure from this template.
    #[must_use]
    pub fn to_public(&self, auth_policy: Tpm2bDigest, object_attributes: TpmaObject) -> TpmtPublic {
        let symmetric = TpmtSymDefObject {
            algorithm: TpmAlgId::Aes,
            key_bits: TpmuSymKeyBits::Aes(128),
            mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
        };

        let (parameters, unique) = match self.kind {
            TpmPublicTemplateType::Rsa { key_bits } => (
                TpmuPublicParms::Rsa(TpmsRsaParms {
                    symmetric,
                    scheme: TpmtRsaScheme::default(),
                    key_bits,
                    exponent: 0,
                }),
                TpmuPublicId::Rsa(TpmBuffer::default()),
            ),
            TpmPublicTemplateType::Ecc { curve_id } => (
                TpmuPublicParms::Ecc(TpmsEccParms {
                    symmetric,
                    scheme: TpmtEccScheme::default(),
                    curve_id,
                    kdf: TpmtKdfScheme::default(),
                }),
                TpmuPublicId::Ecc(tpm2_protocol::data::TpmsEccPoint::default()),
            ),
            TpmPublicTemplateType::KeyedHash => (
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
            object_type: self.alg_id(),
            name_alg: self.hash,
            object_attributes,
            auth_policy,
            parameters,
            unique,
        }
    }

    fn parse_keyedhash(hash_alg: &str) -> Result<Self, TpmCryptoError> {
        let name_alg = TpmHash::from_str(hash_alg)
            .map_err(|_| TpmCryptoError::InvalidObjectType)?
            .into();
        Ok(Self::new_keyedhash(name_alg))
    }

    fn parse_rsa(suffix: &str) -> Result<Self, TpmCryptoError> {
        let (bits_str, name_alg_str) = suffix
            .split_once(':')
            .ok_or(TpmCryptoError::InvalidObjectType)?;
        let key_bits: u16 = bits_str
            .parse()
            .map_err(|_| TpmCryptoError::InvalidObjectType)?;
        let name_alg = TpmHash::from_str(name_alg_str)
            .map_err(|_| TpmCryptoError::InvalidObjectType)?
            .into();
        Ok(Self::new_rsa(key_bits, name_alg))
    }

    fn parse_ecc(suffix: &str) -> Result<Self, TpmCryptoError> {
        let (curve_str, name_alg_str) = suffix
            .split_once(':')
            .ok_or(TpmCryptoError::InvalidObjectType)?;
        let curve_id: TpmEccCurve = TpmEllipticCurve::from_str(curve_str)
            .map_err(|_| TpmCryptoError::InvalidObjectType)?
            .into();
        let name_alg = TpmHash::from_str(name_alg_str)
            .map_err(|_| TpmCryptoError::InvalidObjectType)?
            .into();
        Ok(Self::new_ecc(curve_id, name_alg))
    }
}

impl std::fmt::Display for TpmPublicTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl FromStr for TpmPublicTemplate {
    type Err = TpmCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("rsa-") {
            Self::parse_rsa(rest)
        } else if let Some(rest) = s.strip_prefix("ecc-") {
            Self::parse_ecc(rest)
        } else if let Some(name_alg_str) = s.strip_prefix("keyedhash:") {
            Self::parse_keyedhash(name_alg_str)
        } else {
            Err(TpmCryptoError::InvalidObjectType)
        }
    }
}

impl TryFrom<&TpmtPublic> for TpmPublicTemplate {
    type Error = TpmCryptoError;

    fn try_from(public: &TpmtPublic) -> Result<Self, Self::Error> {
        match public.object_type {
            TpmAlgId::Rsa => {
                if let TpmuPublicParms::Rsa(params) = &public.parameters {
                    Ok(TpmPublicTemplate::new_rsa(params.key_bits, public.name_alg))
                } else {
                    Err(TpmCryptoError::InvalidRsaParameters)
                }
            }
            TpmAlgId::Ecc => {
                if let TpmuPublicParms::Ecc(params) = &public.parameters {
                    Ok(TpmPublicTemplate::new_ecc(params.curve_id, public.name_alg))
                } else {
                    Err(TpmCryptoError::InvalidEccParameters)
                }
            }
            TpmAlgId::KeyedHash => Ok(TpmPublicTemplate::new_keyedhash(public.name_alg)),
            _ => Err(TpmCryptoError::InvalidObjectType),
        }
    }
}

impl std::cmp::Ord for TpmPublicTemplate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

impl std::cmp::PartialOrd for TpmPublicTemplate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
