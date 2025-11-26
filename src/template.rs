// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! TPM 2.0 public key templates.

use crate::{TpmCryptoError, TpmEllipticCurve, TpmHash};
use std::str::FromStr;
use tpm2_protocol::{
    basic::{TpmBuffer, Uint16, Uint32},
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
    pub object_type: TpmAlgId,
    pub name_alg: TpmAlgId,
    pub key_bits: Option<u16>,
    pub curve_id: Option<TpmEccCurve>,
}

impl TpmPublicTemplate {
    /// Creates a new template for an RSA object.
    #[must_use]
    pub const fn new_rsa(key_bits: u16, name_alg: TpmAlgId) -> Self {
        Self {
            object_type: TpmAlgId::Rsa,
            name_alg,
            key_bits: Some(key_bits),
            curve_id: None,
        }
    }

    /// Creates a new template for an ECC object.
    #[must_use]
    pub const fn new_ecc(curve_id: TpmEccCurve, name_alg: TpmAlgId) -> Self {
        Self {
            object_type: TpmAlgId::Ecc,
            name_alg,
            key_bits: None,
            curve_id: Some(curve_id),
        }
    }

    /// Creates a new template for a `KeyedHash` object.
    #[must_use]
    pub const fn new_keyedhash(name_alg: TpmAlgId) -> Self {
        Self {
            object_type: TpmAlgId::KeyedHash,
            name_alg,
            key_bits: None,
            curve_id: None,
        }
    }

    /// Returns the template identifier name.
    #[must_use]
    pub fn name(&self) -> String {
        let name_alg_str = TpmHash::from(self.name_alg).to_string();
        match self.object_type {
            TpmAlgId::Rsa => {
                let key_bits = self.key_bits.unwrap_or(2048);
                format!("rsa-{key_bits}:{name_alg_str}")
            }
            TpmAlgId::Ecc => {
                let curve = self.curve_id.unwrap_or(TpmEccCurve::NistP256);
                let curve_str = TpmEllipticCurve::from(curve).to_string();
                format!("ecc-{curve_str}:{name_alg_str}")
            }
            TpmAlgId::KeyedHash => format!("keyedhash:{name_alg_str}"),
            _ => format!("unknown:{name_alg_str}"),
        }
    }

    /// Returns the object type.
    #[must_use]
    pub fn object_type(&self) -> TpmAlgId {
        self.object_type
    }

    /// Returns the curve ID, if applicable.
    #[must_use]
    pub fn curve_id(&self) -> Option<TpmEccCurve> {
        self.curve_id
    }

    /// Returns the key bits, if applicable.
    #[must_use]
    pub fn key_bits(&self) -> Option<u16> {
        self.key_bits
    }

    /// Constructs a `TpmtPublic` structure from this template.
    #[must_use]
    pub fn to_public(&self, auth_policy: Tpm2bDigest, object_attributes: TpmaObject) -> TpmtPublic {
        let symmetric = TpmtSymDefObject {
            algorithm: TpmAlgId::Aes,
            key_bits: TpmuSymKeyBits::Aes(Uint16::from(128)),
            mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
        };

        let (parameters, unique) = match self.object_type {
            TpmAlgId::Rsa => (
                TpmuPublicParms::Rsa(TpmsRsaParms {
                    symmetric,
                    scheme: TpmtRsaScheme::default(),
                    key_bits: Uint16::from(self.key_bits.unwrap_or(2048)),
                    exponent: Uint32::from(0),
                }),
                TpmuPublicId::Rsa(TpmBuffer::default()),
            ),
            TpmAlgId::Ecc => (
                TpmuPublicParms::Ecc(TpmsEccParms {
                    symmetric,
                    scheme: TpmtEccScheme::default(),
                    curve_id: self.curve_id.unwrap_or(TpmEccCurve::NistP256),
                    kdf: TpmtKdfScheme::default(),
                }),
                TpmuPublicId::Ecc(tpm2_protocol::data::TpmsEccPoint::default()),
            ),
            _ => (
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
            object_type: self.object_type,
            name_alg: self.name_alg,
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
        write!(f, "{}", self.name())
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
