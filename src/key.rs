//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::no_effect_underscore_binding)]

use openssl::error::ErrorStack;
use std::num::TryFromIntError;
use std::str::FromStr;
use thiserror::Error;
use tpm2_crypto::{EccCurve, EccPublicKey, Error as CryptoError, Hash, RsaPublicKey};
use tpm2_protocol::{
    data::{
        Tpm2bDigest, Tpm2bPublicKeyRsa, TpmAlgId, TpmEccCurve, TpmaObject, TpmsEccParms,
        TpmsRsaParms, TpmsSchemeHash, TpmtEccScheme, TpmtKdfScheme, TpmtPublic, TpmtRsaScheme,
        TpmtSymDefObject, TpmuAsymScheme, TpmuPublicId, TpmuPublicParms,
    },
    TpmProtocolError,
};
use tpm2_tpmkey::Error as TpmKeyError;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("capacity exceeded")]
    CapacityExceeded,
    #[error("unsupported name algorithm: {0}")]
    InvalidAlgorithm(String),
    #[error("invalid algorithm format: '{0}'")]
    InvalidAlgorithmFormat(String),
    #[error("invalid ECC curve: {0}")]
    InvalidEccCurve(String),
    #[error("invalid ECC point: {0}")]
    InvalidEccPoint(String),
    #[error("invalid key format")]
    InvalidFormat,
    #[error("invalid RSA exponent")]
    InvalidRsaExponent,
    #[error("invalid RSA key bits: {0}")]
    InvalidRsaKeyBits(String),
    #[error("unsupported file format")]
    UnsupportedFileFormat,
    #[error("unsupported OID: {0}")]
    UnsupportedOid(String),
    #[error("unsupported PEM tag: {0}")]
    UnsupportedPemTag(String),
    #[error("value conversion failed: {0}")]
    ValueConversionFailed(String),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("hex decode: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("int decode: {0}")]
    IntDecode(#[from] TryFromIntError),
    #[error("tpm key: {0}")]
    TpmKey(#[from] TpmKeyError),
    #[error("openssl: {0}")]
    Openssl(#[from] ErrorStack),
    #[error("protocol: {0}")]
    Protocol(#[from] TpmProtocolError),
}

/// Converts an `RsaPublicKey` to a `TpmtPublic` structure.
///
/// # Errors
///
/// Returns a `KeyError` if the key's public modulus cannot be converted to the
/// `Tpm2bPublicKeyRsa` type.
pub fn rsa_to_public(
    rsa_key: &RsaPublicKey,
    hash_alg: TpmAlgId,
    symmetric: TpmtSymDefObject,
    key_bits: u16,
) -> Result<tpm2_protocol::data::TpmtPublic, KeyError> {
    Ok(tpm2_protocol::data::TpmtPublic {
        object_type: TpmAlgId::Rsa,
        name_alg: hash_alg,
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parameters: TpmuPublicParms::Rsa(TpmsRsaParms {
            symmetric,
            scheme: TpmtRsaScheme {
                scheme: TpmAlgId::Oaep,
                details: TpmuAsymScheme::Any(TpmsSchemeHash { hash_alg }),
            },
            key_bits,
            exponent: 0,
        }),
        unique: TpmuPublicId::Rsa(
            Tpm2bPublicKeyRsa::try_from(rsa_key.n.as_ref())
                .map_err(|_| KeyError::CapacityExceeded)?,
        ),
    })
}

/// Converts ECC public key bytes to a `TpmtPublic` structure.
///
/// # Errors
///
/// Returns a `KeyError` if the public key bytes do not represent a valid
/// uncompressed ECC point or if conversion to TPM types fails.
pub fn ecc_to_public(
    ecc_key: &EccPublicKey,
    hash_alg: TpmAlgId,
    symmetric: TpmtSymDefObject,
) -> Result<TpmtPublic, KeyError> {
    Ok(TpmtPublic {
        object_type: TpmAlgId::Ecc,
        name_alg: hash_alg,
        object_attributes: TpmaObject::USER_WITH_AUTH | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::default(),
        parameters: TpmuPublicParms::Ecc(TpmsEccParms {
            symmetric,
            scheme: TpmtEccScheme {
                scheme: TpmAlgId::Ecdh,
                details: TpmuAsymScheme::Any(tpm2_protocol::data::TpmsSchemeHash { hash_alg }),
            },
            curve_id: ecc_key.curve.into(),
            kdf: TpmtKdfScheme::default(),
        }),
        unique: TpmuPublicId::Ecc(tpm2_protocol::data::TpmsEccPoint {
            x: ecc_key.x,
            y: ecc_key.y,
        }),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgInfo {
    Rsa { key_bits: u16 },
    Ecc { curve_id: TpmEccCurve },
    KeyedHash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alg {
    pub name: String,
    pub object_type: TpmAlgId,
    pub name_alg: TpmAlgId,
    pub params: AlgInfo,
}

impl Alg {
    /// Creates a new `Alg` struct for a `KeyedHash` object.
    ///
    /// # Errors
    ///
    /// Returns an `KeyError` if the provided hash algorithm string is invalid.
    pub fn new_keyedhash(hash_alg: &str) -> Result<Self, KeyError> {
        let name_alg = Hash::from_str(hash_alg)
            .map_err(|_| KeyError::InvalidAlgorithm(hash_alg.to_string()))?
            .into();
        Ok(Self {
            name: format!("keyedhash:{hash_alg}"),
            object_type: TpmAlgId::KeyedHash,
            name_alg,
            params: AlgInfo::KeyedHash,
        })
    }
}

impl std::fmt::Display for Alg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl std::str::FromStr for Alg {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("rsa-") {
            let (bits_str, name_alg_str) = rest
                .split_once(':')
                .ok_or_else(|| KeyError::InvalidAlgorithmFormat(s.to_string()))?;
            let key_bits: u16 = bits_str
                .parse()
                .map_err(|_| KeyError::InvalidRsaKeyBits(bits_str.to_string()))?;
            let name_alg = Hash::from_str(name_alg_str)
                .map_err(|_| KeyError::InvalidAlgorithm(name_alg_str.to_string()))?
                .into();
            Ok(Self {
                name: s.to_string(),
                object_type: TpmAlgId::Rsa,
                name_alg,
                params: AlgInfo::Rsa { key_bits },
            })
        } else if let Some(rest) = s.strip_prefix("ecc-") {
            let (curve_str, name_alg_str) = rest
                .split_once(':')
                .ok_or_else(|| KeyError::InvalidAlgorithmFormat(s.to_string()))?;
            let curve_id: TpmEccCurve = EccCurve::from_str(curve_str)
                .map_err(|_| KeyError::InvalidEccCurve(curve_str.to_string()))?
                .into();
            let name_alg = Hash::from_str(name_alg_str)
                .map_err(|_| KeyError::InvalidAlgorithm(name_alg_str.to_string()))?
                .into();
            Ok(Self {
                name: s.to_string(),
                object_type: TpmAlgId::Ecc,
                name_alg,
                params: AlgInfo::Ecc { curve_id },
            })
        } else if let Some(name_alg_str) = s.strip_prefix("keyedhash:") {
            let name_alg = Hash::from_str(name_alg_str)
                .map_err(|_| KeyError::InvalidAlgorithm(name_alg_str.to_string()))?
                .into();
            Ok(Self {
                name: s.to_string(),
                object_type: TpmAlgId::KeyedHash,
                name_alg,
                params: AlgInfo::KeyedHash,
            })
        } else {
            Err(KeyError::InvalidAlgorithmFormat(s.to_string()))
        }
    }
}

impl std::cmp::Ord for Alg {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

impl std::cmp::PartialOrd for Alg {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Formats a human-readable algorithm string from a `TpmtPublic` structure.
#[must_use]
pub fn format_alg_from_public(public: &TpmtPublic) -> String {
    let name_alg_str = Hash::from(public.name_alg).to_string();
    match public.object_type {
        TpmAlgId::Rsa => {
            if let TpmuPublicParms::Rsa(params) = &public.parameters {
                format!("rsa-{}:{}", params.key_bits, name_alg_str)
            } else {
                "rsa".to_string()
            }
        }
        TpmAlgId::Ecc => {
            if let TpmuPublicParms::Ecc(params) = &public.parameters {
                let curve_str = EccCurve::from(params.curve_id).to_string();
                format!("ecc-{curve_str}:{name_alg_str}")
            } else {
                "ecc".to_string()
            }
        }
        TpmAlgId::KeyedHash => format!("keyedhash:{name_alg_str}"),
        _ => Hash::from(public.object_type).to_string(),
    }
}
