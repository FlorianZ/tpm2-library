//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

#![allow(clippy::no_effect_underscore_binding)]

pub mod ecc;
pub mod rsa;

pub use ecc::ecc_to_public_id;
pub use rsa::rsa_to_public_id;

use openssl::error::ErrorStack;
use std::num::TryFromIntError;
use strum::{Display, EnumString};
use thiserror::Error;
use tpm2_protocol::{
    data::{TpmAlgId, TpmEccCurve, TpmtPublic, TpmuPublicParms},
    TpmMarshalError, TpmUnmarshalError,
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
    #[error("hex decode: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("int decode: {0}")]
    IntDecode(#[from] TryFromIntError),
    #[error("tpm key: {0}")]
    TpmKey(#[from] TpmKeyError),
    #[error("openssl: {0}")]
    Openssl(#[from] ErrorStack),
    #[error("protocol marshal: {0}")]
    ProtocolMarshal(tpm2_protocol::TpmMarshalError),
    #[error("protocol unmarshal: {0}")]
    ProtocolUnmarshal(tpm2_protocol::TpmUnmarshalError),
}

impl From<TpmMarshalError> for KeyError {
    fn from(err: TpmMarshalError) -> Self {
        Self::ProtocolMarshal(err)
    }
}

impl From<TpmUnmarshalError> for KeyError {
    fn from(err: TpmUnmarshalError) -> Self {
        Self::ProtocolUnmarshal(err)
    }
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
        let name_alg = Tpm2shAlgId::try_from(hash_alg)?.0;
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
            let name_alg = Tpm2shAlgId::try_from(name_alg_str)?.0;
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
            let curve_id: TpmEccCurve = Tpm2shEccCurve::from_str(curve_str)
                .map_err(|e| KeyError::InvalidEccCurve(e.to_string()))?
                .into();
            let name_alg = Tpm2shAlgId::try_from(name_alg_str)?.0;
            Ok(Self {
                name: s.to_string(),
                object_type: TpmAlgId::Ecc,
                name_alg,
                params: AlgInfo::Ecc { curve_id },
            })
        } else if let Some(name_alg_str) = s.strip_prefix("keyedhash:") {
            let name_alg = Tpm2shAlgId::try_from(name_alg_str)?.0;
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

/// A newtype wrapper to provide a project-specific `Display` implementation for `TpmAlgId`.
#[derive(Debug, Clone, Copy)]
pub struct Tpm2shAlgId(pub TpmAlgId);

impl TryFrom<&str> for Tpm2shAlgId {
    type Error = KeyError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let alg_id = match s {
            "rsa" => TpmAlgId::Rsa,
            "sha1" => TpmAlgId::Sha1,
            "hmac" => TpmAlgId::Hmac,
            "aes" => TpmAlgId::Aes,
            "keyedhash" => TpmAlgId::KeyedHash,
            "xor" => TpmAlgId::Xor,
            "sha256" => TpmAlgId::Sha256,
            "sha384" => TpmAlgId::Sha384,
            "sha512" => TpmAlgId::Sha512,
            "null" => TpmAlgId::Null,
            "sm3_256" => TpmAlgId::Sm3_256,
            "sm4" => TpmAlgId::Sm4,
            "ecc" => TpmAlgId::Ecc,
            _ => return Err(KeyError::InvalidAlgorithm(s.to_string())),
        };
        Ok(Self(alg_id))
    }
}

impl std::fmt::Display for Tpm2shAlgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self.0 {
            TpmAlgId::Sha1 => "sha1",
            TpmAlgId::Sha256 => "sha256",
            TpmAlgId::Sha384 => "sha384",
            TpmAlgId::Sha512 => "sha512",
            TpmAlgId::Rsa => "rsa",
            TpmAlgId::Hmac => "hmac",
            TpmAlgId::Aes => "aes",
            TpmAlgId::KeyedHash => "keyedhash",
            TpmAlgId::Xor => "xor",
            TpmAlgId::Null => "null",
            TpmAlgId::Sm3_256 => "sm3_256",
            TpmAlgId::Sm4 => "sm4",
            TpmAlgId::Ecc => "ecc",
            _ => "unknown",
        };
        write!(f, "{s}")
    }
}

/// A local wrapper enum for `TpmEccCurve` to allow `strum` derives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display)]
#[strum(serialize_all = "kebab-case")]
pub enum Tpm2shEccCurve {
    NistP192,
    NistP224,
    NistP256,
    NistP384,
    NistP521,
    BnP256,
    BnP638,
    Sm2P256,
    #[strum(serialize = "bp-p256-r1")]
    BpP256R1,
    #[strum(serialize = "bp-p384-r1")]
    BpP384R1,
    #[strum(serialize = "bp-p512-r1")]
    BpP512R1,
    Curve25519,
    Curve448,
    None,
}

impl From<TpmEccCurve> for Tpm2shEccCurve {
    fn from(curve: TpmEccCurve) -> Self {
        match curve {
            TpmEccCurve::NistP192 => Self::NistP192,
            TpmEccCurve::NistP224 => Self::NistP224,
            TpmEccCurve::NistP256 => Self::NistP256,
            TpmEccCurve::NistP384 => Self::NistP384,
            TpmEccCurve::NistP521 => Self::NistP521,
            TpmEccCurve::BnP256 => Self::BnP256,
            TpmEccCurve::BnP638 => Self::BnP638,
            TpmEccCurve::Sm2P256 => Self::Sm2P256,
            TpmEccCurve::BpP256R1 => Self::BpP256R1,
            TpmEccCurve::BpP384R1 => Self::BpP384R1,
            TpmEccCurve::BpP512R1 => Self::BpP512R1,
            TpmEccCurve::Curve25519 => Self::Curve25519,
            TpmEccCurve::Curve448 => Self::Curve448,
            TpmEccCurve::None => Self::None,
        }
    }
}

impl From<Tpm2shEccCurve> for TpmEccCurve {
    fn from(curve: Tpm2shEccCurve) -> Self {
        match curve {
            Tpm2shEccCurve::NistP192 => Self::NistP192,
            Tpm2shEccCurve::NistP224 => Self::NistP224,
            Tpm2shEccCurve::NistP256 => Self::NistP256,
            Tpm2shEccCurve::NistP384 => Self::NistP384,
            Tpm2shEccCurve::NistP521 => Self::NistP521,
            Tpm2shEccCurve::BnP256 => Self::BnP256,
            Tpm2shEccCurve::BnP638 => Self::BnP638,
            Tpm2shEccCurve::Sm2P256 => Self::Sm2P256,
            Tpm2shEccCurve::BpP256R1 => Self::BpP256R1,
            Tpm2shEccCurve::BpP384R1 => Self::BpP384R1,
            Tpm2shEccCurve::BpP512R1 => Self::BpP512R1,
            Tpm2shEccCurve::Curve25519 => Self::Curve25519,
            Tpm2shEccCurve::Curve448 => Self::Curve448,
            Tpm2shEccCurve::None => Self::None,
        }
    }
}

/// Formats a human-readable algorithm string from a `TpmtPublic` structure.
#[must_use]
pub fn format_alg_from_public(public: &TpmtPublic) -> String {
    let name_alg_str = Tpm2shAlgId(public.name_alg).to_string();
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
                let curve_str = Tpm2shEccCurve::from(params.curve_id).to_string();
                format!("ecc-{curve_str}:{name_alg_str}")
            } else {
                "ecc".to_string()
            }
        }
        TpmAlgId::KeyedHash => format!("keyedhash:{name_alg_str}"),
        _ => Tpm2shAlgId(public.object_type).to_string(),
    }
}
