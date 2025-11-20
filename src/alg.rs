// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use std::str::FromStr;
use thiserror::Error;
use tpm2_crypto::{TpmEllipticCurve, TpmHash};
use tpm2_protocol::data::{TpmAlgId, TpmEccCurve, TpmtPublic, TpmuPublicParms};
use tpm2_tpmkey::TpmKeyError;

#[derive(Debug, Error)]
pub enum AlgError {
    #[error("unsupported name algorithm: {0}")]
    InvalidAlgorithm(String),
    #[error("invalid algorithm format: '{0}'")]
    InvalidAlgorithmFormat(String),
    #[error("invalid ECC curve: {0}")]
    InvalidEccCurve(String),
    #[error("invalid RSA key bits: {0}")]
    InvalidRsaKeyBits(String),
    #[error("TpmKey: {0}")]
    TpmKey(#[from] TpmKeyError),
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
    pub fn parse_keyedhash(hash_alg: &str) -> Result<Self, AlgError> {
        let name_alg = TpmHash::from_str(hash_alg)
            .map_err(|_| AlgError::InvalidAlgorithm(hash_alg.to_string()))?
            .into();
        Ok(Self {
            name: format!("keyedhash:{hash_alg}"),
            object_type: TpmAlgId::KeyedHash,
            name_alg,
            params: AlgInfo::KeyedHash,
        })
    }

    fn parse_rsa(original: &str, suffix: &str) -> Result<Self, AlgError> {
        let (bits_str, name_alg_str) = suffix
            .split_once(':')
            .ok_or_else(|| AlgError::InvalidAlgorithmFormat(original.to_string()))?;
        let key_bits: u16 = bits_str
            .parse()
            .map_err(|_| AlgError::InvalidRsaKeyBits(bits_str.to_string()))?;
        let name_alg = TpmHash::from_str(name_alg_str)
            .map_err(|_| AlgError::InvalidAlgorithm(name_alg_str.to_string()))?
            .into();
        Ok(Self {
            name: original.to_string(),
            object_type: TpmAlgId::Rsa,
            name_alg,
            params: AlgInfo::Rsa { key_bits },
        })
    }

    fn parse_ecc(original: &str, suffix: &str) -> Result<Self, AlgError> {
        let (curve_str, name_alg_str) = suffix
            .split_once(':')
            .ok_or_else(|| AlgError::InvalidAlgorithmFormat(original.to_string()))?;
        let curve_id: TpmEccCurve = TpmEllipticCurve::from_str(curve_str)
            .map_err(|_| AlgError::InvalidEccCurve(curve_str.to_string()))?
            .into();
        let name_alg = TpmHash::from_str(name_alg_str)
            .map_err(|_| AlgError::InvalidAlgorithm(name_alg_str.to_string()))?
            .into();
        Ok(Self {
            name: original.to_string(),
            object_type: TpmAlgId::Ecc,
            name_alg,
            params: AlgInfo::Ecc { curve_id },
        })
    }
}

impl std::fmt::Display for Alg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl std::str::FromStr for Alg {
    type Err = AlgError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("rsa-") {
            Self::parse_rsa(s, rest)
        } else if let Some(rest) = s.strip_prefix("ecc-") {
            Self::parse_ecc(s, rest)
        } else if let Some(name_alg_str) = s.strip_prefix("keyedhash:") {
            Self::parse_keyedhash(name_alg_str)
        } else {
            Err(AlgError::InvalidAlgorithmFormat(s.to_string()))
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
pub fn alg_details(public: &TpmtPublic) -> String {
    let name_alg_str = TpmHash::from(public.name_alg).to_string();
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
                let curve_str = TpmEllipticCurve::from(params.curve_id).to_string();
                format!("ecc-{curve_str}:{name_alg_str}")
            } else {
                "ecc".to_string()
            }
        }
        TpmAlgId::KeyedHash => format!("keyedhash:{name_alg_str}"),
        _ => TpmHash::from(public.object_type).to_string(),
    }
}
