// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use std::str::FromStr;
use thiserror::Error;
use tpm2_crypto::{TpmEllipticCurve, TpmHash};
use tpm2_protocol::data::{TpmAlgId, TpmEccCurve, TpmtPublic, TpmuPublicParms};

#[derive(Debug, Error)]
pub enum AlgError {
    #[error("invalid hash algorithm: {0}")]
    InvalidHashAlgorithm(String),
    #[error("invalid algorithm: '{0}'")]
    InvalidKeyAlgorithm(String),
    #[error("invalid ECC curve: {0}")]
    InvalidEccCurve(String),
    #[error("invalid public area: {0}")]
    InvalidPublicArea(&'static str),
    #[error("invalid RSA key bits: {0}")]
    InvalidRsaKeyBits(String),
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
    pub hash: TpmAlgId,
    pub kind: AlgInfo,
}

impl Alg {
    /// Creates a new `Alg` struct for an RSA object.
    #[must_use]
    pub fn new_rsa(key_bits: u16, name_alg: TpmAlgId) -> Self {
        let name_alg_str = TpmHash::from(name_alg).to_string();
        Self {
            name: format!("rsa-{key_bits}:{name_alg_str}"),
            hash: name_alg,
            kind: AlgInfo::Rsa { key_bits },
        }
    }

    /// Creates a new `Alg` struct for an ECC object.
    #[must_use]
    pub fn new_ecc(curve_id: TpmEccCurve, name_alg: TpmAlgId) -> Self {
        let curve_str = TpmEllipticCurve::from(curve_id).to_string();
        let name_alg_str = TpmHash::from(name_alg).to_string();
        Self {
            name: format!("ecc-{curve_str}:{name_alg_str}"),
            hash: name_alg,
            kind: AlgInfo::Ecc { curve_id },
        }
    }

    /// Creates a new `Alg` struct for a `KeyedHash` object.
    #[must_use]
    pub fn new_keyedhash(name_alg: TpmAlgId) -> Self {
        let name_alg_str = TpmHash::from(name_alg).to_string();
        Self {
            name: format!("keyedhash:{name_alg_str}"),
            hash: name_alg,
            kind: AlgInfo::KeyedHash,
        }
    }

    /// Return `TpmAlgId` matching to the key type.
    #[must_use]
    pub fn alg_id(&self) -> TpmAlgId {
        match self.kind {
            AlgInfo::Ecc { .. } => TpmAlgId::Ecc,
            AlgInfo::Rsa { .. } => TpmAlgId::Rsa,
            AlgInfo::KeyedHash => TpmAlgId::KeyedHash,
        }
    }

    fn parse_keyedhash(hash_alg: &str) -> Result<Self, AlgError> {
        let name_alg = TpmHash::from_str(hash_alg)
            .map_err(|_| AlgError::InvalidHashAlgorithm(hash_alg.to_string()))?
            .into();
        Ok(Self::new_keyedhash(name_alg))
    }

    fn parse_rsa(original: &str, suffix: &str) -> Result<Self, AlgError> {
        let (bits_str, name_alg_str) = suffix
            .split_once(':')
            .ok_or_else(|| AlgError::InvalidKeyAlgorithm(original.to_string()))?;
        let key_bits: u16 = bits_str
            .parse()
            .map_err(|_| AlgError::InvalidRsaKeyBits(bits_str.to_string()))?;
        let name_alg = TpmHash::from_str(name_alg_str)
            .map_err(|_| AlgError::InvalidHashAlgorithm(name_alg_str.to_string()))?
            .into();
        Ok(Self::new_rsa(key_bits, name_alg))
    }

    fn parse_ecc(original: &str, suffix: &str) -> Result<Self, AlgError> {
        let (curve_str, name_alg_str) = suffix
            .split_once(':')
            .ok_or_else(|| AlgError::InvalidKeyAlgorithm(original.to_string()))?;
        let curve_id: TpmEccCurve = TpmEllipticCurve::from_str(curve_str)
            .map_err(|_| AlgError::InvalidEccCurve(curve_str.to_string()))?
            .into();
        let name_alg = TpmHash::from_str(name_alg_str)
            .map_err(|_| AlgError::InvalidHashAlgorithm(name_alg_str.to_string()))?
            .into();
        Ok(Self::new_ecc(curve_id, name_alg))
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
            Err(AlgError::InvalidKeyAlgorithm(s.to_string()))
        }
    }
}

impl TryFrom<&TpmtPublic> for Alg {
    type Error = AlgError;

    fn try_from(public: &TpmtPublic) -> Result<Self, Self::Error> {
        match public.object_type {
            TpmAlgId::Rsa => {
                if let TpmuPublicParms::Rsa(params) = &public.parameters {
                    Ok(Alg::new_rsa(params.key_bits, public.name_alg))
                } else {
                    Err(AlgError::InvalidPublicArea("rsa"))
                }
            }
            TpmAlgId::Ecc => {
                if let TpmuPublicParms::Ecc(params) = &public.parameters {
                    Ok(Alg::new_ecc(params.curve_id, public.name_alg))
                } else {
                    Err(AlgError::InvalidPublicArea("ecc"))
                }
            }
            TpmAlgId::KeyedHash => Ok(Alg::new_keyedhash(public.name_alg)),
            _ => Err(AlgError::InvalidPublicArea("keyedhash")),
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
