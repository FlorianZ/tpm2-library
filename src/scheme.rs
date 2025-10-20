// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use std::{fmt, num::ParseIntError, str::FromStr};
use thiserror::Error;
use tpm2_protocol::data::TpmHt;

#[derive(Debug, Error)]
pub enum SchemeError {
    #[error("invalid scheme: '{0}'")]
    InvalidScheme(String),
    #[error("unsupported scheme: '{0}'")]
    UnsupportedScheme(String),
    #[error("invalid handle format: {0}")]
    InvalidHandleFormat(String),
    #[error("invalid hex format: {0}")]
    InvalidHexFormat(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<ParseIntError> for SchemeError {
    fn from(e: ParseIntError) -> Self {
        Self::InvalidHandleFormat(e.to_string())
    }
}

impl From<hex::FromHexError> for SchemeError {
    fn from(e: hex::FromHexError) -> Self {
        Self::InvalidHexFormat(e.to_string())
    }
}

/// A type-safe representation of a resource identifier.
#[derive(Debug, Clone, PartialEq)]
pub enum Scheme {
    Password(Vec<u8>),
    Path(std::path::PathBuf),
    Policy(Vec<u8>),
    Session(u32),
    Tpm(u32),
    Transient(u32),
}

impl Scheme {
    /// Reads the contents of a file path URI.
    ///
    /// # Errors
    ///
    /// Returns `UriError::Io` on read failure or `UriError::UnsupportedScheme`
    /// if called on a non-Path variant.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        match self {
            Self::Path(path) => Ok(std::fs::read(path)?),
            _ => Err(SchemeError::UnsupportedScheme(self.to_string())),
        }
    }

    /// Extracts the handle from a TPM or Session URI.
    ///
    /// # Errors
    ///
    /// Returns `UriError::UnsupportedScheme` if called on a non-handle variant.
    pub fn to_handle(&self) -> Result<u32, SchemeError> {
        match self {
            Self::Tpm(handle) | Self::Session(handle) => Ok(*handle),
            _ => Err(SchemeError::UnsupportedScheme(self.to_string())),
        }
    }
}

impl FromStr for Scheme {
    type Err = SchemeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((scheme, value)) = s.split_once(':') {
            if s.starts_with('/') || scheme.len() == 1 {
                return Ok(Self::Path(s.into()));
            }
            match scheme {
                "tpm" => {
                    let handle = u32::from_str_radix(value, 16)?;
                    Ok(Self::Tpm(handle))
                }
                "password" => {
                    let bytes = hex::decode(value)?;
                    Ok(Self::Password(bytes))
                }
                "policy" => {
                    let bytes = hex::decode(value)?;
                    Ok(Self::Policy(bytes))
                }
                "vtpm" => {
                    let vhandle = u32::from_str_radix(value, 16)?;
                    let mso = (vhandle >> 24) as u8;
                    if mso == TpmHt::PolicySession as u8 {
                        Ok(Self::Session(vhandle))
                    } else if mso == TpmHt::Transient as u8 {
                        Ok(Self::Transient(vhandle))
                    } else {
                        Err(SchemeError::UnsupportedScheme(s.to_string()))
                    }
                }
                _ => Err(SchemeError::UnsupportedScheme(s.to_string())),
            }
        } else {
            Ok(Self::Path(s.into()))
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tpm(handle) => write!(f, "tpm:{handle:08x}"),
            Self::Transient(vhandle) => write!(f, "vtpm:{vhandle}"),
            Self::Path(path) => write!(f, "{}", path.to_string_lossy()),
            Self::Session(vhandle) => write!(f, "vtpm:{vhandle:08x}"),
            Self::Password(bytes) => write!(f, "password:{}", hex::encode(bytes)),
            Self::Policy(bytes) => write!(f, "policy:{}", hex::encode(bytes)),
        }
    }
}
