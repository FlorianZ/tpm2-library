// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use std::{fmt, num::ParseIntError, str::FromStr};
use thiserror::Error;
use tpm2_protocol::data::TpmHt;

#[derive(Debug, Error)]
pub enum UriError {
    #[error("invalid URI format: '{0}'")]
    InvalidFormat(String),
    #[error("unsupported URI scheme: '{0}'")]
    UnsupportedScheme(String),
    #[error("invalid handle format: {0}")]
    InvalidHandleFormat(String),
    #[error("invalid hex format: {0}")]
    InvalidHexFormat(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<ParseIntError> for UriError {
    fn from(e: ParseIntError) -> Self {
        Self::InvalidHandleFormat(e.to_string())
    }
}

impl From<hex::FromHexError> for UriError {
    fn from(e: hex::FromHexError) -> Self {
        Self::InvalidHexFormat(e.to_string())
    }
}

/// A type-safe representation of a resource identifier.
#[derive(Debug, Clone, PartialEq)]
pub enum Uri {
    Tpm(u32),
    Key(u32),
    Path(std::path::PathBuf),
    Session(u32),
    Password(Vec<u8>),
    Policy(Vec<u8>),
}

impl Uri {
    /// Reads the contents of a file path URI.
    ///
    /// # Errors
    ///
    /// Returns `UriError::Io` on read failure or `UriError::UnsupportedScheme`
    /// if called on a non-Path variant.
    pub fn to_bytes(&self) -> Result<Vec<u8>, UriError> {
        match self {
            Self::Path(path) => Ok(std::fs::read(path)?),
            _ => Err(UriError::UnsupportedScheme(self.to_string())),
        }
    }

    /// Extracts the handle from a TPM or Session URI.
    ///
    /// # Errors
    ///
    /// Returns `UriError::UnsupportedScheme` if called on a non-handle variant.
    pub fn to_handle(&self) -> Result<u32, UriError> {
        match self {
            Self::Tpm(handle) | Self::Session(handle) => Ok(*handle),
            _ => Err(UriError::UnsupportedScheme(self.to_string())),
        }
    }
}

impl FromStr for Uri {
    type Err = UriError;

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
                        Ok(Self::Key(vhandle))
                    } else {
                        Err(UriError::UnsupportedScheme(s.to_string()))
                    }
                }
                _ => Err(UriError::UnsupportedScheme(s.to_string())),
            }
        } else {
            Ok(Self::Path(s.into()))
        }
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tpm(handle) => write!(f, "tpm:{handle:08x}"),
            Self::Key(vhandle) => write!(f, "vtpm:{vhandle}"),
            Self::Path(path) => write!(f, "{}", path.to_string_lossy()),
            Self::Session(vhandle) => write!(f, "vtpm:{vhandle:08x}"),
            Self::Password(bytes) => write!(f, "password:{}", hex::encode(bytes)),
            Self::Policy(bytes) => write!(f, "policy:{}", hex::encode(bytes)),
        }
    }
}
