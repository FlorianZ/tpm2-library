// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use std::{fmt, num::ParseIntError, str::FromStr};
use thiserror::Error;
use tpm2_protocol::{data::TpmHt, TpmHandle};

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

/// A type-safe representation of a specific handle type.
#[derive(Debug, Clone, PartialEq)]
pub enum Handle {
    Session(u32),
    Persistent(u32),
    Transient(u32),
}

impl Handle {
    #[must_use]
    pub fn value_raw(&self) -> u32 {
        match *self {
            Handle::Session(h) | Handle::Persistent(h) | Handle::Transient(h) => h,
        }
    }

    #[must_use]
    pub fn value_tpm(&self) -> TpmHandle {
        TpmHandle(self.value_raw())
    }
}

/// A type-safe representation of a resource identifier.
#[derive(Debug, Clone, PartialEq)]
pub enum Scheme {
    Password(Vec<u8>),
    Path(std::path::PathBuf),
    Policy(Vec<u8>),
    Tpm(Handle),
    Vtpm(Handle),
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
                    let mso = (handle >> 24) as u8;
                    let handle_type = if mso == TpmHt::Persistent as u8 {
                        Handle::Persistent(handle)
                    } else if mso == TpmHt::Transient as u8 {
                        Handle::Transient(handle)
                    } else {
                        return Err(SchemeError::UnsupportedScheme(s.to_string()));
                    };
                    Ok(Self::Tpm(handle_type))
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
                    let handle_type = if mso == TpmHt::PolicySession as u8 {
                        Handle::Session(vhandle)
                    } else if mso == TpmHt::Transient as u8 {
                        Handle::Transient(vhandle)
                    } else {
                        return Err(SchemeError::UnsupportedScheme(s.to_string()));
                    };
                    Ok(Self::Vtpm(handle_type))
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
            Self::Tpm(handle) => match handle {
                Handle::Persistent(h) | Handle::Transient(h) => write!(f, "tpm:{h:08x}"),
                Handle::Session(_) => write!(f, "tpm:<invalid-session>"),
            },
            Self::Vtpm(handle) => match handle {
                Handle::Transient(h) | Handle::Session(h) => write!(f, "vtpm:{h:08x}"),
                Handle::Persistent(_) => write!(f, "vtpm:<invalid-persistent>"),
            },
            Self::Path(path) => write!(f, "{}", path.to_string_lossy()),
            Self::Password(bytes) => write!(f, "password:{}", hex::encode(bytes)),
            Self::Policy(bytes) => write!(f, "policy:{}", hex::encode(bytes)),
        }
    }
}
