// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use std::{fmt, num::ParseIntError, str::FromStr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UriError {
    #[error("unsupported URI scheme: '{0}'")]
    UnsupportedScheme(String),
    #[error("invalid handle format: {0}")]
    ParseHandle(#[from] ParseIntError),
    #[error("invalid context grip format: '{0}'")]
    InvalidGripFormat(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("operation not valid for this URI type")]
    InvalidUriType,
}

/// A type-safe representation of a resource identifier.
#[derive(Debug, Clone, PartialEq)]
pub enum Uri {
    Tpm(u32),
    Key(String),
    Path(std::path::PathBuf),
    Session(u32),
}

impl Uri {
    /// Checks if the URI variant can be used as a parent object.
    #[must_use]
    pub fn is_parent(&self) -> bool {
        matches!(self, Self::Tpm(_) | Self::Key(_) | Self::Path(_))
    }

    /// Reads the contents of a file path URI.
    ///
    /// # Errors
    ///
    /// Returns `UriError::Io` on read failure or `UriError::InvalidUriType`
    /// if called on a non-Path variant.
    pub fn to_bytes(&self) -> Result<Vec<u8>, UriError> {
        match self {
            Self::Path(path) => Ok(std::fs::read(path)?),
            _ => Err(UriError::InvalidUriType),
        }
    }

    /// Extracts the handle from a TPM or Session URI.
    ///
    /// # Errors
    ///
    /// Returns `UriError::InvalidUriType` if called on a non-handle variant.
    pub fn to_handle(&self) -> Result<u32, UriError> {
        match self {
            Self::Tpm(handle) | Self::Session(handle) => Ok(*handle),
            _ => Err(UriError::InvalidUriType),
        }
    }
}

impl FromStr for Uri {
    type Err = UriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(handle_str) = s.strip_prefix("tpm:") {
            let handle = u32::from_str_radix(handle_str.trim_start_matches("0x"), 16)?;
            Ok(Self::Tpm(handle))
        } else if let Some(handle_str) = s.strip_prefix("session:") {
            let handle = u32::from_str_radix(handle_str.trim_start_matches("0x"), 16)?;
            Ok(Self::Session(handle))
        } else if let Some(grip) = s.strip_prefix("key:") {
            if grip.len() == 16 && grip.chars().all(|c| c.is_ascii_hexdigit()) {
                Ok(Self::Key(grip.to_string()))
            } else {
                Err(UriError::InvalidGripFormat(grip.to_string()))
            }
        } else if s.contains(':') && !s.starts_with('/') && s.chars().nth(1) != Some(':') {
            Err(UriError::UnsupportedScheme(
                s.split_once(':').unwrap_or(("", "")).0.to_string(),
            ))
        } else {
            Ok(Self::Path(s.to_string().into()))
        }
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tpm(handle) => write!(f, "tpm:{handle:08x}"),
            Self::Key(grip) => write!(f, "key:{grip}"),
            Self::Path(path) => write!(f, "{}", path.to_string_lossy()),
            Self::Session(handle) => write!(f, "session:{handle:08x}"),
        }
    }
}
