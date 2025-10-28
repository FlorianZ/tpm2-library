// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles parsing and representation of authorization data for TPM commands.

use std::{num::ParseIntError, str::FromStr};
use thiserror::Error;
use tpm2_protocol::data::TpmHt;

/// Maximum size for password or policy authorization data.
const MAX_AUTH_SIZE: usize = 64;

/// Authorization errors.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid auth string")]
    InvalidAuth,
    #[error("malformed auth value")]
    MalformedAuth,
    #[error("auth value too large")]
    ValueTooLarge,
    #[error("hex decode: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("handle decode: {0}")]
    IntDecode(#[from] ParseIntError),
}

/// Authorization data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    Password(Vec<u8>),
    Policy(Vec<u8>),
    Session(u32),
}

/// Decodes a hexadecimal string.
///
/// # Errors
///
/// Returns [`HexDecode`](crate::auth::AuthError::HexDecode) when the decoding
/// fails.
/// Returns [`ValueTooLarge`](crate::auth::AuthError::ValueTooLarge) when the
/// size exceeds [`MAX_AUTH_SIZE`](crate::auth::MAX_AUTH_SIZE).
fn parse_auth_hex(s: &str) -> Result<Vec<u8>, AuthError> {
    let bytes = hex::decode(s)?;
    if bytes.len() > MAX_AUTH_SIZE {
        return Err(AuthError::ValueTooLarge);
    }
    Ok(bytes)
}

impl Auth {
    /// Creates a new [`Auth`] session instance.
    #[must_use]
    pub fn new_session(vhandle: u32) -> Self {
        Self::Session(vhandle)
    }
}

impl Default for Auth {
    /// Creates a default `Auth` instance representing an empty password.
    fn default() -> Self {
        Self::Password(Vec::new())
    }
}

impl std::fmt::Display for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(data) if data.is_empty() => write!(f, "empty"),
            Self::Password(_) => write!(f, "password:<sensitive>"),
            Self::Policy(data) => write!(f, "policy:{}", hex::encode(data)),
            Self::Session(handle) => write!(f, "vtpm:{handle:08x}"),
        }
    }
}

impl FromStr for Auth {
    type Err = AuthError;

    /// Parses an authorization string into an `Auth` structure.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAuth`](crate::auth::AuthError::InvalidAuth) when the string does not
    /// match any valid format, or if a `vtpm:` handle represents an HMAC session.
    /// Returns [`ValueTooLarge`](crate::auth::AuthError::ValueTooLarge) when the password or
    /// policy hex data exceeds `MAX_AUTH_SIZE`.
    fn from_str(auth_str: &str) -> Result<Self, Self::Err> {
        if auth_str == "empty" {
            return Ok(Self::default());
        }

        let (prefix, value) = auth_str.split_once(':').ok_or(AuthError::InvalidAuth)?;

        match prefix {
            "password" => Ok(Self::Password(parse_auth_hex(value)?)),
            "policy" => Ok(Self::Policy(parse_auth_hex(value)?)),
            "vtpm" => {
                let handle_val = u32::from_str_radix(value, 16)?;
                let ht_byte = (handle_val >> 24) as u8;
                let ht = TpmHt::try_from(ht_byte).map_err(|()| AuthError::InvalidAuth)?;

                match ht {
                    TpmHt::PolicySession | TpmHt::HmacSession => Ok(Self::Session(handle_val)),
                    _ => Err(AuthError::InvalidAuth),
                }
            }
            _ => Err(AuthError::InvalidAuth),
        }
    }
}
