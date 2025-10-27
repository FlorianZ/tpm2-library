// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles parsing and representation of authorization data for TPM commands.

use std::{num::ParseIntError, str::FromStr};
use thiserror::Error;
use tpm2_protocol::{data::TpmHt, TpmBuild, TpmError, TpmHandle, TpmParse, TpmSized, TpmWriter};

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

impl From<TpmError> for AuthError {
    fn from(_: TpmError) -> Self {
        Self::MalformedAuth
    }
}

/// Authorization type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthClass {
    Password,
    Policy,
    Session,
}

/// Authorization data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    pub class: AuthClass,
    pub data: Vec<u8>,
}

/// Serializes a handle into a byte vector.
///
/// # Errors
///
/// Returns [`MalformedAuth`](crate::auth::AuthError::MalformedAuth) when
/// serialization fails.
fn build_handle_vec(handle_val: u32) -> Result<Vec<u8>, TpmError> {
    let handle = TpmHandle(handle_val);
    let mut vec = vec![0u8; TpmHandle::SIZE];
    let mut writer = TpmWriter::new(&mut vec);
    handle.build(&mut writer)?;
    Ok(vec)
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
    /// Returns the authorization class.
    #[must_use]
    pub fn class(&self) -> AuthClass {
        self.class
    }

    /// Returns the raw authorization value as a byte slice.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.data
    }

    /// Extracts the session handle.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAuth`](crate::auth::AuthError::InvalidAuth) when the
    /// authorization class is not [`Session`](crate::auth::AuthClass::Session).
    /// Returns [`MalformedAuth`](crate::auth::AuthError::MalformedAuth) when
    /// the input data is malformed.
    pub fn session(&self) -> Result<u32, AuthError> {
        if self.class() != AuthClass::Session {
            return Err(AuthError::InvalidAuth);
        }
        if self.data.len() != TpmHandle::SIZE {
            return Err(AuthError::MalformedAuth);
        }
        let (handle, remainder) = TpmHandle::parse(&self.data)?;
        if !remainder.is_empty() {
            return Err(AuthError::MalformedAuth);
        }
        Ok(handle.0)
    }

    /// Creates a new [`Auth`](crate::auth::Auth) instance.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedAuth`](crate::auth::AuthError::MalformedAuth) when
    /// the output data is malformed.
    pub fn new_session(vhandle: u32) -> Result<Self, AuthError> {
        let data = build_handle_vec(vhandle).map_err(|_| AuthError::MalformedAuth)?;
        Ok(Auth {
            class: AuthClass::Session,
            data,
        })
    }
}

impl Default for Auth {
    /// Creates a default `Auth` instance representing an empty password.
    fn default() -> Self {
        Self {
            class: AuthClass::Password,
            data: Vec::new(),
        }
    }
}

impl std::fmt::Display for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if *self == Self::default() {
            return write!(f, "empty");
        }

        match self.class {
            AuthClass::Password => write!(f, "password:<sensitive>"),
            AuthClass::Policy => write!(f, "policy:{}", hex::encode(self.value())),
            AuthClass::Session => match self.session() {
                Ok(handle_val) => write!(f, "vtpm:{handle_val:08x}"),
                Err(_) => Err(std::fmt::Error),
            },
        }
    }
}

impl FromStr for Auth {
    type Err = AuthError;

    /// Parses an authorization string into an `Auth` structure.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAuth`](AuthError::InvalidAuth) when the string does not
    /// match any valid format, or if a `vtpm:` handle represents an HMAC session.
    /// Returns [`ValueTooLarge`](AuthError::ValueTooLarge) when the password or
    /// policy hex data exceeds `MAX_AUTH_SIZE`.
    fn from_str(auth_str: &str) -> Result<Self, Self::Err> {
        if auth_str == "empty" {
            return Ok(Self::default());
        }

        let (prefix, value) = auth_str.split_once(':').ok_or(AuthError::InvalidAuth)?;

        match prefix {
            "password" => {
                let data = parse_auth_hex(value)?;
                Ok(Auth {
                    class: AuthClass::Password,
                    data,
                })
            }
            "policy" => {
                let data = parse_auth_hex(value)?;
                Ok(Auth {
                    class: AuthClass::Policy,
                    data,
                })
            }
            "vtpm" => {
                let handle_val = u32::from_str_radix(value, 16)?;
                let ht_byte = (handle_val >> 24) as u8;
                let ht = TpmHt::try_from(ht_byte).map_err(|()| AuthError::InvalidAuth)?;

                match ht {
                    TpmHt::PolicySession => {
                        let data =
                            build_handle_vec(handle_val).map_err(|_| AuthError::MalformedAuth)?;
                        Ok(Auth {
                            class: AuthClass::Session,
                            data,
                        })
                    }
                    _ => Err(AuthError::InvalidAuth),
                }
            }
            _ => Err(AuthError::InvalidAuth),
        }
    }
}
