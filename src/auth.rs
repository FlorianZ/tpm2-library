// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Handles parsing and representation of authorization data for TPM commands.

use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::hex_digit1,
    combinator::{all_consuming, map, map_res},
    sequence::preceded,
    IResult,
};
use std::{num::ParseIntError, str::FromStr};
use thiserror::Error;
use tpm2_protocol::{data::TpmHt, TpmBuild, TpmError, TpmHandle, TpmParse, TpmSized, TpmWriter};

/// Maximum size for password or policy authorization data.
const MAX_AUTH_SIZE: usize = 64;

/// Errors related to parsing or using authorization data.
#[derive(Debug, Error)]
pub enum AuthError {
    /// The provided authorization string is invalid or malformed.
    #[error("invalid auth string")]
    InvalidAuth,
    /// The structure or format of the authorization data is incorrect.
    #[error("malformed auth value")]
    MalformedAuth,
    /// The provided authorization value (password or policy) exceeds `MAX_AUTH_SIZE`.
    #[error("auth value too large")]
    ValueTooLarge,
    /// Failed to decode a hexadecimal string.
    #[error("hex decode: {0}")]
    HexDecode(#[from] hex::FromHexError),
    /// Failed to parse a hexadecimal string as a handle (u32).
    #[error("handle decode: {0}")]
    IntDecode(#[from] ParseIntError),
}

impl From<TpmError> for AuthError {
    fn from(_: TpmError) -> Self {
        Self::MalformedAuth
    }
}

/// Specifies the type or method of authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthClass {
    /// Authorization using a password (or empty password represented by `Auth::default()`).
    Password,
    /// Authorization based on a policy digest.
    Policy,
    /// Authorization using a session handle (HMAC or policy session).
    Session,
}

/// Represents authorization data, holding the class and the actual value.
///
/// It uses a fixed-size array internally for efficiency and predictability,
/// tracking the actual length of the data used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    /// The class (type) of authorization.
    pub class: AuthClass,
    /// Fixed-size buffer holding the authorization data (password, policy digest, or handle bytes).
    pub data: [u8; MAX_AUTH_SIZE],
    /// The actual number of bytes used in the `data` buffer.
    pub len: usize,
}

/// Helper function to build a handle byte array from a u32 value.
/// Serializes a `TpmHandle` into a byte array suitable for the `Auth::data` field.
///
/// # Errors
///
/// Returns a `TpmError` if serialization fails.
fn build_handle_array(handle_val: u32) -> Result<([u8; MAX_AUTH_SIZE], usize), TpmError> {
    let handle = TpmHandle(handle_val);
    let mut array = [0u8; MAX_AUTH_SIZE];
    let mut writer = TpmWriter::new(&mut array[0..TpmHandle::SIZE]);
    handle.build(&mut writer)?;
    Ok((array, TpmHandle::SIZE))
}

/// Helper function to parse hex string, validate size, and copy to fixed array.
///
/// Decodes a hexadecimal string, checks if it exceeds `MAX_AUTH_SIZE`, and
/// copies the resulting bytes into the fixed-size array format used by `Auth`.
///
/// # Errors
///
/// Returns `AuthError::HexDecode` if the string is not valid hex.
/// Returns `AuthError::ValueTooLarge` if the decoded bytes exceed `MAX_AUTH_SIZE`.
fn parse_auth_hex(s: &str) -> Result<([u8; MAX_AUTH_SIZE], usize), AuthError> {
    let bytes = hex::decode(s)?;
    if bytes.len() > MAX_AUTH_SIZE {
        return Err(AuthError::ValueTooLarge);
    }
    let mut array = [0u8; MAX_AUTH_SIZE];
    array[..bytes.len()].copy_from_slice(&bytes);
    Ok((array, bytes.len()))
}

/// Parses a "password:<hex>" string into an `Auth` struct.
fn parse_password_auth(input: &str) -> IResult<&str, Auth> {
    map(
        preceded(tag("password:"), map_res(hex_digit1, parse_auth_hex)),
        |(array, len)| Auth {
            class: AuthClass::Password,
            data: array,
            len,
        },
    )(input)
}

/// Parses a "policy:<hex>" string into an `Auth` struct.
fn parse_policy_auth(input: &str) -> IResult<&str, Auth> {
    map(
        preceded(tag("policy:"), map_res(hex_digit1, parse_auth_hex)),
        |(array, len)| Auth {
            class: AuthClass::Policy,
            data: array,
            len,
        },
    )(input)
}

/// Parses a "vtpm:<hex>" string into an `Auth` struct representing a session handle.
fn parse_session_auth(input: &str) -> IResult<&str, Auth> {
    map(
        preceded(
            tag("vtpm:"),
            map_res(hex_digit1, |s: &str| -> Result<_, AuthError> {
                let handle_val = u32::from_str_radix(s, 16)?;
                Ok(build_handle_array(handle_val)?)
            }),
        ),
        |(array, len)| Auth {
            class: AuthClass::Session,
            data: array,
            len,
        },
    )(input)
}

impl Auth {
    /// Returns the authorization class (`Password`, `Policy`, or `Session`).
    #[must_use]
    pub fn class(&self) -> AuthClass {
        self.class
    }

    /// Returns the raw authorization value as a byte slice.
    ///
    /// The length of the slice depends on the `AuthClass`:
    /// * `Password`, `Policy`: Length determined by parsed hex data (`self.len`).
    /// * `Session`: Fixed length equal to `TpmHandle::SIZE`.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.data[0..self.len]
    }

    /// Extracts the session handle (u32) if the class is `Session`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAuth`](AuthError::InvalidAuth) if the class is not `AuthClass::Session`.
    /// Returns [`MalformedAuth`](AuthError::MalformedAuth) if the stored bytes are not a valid `TpmHandle`.
    pub fn session(&self) -> Result<u32, AuthError> {
        if self.class() != AuthClass::Session {
            return Err(AuthError::InvalidAuth);
        }
        let (handle, remainder) = TpmHandle::parse(&self.data[0..TpmHandle::SIZE])?;
        if !remainder.is_empty() {
            return Err(AuthError::MalformedAuth);
        }
        Ok(handle.0)
    }
}

impl Default for Auth {
    /// Creates a default `Auth` instance representing an empty password.
    fn default() -> Self {
        Self {
            class: AuthClass::Password,
            data: [0u8; MAX_AUTH_SIZE],
            len: 0,
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
    /// Valid formats:
    /// * `empty` - Represents an empty password.
    /// * `password:<hex>` - Password specified as a hex string.
    /// * `policy:<hex>` - Policy digest specified as a hex string.
    /// * `vtpm:<hex>` - Session handle specified as a hex string.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAuth`](AuthError::InvalidAuth) if the string does not match any valid format,
    /// or if the session handle type (extracted from the high byte) is not `HmacSession` or `PolicySession`.
    fn from_str(auth_str: &str) -> Result<Self, Self::Err> {
        if auth_str == "empty" {
            return Ok(Self::default());
        }

        match all_consuming(alt((
            parse_password_auth,
            parse_policy_auth,
            parse_session_auth,
        )))(auth_str)
        {
            Ok((_, auth)) => {
                if auth.class() == AuthClass::Session {
                    let handle = auth.session()?;
                    let ht = (handle >> 24) as u8;
                    if ht == TpmHt::PolicySession as u8 || ht == TpmHt::HmacSession as u8 {
                        Ok(auth)
                    } else {
                        Err(AuthError::InvalidAuth)
                    }
                } else {
                    Ok(auth)
                }
            }
            Err(_) => Err(AuthError::InvalidAuth),
        }
    }
}
