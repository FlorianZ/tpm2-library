// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

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

const MAX_AUTH_SIZE: usize = 64;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid auth")]
    InvalidAuth,
    #[error("malformed value")]
    MalformedAuth,
    #[error("value too large")]
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

/// Authorization methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthClass {
    Password,
    Policy,
    Session,
}

/// Authorization data using a fixed-size array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth(pub (AuthClass, [u8; MAX_AUTH_SIZE]));

fn build_handle_array(handle_val: u32) -> Result<[u8; MAX_AUTH_SIZE], TpmError> {
    let handle = TpmHandle(handle_val);
    let mut array = [0u8; MAX_AUTH_SIZE];
    let mut writer = TpmWriter::new(&mut array[0..TpmHandle::SIZE]);
    handle.build(&mut writer)?;
    Ok(array)
}

fn parse_auth(input: &str) -> IResult<&str, Auth> {
    alt((
        map(
            preceded(
                tag("password:"),
                map_res(hex_digit1, |s: &str| -> Result<_, AuthError> {
                    let bytes = hex::decode(s)?;
                    if bytes.len() > MAX_AUTH_SIZE {
                        return Err(AuthError::ValueTooLarge);
                    }
                    let mut array = [0u8; MAX_AUTH_SIZE];
                    array[..bytes.len()].copy_from_slice(&bytes);
                    Ok(array)
                }),
            ),
            |array| Auth((AuthClass::Password, array)),
        ),
        map(
            preceded(
                tag("policy:"),
                map_res(hex_digit1, |s: &str| -> Result<_, AuthError> {
                    let bytes = hex::decode(s)?;
                    if bytes.len() > MAX_AUTH_SIZE {
                        return Err(AuthError::ValueTooLarge);
                    }
                    let mut array = [0u8; MAX_AUTH_SIZE];
                    array[..bytes.len()].copy_from_slice(&bytes);
                    Ok(array)
                }),
            ),
            |array| Auth((AuthClass::Policy, array)),
        ),
        map(
            preceded(
                tag("vtpm:"),
                map_res(hex_digit1, |s: &str| -> Result<_, AuthError> {
                    let handle_val = u32::from_str_radix(s, 16)?;
                    Ok(build_handle_array(handle_val)?)
                }),
            ),
            |array| Auth((AuthClass::Session, array)),
        ),
    ))(input)
}

impl Auth {
    /// Returns class of the auth.
    #[must_use]
    pub fn class(&self) -> AuthClass {
        self.0 .0
    }

    /// Returns value of the auth as a slice.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        match self.0 .0 {
            AuthClass::Session => &self.0 .1[0..TpmHandle::SIZE],
            AuthClass::Password | AuthClass::Policy => {
                let len = self.0 .1.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
                let effective_len = std::cmp::min(len, MAX_AUTH_SIZE);
                &self.0 .1[0..effective_len]
            }
        }
    }

    /// Extracts the session handle.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::InvalidAuth` if the class is not `AuthClass::Session`.
    /// Returns `AuthError::Protocol` if the stored bytes are not a valid handle.
    pub fn session(&self) -> Result<u32, AuthError> {
        if self.class() != AuthClass::Session {
            return Err(AuthError::InvalidAuth);
        }
        let (handle, remainder) = TpmHandle::parse(&self.0 .1[0..TpmHandle::SIZE])?;
        if !remainder.is_empty() {
            return Err(AuthError::InvalidAuth);
        }
        Ok(handle.0)
    }
}

impl Default for Auth {
    fn default() -> Self {
        Self((AuthClass::Password, [0u8; MAX_AUTH_SIZE]))
    }
}

impl std::fmt::Display for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 .0 {
            AuthClass::Password => write!(f, "password:{}", hex::encode(self.value())),
            AuthClass::Policy => write!(f, "policy:{}", hex::encode(self.value())),
            AuthClass::Session => match TpmHandle::parse(&self.0 .1[0..TpmHandle::SIZE]) {
                Ok((handle, [])) => {
                    write!(f, "vtpm:{:08x}", handle.0)
                }
                _ => Err(std::fmt::Error),
            },
        }
    }
}

impl FromStr for Auth {
    type Err = AuthError;

    fn from_str(uri_str: &str) -> Result<Self, Self::Err> {
        match all_consuming(parse_auth)(uri_str) {
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
