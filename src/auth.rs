// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::handle::{Handle, HandleError};
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{char, hex_digit1},
    combinator::{all_consuming, map_res},
    sequence::tuple,
    IResult,
};
use std::str::FromStr;
use thiserror::Error;
use tpm2_protocol::data::TpmHt;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("auth handle is not a policy session handle")]
    InvalidHandle,
    #[error("auth content is not valid hex string")]
    InvalidHexString,
    #[error("auth scheme is invalid or format incorrect")]
    InvalidScheme,
    #[error("auth handle error: {0}")]
    Handle(#[from] HandleError),
}

/// Represents an authorization method for a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    Password(Vec<u8>),
    Policy(Vec<u8>),
    Session(Handle),
}

/// Nom parser for the Auth enum.
fn parse_auth(input: &str) -> IResult<&str, Auth> {
    let parse_password = map_res(hex_digit1, |hex: &str| {
        hex::decode(hex)
            .map(Auth::Password)
            .map_err(|_| AuthError::InvalidHexString)
    });

    let parse_policy = map_res(hex_digit1, |hex: &str| {
        hex::decode(hex)
            .map(Auth::Policy)
            .map_err(|_| AuthError::InvalidHexString)
    });

    let parse_session = map_res(hex_digit1, |hex: &str| {
        u32::from_str_radix(hex, 16)
            .map_err(|_| AuthError::InvalidHexString)
            .and_then(|val| {
                if (val >> 24) as u8 == TpmHt::PolicySession as u8 {
                    Ok(Auth::Session(Handle::Vtpm(val)))
                } else {
                    Err(AuthError::InvalidHandle)
                }
            })
    });

    alt((
        map_res(
            tuple((tag("password"), char(':'), parse_password)),
            |(_, _, auth)| -> Result<Auth, AuthError> { Ok(auth) },
        ),
        map_res(
            tuple((tag("policy"), char(':'), parse_policy)),
            |(_, _, auth)| -> Result<Auth, AuthError> { Ok(auth) },
        ),
        map_res(
            tuple((tag("vtpm"), char(':'), parse_session)),
            |(_, _, auth)| -> Result<Auth, AuthError> { Ok(auth) },
        ),
    ))(input)
}

impl Default for Auth {
    fn default() -> Self {
        Self::Password(Vec::new())
    }
}

impl std::fmt::Display for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Auth::Password(bytes) => write!(f, "password:{}", hex::encode(bytes)),
            Auth::Policy(bytes) => write!(f, "policy:{}", hex::encode(bytes)),
            Auth::Session(handle) => write!(f, "{handle}"),
        }
    }
}

impl FromStr for Auth {
    type Err = AuthError;

    fn from_str(uri_str: &str) -> Result<Self, Self::Err> {
        match all_consuming(parse_auth)(uri_str) {
            Ok((_, auth)) => Ok(auth),
            Err(_) => Err(AuthError::InvalidScheme),
        }
    }
}
