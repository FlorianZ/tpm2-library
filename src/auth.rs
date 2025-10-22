// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{char, hex_digit1},
    combinator::{all_consuming, map_res},
    sequence::tuple,
    IResult,
};
use std::{num::ParseIntError, str::FromStr};
use thiserror::Error;
use tpm2_protocol::data::TpmHt;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("auth is not a policy handle")]
    NotPolicyHandle,
    #[error("auth is not a valid hex string")]
    InvalidHexString,
    #[error("auth is invalid")]
    InvalidAuth,
    #[error("hex decode: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("handle decode: {0}")]
    IntDecode(#[from] ParseIntError),
}

/// Represents an authorization method for a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    Password(Vec<u8>),
    Policy(Vec<u8>),
    Session(u32),
}

/// Nom parser for the Auth enum.
fn parse_auth(input: &str) -> IResult<&str, Auth> {
    let parse_password = map_res(hex_digit1, |hex: &str| hex::decode(hex).map(Auth::Password));
    let parse_policy = map_res(hex_digit1, |hex: &str| hex::decode(hex).map(Auth::Policy));
    let parse_session = map_res(hex_digit1, |hex: &str| {
        u32::from_str_radix(hex, 16).map(Auth::Session)
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
            Auth::Session(handle) => write!(f, "vtpm:{handle:08x}"),
        }
    }
}

impl FromStr for Auth {
    type Err = AuthError;

    fn from_str(uri_str: &str) -> Result<Self, Self::Err> {
        match all_consuming(parse_auth)(uri_str) {
            Ok((_, Auth::Session(handle))) => {
                if (handle >> 24) as u8 == TpmHt::PolicySession as u8 {
                    Ok(Auth::Session(handle))
                } else {
                    Err(AuthError::NotPolicyHandle)
                }
            }
            Ok((_, auth)) => Ok(auth),
            Err(_) => Err(AuthError::InvalidAuth),
        }
    }
}
