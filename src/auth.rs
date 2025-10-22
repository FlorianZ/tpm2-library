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
use tpm2_protocol::data::TpmHt;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("auth is invalid")]
    InvalidAuth,
    #[error("auth is not a policy session handle")]
    NotPolicyHandle,
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
    alt((
        map(
            preceded(tag("password:"), map_res(hex_digit1, hex::decode)),
            Auth::Password,
        ),
        map(
            preceded(tag("policy:"), map_res(hex_digit1, hex::decode)),
            Auth::Policy,
        ),
        map(
            preceded(
                tag("vtpm:"),
                map_res(hex_digit1, |s| u32::from_str_radix(s, 16)),
            ),
            Auth::Session,
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
                let ht = (handle >> 24) as u8;
                if ht == TpmHt::PolicySession as u8 || ht == TpmHt::HmacSession as u8 {
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
