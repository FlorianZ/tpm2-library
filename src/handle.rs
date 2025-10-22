// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use nom::{
    branch::alt,
    bytes::complete::tag,
    character::{complete::char, complete::hex_digit1},
    combinator::{all_consuming, map_res},
    sequence::tuple,
    IResult,
};
use std::{convert::TryFrom, num::ParseIntError, str::FromStr};
use thiserror::Error;
use tpm2_protocol::{data::TpmHt, TpmHandle};

#[derive(Debug, Error)]
pub enum HandleError {
    #[error("handle is invalid")]
    InvalidHandle,
    #[error("handle decode: {0}")]
    IntDecode(#[from] ParseIntError),
}

/// A type-safe representation of a specific handle type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handle {
    Tpm(u32),
    Vtpm(u32),
}

/// Nom parser for the Handle enum.
fn parse_handle(input: &str) -> IResult<&str, Handle> {
    map_res(
        tuple((
            alt((tag("tpm"), tag("vtpm"))),
            char(':'),
            map_res(hex_digit1, |s: &str| u32::from_str_radix(s, 16)),
        )),
        |(scheme, _, value)| -> Result<Handle, HandleError> {
            match scheme {
                "tpm" => Ok(Handle::Tpm(value)),
                "vtpm" => Ok(Handle::Vtpm(value)),
                _ => unreachable!(),
            }
        },
    )(input)
}

impl Handle {
    /// Returns the raw u32 value of the handle.
    #[must_use]
    pub fn value_raw(&self) -> u32 {
        match *self {
            Handle::Tpm(h) | Handle::Vtpm(h) => h,
        }
    }

    /// Returns the handle value as a `TpmHandle`.
    #[must_use]
    pub fn value_tpm(&self) -> TpmHandle {
        TpmHandle(self.value_raw())
    }
}

impl std::fmt::Display for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Handle::Tpm(h) => write!(f, "tpm:{h:08x}"),
            Handle::Vtpm(h) => write!(f, "vtpm:{h:08x}"),
        }
    }
}

impl FromStr for Handle {
    type Err = HandleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match all_consuming(parse_handle)(s) {
            Ok((_, handle)) => Ok(handle),
            Err(_) => Err(HandleError::InvalidHandle),
        }
    }
}

impl TryFrom<Handle> for TpmHt {
    type Error = HandleError;

    fn try_from(handle: Handle) -> Result<Self, Self::Error> {
        let raw_handle = handle.value_raw();
        let ht_byte = (raw_handle >> 24) as u8;
        TpmHt::try_from(ht_byte).map_err(|()| HandleError::InvalidHandle)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HandlePatternError {
    #[error("handle pattern is not a valid hex string")]
    InvalidHexString,
    #[error("handle pattern has less than eight characters")]
    TooFewDigits,
    #[error("handle pattern has more than one '*'")]
    TooManyAsterisks,
    #[error("handle pattern has more than eight characters")]
    TooManyDigits,
}

/// Pattern matcher for a 32-bit unsigned value represented
/// as a string of exactly eight hex digits.
///
/// Wildcards:
///
/// 1. `?` matches any digit and can be used in place of any digit.
/// 2. `*` matches zero or more digits. Only one `*` is supported per pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlePattern(u32, u32);

impl HandlePattern {
    /// Compiles a query string into a `HandlePattern`.
    ///
    /// # Errors
    ///
    /// Returns `HandlePatternError` if the query string is invalid.
    pub fn new(query: &str) -> Result<Self, HandlePatternError> {
        if query == "*" {
            return Ok(Self(0, 0));
        }

        let mut mask: u32 = 0;
        let mut value: u32 = 0;

        let (prefix, suffix) = if let Some((p, s)) = query.split_once('*') {
            if s.contains('*') {
                return Err(HandlePatternError::TooManyAsterisks);
            }
            if p.len() + s.len() > 8 {
                return Err(HandlePatternError::TooManyDigits);
            }
            (p, s)
        } else {
            if query.len() < 8 {
                return Err(HandlePatternError::TooFewDigits);
            }
            if query.len() > 8 {
                return Err(HandlePatternError::TooManyDigits);
            }
            (query, "")
        };

        for (i, c) in prefix.chars().enumerate() {
            let shift = (7 - i) * 4;
            match c.to_digit(16) {
                Some(v) => {
                    mask |= 0xF << shift;
                    value |= v << shift;
                }
                None if c == '?' => {}
                None => return Err(HandlePatternError::InvalidHexString),
            }
        }

        for (i, c) in suffix.chars().rev().enumerate() {
            let shift = i * 4;
            match c.to_digit(16) {
                Some(v) => {
                    mask |= 0xF << shift;
                    value |= v << shift;
                }
                None if c == '?' => {}
                None => return Err(HandlePatternError::InvalidHexString),
            }
        }

        Ok(Self(mask, value))
    }

    /// Checks if a given handle matches the compiled pattern.
    #[must_use]
    pub fn matches(&self, handle: u32) -> bool {
        if self.0 == 0 && self.1 == 0 {
            return true;
        }
        (handle & self.0) == self.1
    }
}
