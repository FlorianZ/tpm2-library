//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::AuthError;
use std::str::FromStr;
use tpm2_protocol::data::TpmHt;

/// Maximum size for password or policy authorization data.
pub(crate) const MAX_AUTH_SIZE: usize = 64;

/// Authorization data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    Password(Vec<u8>),
    Policy(Vec<u8>),
    Session(u32),
}

impl Default for Auth {
    /// Creates a default `Auth` instance with an empty password.
    fn default() -> Self {
        Self::Password(Vec::new())
    }
}

impl std::fmt::Display for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

    fn from_str(auth_str: &str) -> Result<Self, Self::Err> {
        if auth_str == "empty" {
            return Ok(Self::default());
        }

        let (prefix, value) = auth_str.split_once(':').ok_or(AuthError::InvalidPrefix)?;

        match prefix {
            "password" => {
                let bytes = hex::decode(value).map_err(|_| AuthError::InvalidPasswordString)?;
                if bytes.len() > MAX_AUTH_SIZE {
                    return Err(AuthError::TooLargeAuth(bytes.len()));
                }
                Ok(Self::Password(bytes))
            }
            "policy" => {
                let bytes = hex::decode(value)
                    .map_err(|_| AuthError::InvalidPolicyString(value.to_string()))?;
                if bytes.len() > MAX_AUTH_SIZE {
                    return Err(AuthError::TooLargeAuth(bytes.len()));
                }
                Ok(Self::Policy(bytes))
            }
            "vtpm" => {
                let handle_val = u32::from_str_radix(value, 16)
                    .map_err(|_| AuthError::InvalidHandleString(value.to_string()))?;
                let ht_byte = (handle_val >> 24) as u8;
                let ht =
                    TpmHt::try_from(ht_byte).map_err(|()| AuthError::InvalidHandleType(ht_byte))?;

                match ht {
                    TpmHt::PolicySession | TpmHt::HmacSession => Ok(Self::Session(handle_val)),
                    _ => Err(AuthError::InvalidPrefix),
                }
            }
            _ => Err(AuthError::InvalidPrefix),
        }
    }
}
