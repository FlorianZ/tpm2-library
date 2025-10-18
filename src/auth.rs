// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use std::str::FromStr;

/// Represents an authorization method for a command.
#[derive(Debug, Clone, PartialEq)]
pub enum Auth {
    /// A stateful, tracked session identified by its handle.
    Session(u32),
    /// A password
    Password(Vec<u8>),
    /// A policy digest
    Policy(Vec<u8>),
}

impl Default for Auth {
    fn default() -> Self {
        Self::Password(Vec::new())
    }
}

/// A type alias for a list of authentications, to attach methods.
pub type AuthList = Vec<Auth>;

impl std::fmt::Display for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session(handle) => write!(f, "session:{handle:08x}"),
            Self::Password(bytes) => write!(f, "password:{}", hex::encode(bytes)),
            Self::Policy(bytes) => write!(f, "policy:{}", hex::encode(bytes)),
        }
    }
}

impl FromStr for Auth {
    type Err = String;

    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        let Some((scheme, value)) = uri.split_once(':') else {
            return Err(format!("invalid auth: {uri}"));
        };

        match scheme {
            "session" => {
                let handle = u32::from_str_radix(value.trim_start_matches("0x"), 16)
                    .map_err(|_| format!("invalid session: {uri}"))?;
                Ok(Self::Session(handle))
            }
            "password" => {
                let bytes = hex::decode(value).map_err(|_| format!("invalid password: {uri}"))?;
                Ok(Self::Password(bytes))
            }
            "policy" => {
                let bytes = hex::decode(value).map_err(|_| format!("invalid policy: {uri}"))?;
                Ok(Self::Policy(bytes))
            }
            _ => Err(format!("unsupported auth scheme: {scheme}")),
        }
    }
}
