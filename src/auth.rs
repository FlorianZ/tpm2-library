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
        if let Some(val) = uri.strip_prefix("session:") {
            if let Ok(handle) = u32::from_str_radix(val.trim_start_matches("0x"), 16) {
                Ok(Self::Session(handle))
            } else {
                Err(format!("invalid session: {uri}"))
            }
        } else if let Some(val) = uri.strip_prefix("password:") {
            if let Ok(bytes) = hex::decode(val) {
                Ok(Self::Password(bytes))
            } else {
                Err(format!("invalid password: {uri}"))
            }
        } else if let Some(val) = uri.strip_prefix("policy:") {
            if let Ok(bytes) = hex::decode(val) {
                Ok(Self::Policy(bytes))
            } else {
                Err(format!("invalid policy: {uri}"))
            }
        } else {
            Err(format!("invalid auth: {uri}"))
        }
    }
}
