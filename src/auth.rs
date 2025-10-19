// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::uri::{Uri, UriError};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error(transparent)]
    Uri(#[from] UriError),
    #[error("invalid authentication scheme: {0}")]
    InvalidAuthenticationScheme(String),
}

/// Represents an authorization method for a command.
#[derive(Debug, Clone, PartialEq)]
pub struct Auth(pub Uri);

impl TryFrom<Uri> for Auth {
    type Error = AuthError;

    fn try_from(uri: Uri) -> Result<Self, Self::Error> {
        match uri {
            Uri::Session(_) | Uri::Password(_) | Uri::Policy(_) => Ok(Self(uri)),
            _ => Err(AuthError::InvalidAuthenticationScheme(uri.to_string())),
        }
    }
}

impl Default for Auth {
    fn default() -> Self {
        Self(Uri::Password(Vec::new()))
    }
}

/// A type alias for a list of authentications, to attach methods.
pub type AuthList = Vec<Auth>;

impl std::fmt::Display for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Auth {
    type Err = AuthError;

    fn from_str(uri_str: &str) -> Result<Self, Self::Err> {
        let uri = Uri::from_str(uri_str)?;
        Self::try_from(uri)
    }
}
