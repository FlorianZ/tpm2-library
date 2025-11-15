//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    alg::{Alg, AlgInfo},
    cli::Hierarchy,
    command::CommandError,
};
use clap::{Args, ValueEnum};
use std::{borrow::Cow, path::PathBuf, str::FromStr};
use strum::{Display, EnumString};
use tpm2_policy_language::Auth;
use tpm2_protocol::data::{Tpm2bAuth, TpmaObject};

/// Validates that the authorization string is a password authorization.
///
/// # Errors
///
/// Returns an error if the string is not a valid `Auth` or is not the
/// `Auth::Password` variant.
fn validate_password_auth(s: &str) -> Result<Auth, String> {
    let auth = Auth::from_str(s).map_err(|e| e.to_string())?;
    if matches!(auth, Auth::Password(_)) {
        Ok(auth)
    } else {
        Err("Only 'password:<hex>' authorizations are supported".to_string())
    }
}

#[derive(Args, Debug, Clone, Default)]
pub struct AuthArgs {
    /// List of 'password:<hex>' entries.
    #[arg(short = 'A', long = "auth", value_delimiter = ',', value_parser = validate_password_auth)]
    pub auth: Vec<Auth>,
}

impl AuthArgs {
    /// Returns a slice of authorizations.
    ///
    /// If no authorizations were provided, this returns a default slice
    /// representing a single empty password, unless `empty_auth` is true.
    ///
    /// # Errors
    ///
    /// Returns a `CommandError` if a non-password auth is encountered.
    #[must_use]
    pub fn auths(&self, empty_auth: bool) -> Cow<'_, [Auth]> {
        if self.auth.is_empty() {
            if empty_auth {
                Cow::Owned(vec![])
            } else {
                Cow::Owned(vec![Auth::default()])
            }
        } else {
            Cow::Borrowed(self.auth.as_slice())
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Display, EnumString, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum OutputEncoding {
    #[default]
    Pem,
    Der,
}

#[derive(Args, Debug, Clone)]
pub struct InputArgs {
    /// Input file path (default: stdin)
    #[arg(short = 'I', long)]
    pub input: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct OutputArgs {
    /// Output file path (default: stdout)
    #[arg(short = 'O', long)]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct OutputEncodingArgs {
    /// Output encoding: pem or der
    #[arg(long = "output-encoding", value_enum, default_value_t = OutputEncoding::default())]
    pub output_encoding: OutputEncoding,
}

#[derive(Args, Debug, Clone)]
pub struct HierarchyArgs {
    /// Hierarchy: owner (default), platform or endorsement
    #[arg(short = 'H', long, value_enum, default_value_t = Hierarchy::default())]
    pub hierarchy: Hierarchy,
}

#[derive(Args, Debug, Clone, Default)]
pub struct CreationArgs {
    /// Authentication value: '<hex string>'
    #[arg(long = "password")]
    pub password: Option<String>,

    /// Policy expression: e.g., 'pcr(sha256:7)'
    #[arg(long = "policy")]
    pub policy_expression: Option<String>,
}

impl CreationArgs {
    /// Parse authorization value and policy digest and create object attributes.
    ///
    /// # Errors
    ///
    /// Returns a `CommandError` if parsing fails.
    pub fn parse(&self, alg: &Alg) -> Result<(TpmaObject, Tpm2bAuth), CommandError> {
        let user_auth = match &self.password {
            Some(hex_str) => Tpm2bAuth::try_from(hex::decode(hex_str)?.as_slice())
                .map_err(|_| CommandError::CapacityExceeded)?,
            None => Tpm2bAuth::default(),
        };

        let mut attributes = TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT;

        if alg.params != AlgInfo::KeyedHash {
            attributes |=
                TpmaObject::SENSITIVE_DATA_ORIGIN | TpmaObject::DECRYPT | TpmaObject::RESTRICTED;
        }

        if !user_auth.is_empty() || self.policy_expression.is_none() {
            attributes |= TpmaObject::USER_WITH_AUTH;
        }
        if self.policy_expression.is_some() {
            attributes |= TpmaObject::ADMIN_WITH_POLICY;
        }

        Ok((attributes, user_auth))
    }
}
