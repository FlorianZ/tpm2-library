// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli::Hierarchy, command::CommandError, key::Alg};
use clap::{Args, ValueEnum};
use std::{borrow::Cow, path::PathBuf};
use strum::{Display, EnumString};
use tpm2_policy_language::Auth;
use tpm2_protocol::data::{Tpm2bAuth, Tpm2bDigest, TpmaObject};

#[derive(Args, Debug, Clone, Default)]
pub struct AuthArgs {
    /// List of 'password:<hex>', 'policy:<hex>' or 'vtpm:<handle>' entries.
    #[arg(short = 'A', long = "auth", value_delimiter = ',')]
    pub auth: Vec<Auth>,
}

impl AuthArgs {
    /// Returns a slice of authorizations.
    ///
    /// If no authorizations were provided on the command line, this returns
    /// a default slice representing a single empty password, which is the
    /// required behavior for most authorized commands.
    #[must_use]
    pub fn auths(&self) -> Cow<'_, [Auth]> {
        if self.auth.is_empty() {
            Cow::Owned(vec![Auth::default()])
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

    /// Policy digest: '<hex string>'
    #[arg(long = "policy")]
    pub policy: Option<String>,
}

impl CreationArgs {
    /// Parse authorization value and policy digest and create object attributes.
    ///
    /// # Errors
    ///
    /// Returns a `CommandError` if parsing fails.
    pub fn parse(&self, alg: &Alg) -> Result<(TpmaObject, Tpm2bAuth, Tpm2bDigest), CommandError> {
        let user_auth = match &self.password {
            Some(hex_str) => Tpm2bAuth::try_from(hex::decode(hex_str)?.as_slice())?,
            None => Tpm2bAuth::default(),
        };

        let auth_policy = match &self.policy {
            Some(hex_str) => Tpm2bDigest::try_from(hex::decode(hex_str)?.as_slice())?,
            None => Tpm2bDigest::default(),
        };

        let mut attributes: TpmaObject = alg.clone().into();
        if !user_auth.is_empty() || auth_policy.is_empty() {
            attributes |= TpmaObject::USER_WITH_AUTH;
        }
        if !auth_policy.is_empty() {
            attributes |= TpmaObject::ADMIN_WITH_POLICY;
        }

        Ok((attributes, user_auth, auth_policy))
    }
}
