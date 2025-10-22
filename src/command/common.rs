// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{auth::Auth, cli::Hierarchy, command::CommandError, handle::Handle, key::Alg};
use clap::Args;
use std::path::PathBuf;
use strum::{Display, EnumString};
use tpm2_protocol::data::{Tpm2bAuth, Tpm2bDigest, TpmaObject};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Display, EnumString)]
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
    #[arg(long = "output-encoding", default_value_t = OutputEncoding::default(), value_parser = clap::value_parser!(OutputEncoding))]
    pub output_encoding: OutputEncoding,
}

#[derive(Args, Debug, Clone)]
pub struct ParentAuthArgs {
    /// Parent key: 'tpm:<handle>', or 'vtpm:<handle>'
    #[arg(short = 'P', long)]
    pub parent: Handle,

    /// Authentication: 'password:<hex>', 'policy:<hex>' or 'vtpm:<handle>'
    #[arg(short = 'A', long = "auth")]
    pub auth: Option<Auth>,
}

#[derive(Args, Debug, Clone)]
pub struct AuthArgs {
    /// Authentication: 'password:<hex>', 'policy:<hex>' or 'vtpm:<handle>'
    #[arg(short = 'A', long = "auth")]
    pub auth: Option<Auth>,
}

#[derive(Args, Debug, Clone)]
pub struct HierarchyAuthArgs {
    /// Hierarchy: owner (default), platform or endorsement
    #[arg(short = 'H', long, default_value_t = Hierarchy::default(), value_parser = clap::value_parser!(Hierarchy))]
    pub hierarchy: Hierarchy,

    /// Authentication: 'password:<hex>', 'policy:<hex>' or 'vtpm:<handle>'
    #[arg(short = 'A', long = "auth")]
    pub auth: Option<Auth>,
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
        let mut attributes: TpmaObject = alg.clone().into();

        if self.password.is_none() && self.policy.is_none() {
            attributes |= TpmaObject::USER_WITH_AUTH;
        }

        let user_auth = if let Some(hex_str) = &self.password {
            attributes |= TpmaObject::USER_WITH_AUTH;
            Tpm2bAuth::try_from(hex::decode(hex_str)?.as_slice())?
        } else {
            Tpm2bAuth::default()
        };

        let auth_policy = if let Some(hex_str) = &self.policy {
            attributes |= TpmaObject::ADMIN_WITH_POLICY;
            Tpm2bDigest::try_from(hex::decode(hex_str)?.as_slice())?
        } else {
            Tpm2bDigest::default()
        };

        Ok((attributes, user_auth, auth_policy))
    }
}
