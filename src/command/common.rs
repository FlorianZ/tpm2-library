// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{auth::Auth, cli::Hierarchy, command::CommandError, key::Alg, uri::Uri};
use clap::Args;
use tpm2_protocol::data::{Tpm2bAuth, Tpm2bDigest, TpmaObject};

#[derive(Args, Debug, Clone)]
pub struct InputArgs {
    /// Input file path (default: stdin)
    #[arg(short = 'I', long)]
    pub input: Option<Uri>,
}

#[derive(Args, Debug, Clone)]
pub struct OutputArgs {
    /// Output file path (default: stdout)
    #[arg(short = 'O', long)]
    pub output: Option<Uri>,
}

#[derive(Args, Debug, Clone)]
pub struct AuthArgs {
    /// Parent key: 'tpm:<handle>', or 'key:<name grip>'
    #[arg(short = 'P', long)]
    pub parent: Uri,

    /// Authentication: 'password:<hex>' or 'session:<handle>'
    #[arg(short = 'a', long = "auth")]
    pub auth: Option<Auth>,
}

#[derive(Args, Debug, Clone)]
pub struct HierarchyArgs {
    /// Hierarchy: owner (default), platform or endorsement
    #[arg(short = 'H', long, default_value_t = Hierarchy::default(), value_parser = clap::value_parser!(Hierarchy))]
    pub hierarchy: Hierarchy,

    /// Authentication: 'password:<hex>' or 'session:<handle>'
    #[arg(short = 'a', long = "auth")]
    pub auth: Option<Auth>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct CreationArgs {
    /// Authentication value
    #[arg(long = "auth-value")]
    pub auth_value: Option<String>,

    /// Policy digest
    #[arg(long = "policy-digest")]
    pub policy_digest: Option<String>,
}

impl CreationArgs {
    /// Parse authorization value and policy digest and create object attributes.
    ///
    /// # Errors
    ///
    /// Returns a `CommandError` if parsing fails.
    pub fn parse(&self, alg: &Alg) -> Result<(TpmaObject, Tpm2bAuth, Tpm2bDigest), CommandError> {
        let mut attributes: TpmaObject = alg.clone().into();

        let user_auth = if let Some(hex_str) = &self.auth_value {
            attributes |= TpmaObject::USER_WITH_AUTH;
            Tpm2bAuth::try_from(hex::decode(hex_str)?.as_slice())?
        } else {
            Tpm2bAuth::default()
        };

        let auth_policy = if let Some(hex_str) = &self.policy_digest {
            attributes |= TpmaObject::ADMIN_WITH_POLICY;
            Tpm2bDigest::try_from(hex::decode(hex_str)?.as_slice())?
        } else {
            Tpm2bDigest::default()
        };

        Ok((attributes, user_auth, auth_policy))
    }
}
