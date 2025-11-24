// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Hierarchy,
    command::CommandError,
    pcr::{pcr_get_bank_list, read_all_pcrs},
    task::{TaskAuth, TaskState},
};
use clap::{Args, ValueEnum};
use std::{borrow::Cow, collections::HashMap, path::PathBuf};
use strum::{Display, EnumString};
use tpm2_crypto::{tpm_make_name, TpmPublicTemplate, TpmPublicTemplateType};
use tpm2_device::TpmDevice;
use tpm2_policy_language::{TpmPolicyExpression, TpmPolicyState};
use tpm2_protocol::{
    data::{Tpm2bAuth, Tpm2bDigest, Tpm2bName, TpmAlgId, TpmHt, TpmaObject},
    frame::{TpmAuthCommands, TpmCommand},
};
use tpm2_vtpm::{VtpmHandle, VtpmHandleClass};

/// Parses an authentication string as 'empty' or a hex string.
///
/// # Errors
///
/// Returns an error if the string is not 'empty' and is not valid hex.
fn parse_auth_password(s: &str) -> Result<TaskAuth, String> {
    if s == "empty" {
        Ok(TaskAuth::Password(Vec::new()))
    } else {
        hex::decode(s)
            .map(TaskAuth::Password)
            .map_err(|e| e.to_string())
    }
}

#[derive(Args, Debug, Clone, Default)]
pub struct AuthArgs {
    /// Authentication value: 'empty' or '<hex string>'
    #[arg(short = 'A', long = "auth", value_delimiter = ',', value_parser = parse_auth_password)]
    pub auth: Vec<TaskAuth>,
}

impl AuthArgs {
    /// Returns a slice of authorizations.
    ///
    /// If no authorizations were provided, this returns a default slice
    /// representing a single empty password.
    #[must_use]
    pub fn build_auth_list(&self) -> Cow<'_, [TaskAuth]> {
        if self.auth.is_empty() {
            Cow::Owned(vec![TaskAuth::default()])
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

    /// Enable dictionary attack protection.
    #[arg(long = "lock")]
    pub lock: bool,
}

impl CreationArgs {
    /// Parse authorization value and policy digest and create object attributes.
    ///
    /// # Errors
    ///
    /// Returns a `CommandError` if parsing fails.
    pub fn parse(&self, alg: &TpmPublicTemplate) -> Result<(TpmaObject, Tpm2bAuth), CommandError> {
        let user_auth = match &self.password {
            Some(hex_str) => Tpm2bAuth::try_from(hex::decode(hex_str)?.as_slice())
                .map_err(|_| CommandError::CapacityExceeded)?,
            None => Tpm2bAuth::default(),
        };

        let mut attributes = TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT;

        if !self.lock {
            attributes |= TpmaObject::NO_DA;
        }

        if alg.kind != TpmPublicTemplateType::KeyedHash {
            attributes |=
                TpmaObject::SENSITIVE_DATA_ORIGIN | TpmaObject::DECRYPT | TpmaObject::RESTRICTED;
        }

        if self.password.is_some() || self.policy_expression.is_none() {
            attributes |= TpmaObject::USER_WITH_AUTH;
        }
        if self.policy_expression.is_some() {
            attributes |= TpmaObject::ADMIN_WITH_POLICY;
        }

        Ok((attributes, user_auth))
    }
}

/// Resolves the policy expression (if any) into a policy digest and a list of commands.
///
/// # Errors
///
/// Returns [`CommandError`] if policy parsing, name resolution, or PCR reading fails.
#[allow(clippy::type_complexity)]
pub fn build_policy_command_list(
    creation_args: &CreationArgs,
    task_state: &mut TaskState,
    device: &mut TpmDevice,
    name_alg: TpmAlgId,
) -> Result<(Tpm2bDigest, Option<Vec<(TpmCommand, TpmAuthCommands)>>), CommandError> {
    if let Some(expression) = &creation_args.policy_expression {
        let pcrs = read_all_pcrs(task_state, device)?;
        let banks = pcr_get_bank_list(device)?;
        let pcr_count = banks.iter().map(|b| b.count).max().unwrap_or(0);

        let names = fetch_handle_names(task_state, device)?;

        let policy_context = TpmPolicyState {
            pcr_count,
            names,
            pcrs,
        };

        let ast = TpmPolicyExpression::new(expression, &policy_context)?;
        let (commands, final_digest) = ast.to_command_list(name_alg, &policy_context)?;

        Ok((final_digest, Some(commands)))
    } else {
        Ok((Tpm2bDigest::default(), None))
    }
}

/// Fetches a map of all available names (virtual and persistent).
fn fetch_handle_names(
    state: &mut TaskState,
    device: &mut TpmDevice,
) -> Result<HashMap<VtpmHandle, Tpm2bName>, CommandError> {
    let mut map = HashMap::new();

    for (vhandle, key) in state.cache.key_iter() {
        let name = tpm_make_name(&key.public)?;
        map.insert(VtpmHandle::new(VtpmHandleClass::Vtpm, *vhandle), name);
    }

    let handles = device.fetch_handles(TpmHt::Persistent)?;
    for h in handles {
        if let Ok((_, name)) = device.read_public(h) {
            map.insert(VtpmHandle::new(VtpmHandleClass::Tpm, h.0), name);
        }
    }

    Ok(map)
}
