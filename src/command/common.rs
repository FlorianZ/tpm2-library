// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Hierarchy,
    command::CommandError,
    pcr::{pcr_get_bank_list, resolve_pcr_digests},
    task::{TaskAuth, TaskState},
};
use clap::{Args, ValueEnum};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    hash::BuildHasher,
    path::PathBuf,
};
use strum::{Display, EnumString};
use tpm2_crypto::{tpm_make_name, TpmPublicTemplate, TpmPublicTemplateType};
use tpm2_device::TpmDevice;
use tpm2_policy_language::TpmPolicyExpression;
use tpm2_protocol::{
    data::{Tpm2bAuth, Tpm2bDigest, TpmAlgId, TpmHt, TpmaObject},
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
    /// representing a single empty password, unless `empty_auth` is true.
    ///
    /// # Errors
    ///
    /// Returns a `CommandError` if a non-password auth is encountered.
    #[must_use]
    pub fn auths(&self, empty_auth: bool) -> Cow<'_, [TaskAuth]> {
        if self.auth.is_empty() {
            if empty_auth {
                Cow::Owned(vec![])
            } else {
                Cow::Owned(vec![TaskAuth::default()])
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
pub fn resolve_policy(
    creation_args: &CreationArgs,
    task_state: &mut TaskState,
    device: &mut TpmDevice,
    name_alg: TpmAlgId,
) -> Result<(Tpm2bDigest, Option<Vec<(TpmCommand, TpmAuthCommands)>>), CommandError> {
    if let Some(expression) = &creation_args.policy_expression {
        let banks = pcr_get_bank_list(device)?;
        let pcr_count = banks.iter().map(|b| b.count).max().unwrap_or(0);

        let static_pcr_banks: Vec<TpmAlgId> = banks.iter().map(|b| b.alg).collect();

        let tmp_policy_context = tpm2_policy_language::TpmPolicyState {
            pcr_count,
            pcr_banks: static_pcr_banks.clone(),
            names: HashMap::new(),
        };

        let mut ast = TpmPolicyExpression::new(expression, &tmp_policy_context)?;

        let mut handles: HashSet<VtpmHandle> = HashSet::new();
        visit_secret_handles(&ast, &mut handles)?;

        let mut names = HashMap::new();
        for handle in handles {
            let name = match handle.class() {
                VtpmHandleClass::Tpm => {
                    let (_, name) =
                        device.read_public(handle.value().unwrap_or_default().into())?;
                    name
                }
                VtpmHandleClass::Vtpm => {
                    let vhandle = handle.value().unwrap_or_default();
                    let key = task_state
                        .cache
                        .find_by_virtual_handle(tpm2_protocol::TpmHandle(vhandle))?;
                    tpm_make_name(&key.public)?
                }
            };
            names.insert(handle, name);
        }

        let policy_context = tpm2_policy_language::TpmPolicyState {
            pcr_count,
            pcr_banks: static_pcr_banks,
            names,
        };

        resolve_pcr_digests(task_state, device, &mut ast, name_alg, &banks)?;

        let (commands, final_digest) = ast.to_command_list(name_alg, &policy_context)?;

        Ok((final_digest, Some(commands)))
    } else {
        Ok((Tpm2bDigest::default(), None))
    }
}

fn visit_secret_handles<S: BuildHasher>(
    ast: &TpmPolicyExpression,
    handles: &mut HashSet<VtpmHandle, S>,
) -> Result<(), CommandError> {
    match ast {
        TpmPolicyExpression::Pcr { .. } | TpmPolicyExpression::Handle(_) => {}
        TpmPolicyExpression::And(branches) | TpmPolicyExpression::Or(branches) => {
            for branch in branches {
                visit_secret_handles(branch, handles)?;
            }
        }
        TpmPolicyExpression::Secret { auth_handle, .. } => {
            if let TpmPolicyExpression::Handle(handle) = &**auth_handle {
                let Some(val) = handle.value() else {
                    return Err(CommandError::PatternNotAllowed(auth_handle.to_string()));
                };

                if handle.class() == VtpmHandleClass::Tpm
                    && (val >> 24) as u8 != TpmHt::Persistent as u8
                {
                    return Err(CommandError::InvalidHandle);
                }
                handles.insert(*handle);
            } else {
                return Err(CommandError::InvalidPolicyExpression(
                    "secret() first argument must be a handle".to_string(),
                ));
            }
        }
    }
    Ok(())
}
