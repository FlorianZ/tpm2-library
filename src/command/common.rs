// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Hierarchy,
    command::CommandError,
    handle::Handle,
    pcr::read_all_pcrs,
    task::{Auth, TaskState},
};
use clap::{Args, ValueEnum};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    str::FromStr,
};
use strum::{Display, EnumString};
use tpm2_crypto::{tpm_make_name, TpmPublicTemplate};
use tpm2_device::TpmDevice;
use tpm2_policy_language::{TpmPolicyExpression, TpmPolicyState};
use tpm2_protocol::{
    basic::{TpmHandle, TpmUint32},
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bName, Tpm2bSensitiveData, TpmAlgId, TpmHt, TpmRh, TpmaObject,
    },
    frame::{TpmAuthCommands, TpmCommand},
};

fn parse_handle_target(s: &str) -> Result<TpmHandle, String> {
    match s {
        "owner" => Ok(TpmUint32(TpmRh::Owner as u32)),
        "platform" => Ok(TpmUint32(TpmRh::Platform as u32)),
        "endorsement" => Ok(TpmUint32(TpmRh::Endorsement as u32)),
        "null" => Ok(TpmUint32(TpmRh::Null as u32)),
        "lockout" => Ok(TpmUint32(TpmRh::Lockout as u32)),
        _ => {
            let handle = Handle::from_str(s).map_err(|e| e.to_string())?;
            let value = handle.value().ok_or("handle pattern not allowed here")?;
            Ok(TpmUint32(value))
        }
    }
}

/// Parses an authentication entry in the format `<handle>:<value>`.
///
/// # Errors
///
/// Returns an error when the string is not formatted correctly, the handle is
/// invalid, or the hex value is malformed.
fn parse_auth(s: &str) -> Result<(TpmHandle, Auth), String> {
    let (handle_str, auth_str) = s
        .split_once(':')
        .ok_or_else(|| "format must be <handle>:<value>".to_string())?;

    let handle = parse_handle_target(handle_str)?;
    let auth = hex::decode(auth_str)
        .map(Auth::Password)
        .map_err(|e| e.to_string())?;

    Ok((handle, auth))
}

#[derive(Args, Debug, Clone, Default)]
pub struct AuthArgs {
    /// List of authentication values in the format '<handle>:<hex string>'.
    #[arg(short = 'A', long = "auth", value_delimiter = ',', value_parser = parse_auth)]
    pub auth: Vec<(TpmHandle, Auth)>,
}

impl AuthArgs {
    /// Builds a map of handle-specific authorizations.
    #[must_use]
    pub fn build_auth_map(&self) -> HashMap<TpmHandle, Auth> {
        self.auth.iter().cloned().collect()
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
    #[arg(short = 'e', long = "encoding", value_enum, default_value_t = OutputEncoding::default())]
    pub encoding: OutputEncoding,
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
    /// Parses the password into a TPM authorization value.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::InvalidPassword`] when the hex string is
    /// malformed, or [`CommandError::CapacityExceeded`] when the password is
    /// too long.
    pub fn parse_password(&self) -> Result<Tpm2bAuth, CommandError> {
        match &self.password {
            Some(hex_str) => Tpm2bAuth::try_from(
                hex::decode(hex_str)
                    .map_err(|_| CommandError::InvalidPassword)?
                    .as_slice(),
            )
            .map_err(|_| CommandError::CapacityExceeded),
            None => Ok(Tpm2bAuth::default()),
        }
    }

    /// Creates object attributes based on the algorithm and policy configuration.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError`] when attribute construction fails.
    pub fn parse_attributes(&self, alg: &TpmPublicTemplate) -> Result<TpmaObject, CommandError> {
        let mut attributes = TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT;

        if !self.lock {
            attributes |= TpmaObject::NO_DA;
        }

        if alg.object_type() != TpmAlgId::KeyedHash {
            attributes |=
                TpmaObject::SENSITIVE_DATA_ORIGIN | TpmaObject::DECRYPT | TpmaObject::RESTRICTED;
        }

        if self.password.is_some() || self.policy_expression.is_none() {
            attributes |= TpmaObject::USER_WITH_AUTH;
        }
        if self.policy_expression.is_some() {
            attributes |= TpmaObject::ADMIN_WITH_POLICY;
        }

        Ok(attributes)
    }
}

/// Resolves the policy expression (if any) into a policy digest and a list of
/// commands.
///
/// # Errors
///
/// Returns [`CommandError`] when policy parsing, name resolution, or PCR
/// reading fails.
#[allow(clippy::type_complexity)]
pub fn build_policy_command_list(
    creation_args: &CreationArgs,
    task_state: &mut TaskState,
    device: &mut TpmDevice,
    name_alg: TpmAlgId,
) -> Result<(Tpm2bDigest, Option<Vec<(TpmCommand, TpmAuthCommands)>>), CommandError> {
    if let Some(expression) = &creation_args.policy_expression {
        let pcrs = read_all_pcrs(device)?;
        let names = fetch_handle_names(task_state, device)?;

        let policy_context = TpmPolicyState::new(names, pcrs)?;
        let ast = TpmPolicyExpression::new(expression, &policy_context)?;
        let (commands, final_digest) = ast.to_command_list(name_alg, &policy_context)?;

        Ok((final_digest, Some(commands)))
    } else {
        Ok((Tpm2bDigest::default(), None))
    }
}

/// Resolves and validates sensitive data based on the algorithm and input
/// sources.
///
/// - If `data_hex` is provided, it is treated as a hex string.
/// - If `input_path` is provided, it is read as raw binary.
///
/// # Errors
///
/// Returns [`InvalidSensitiveData`](CommandError::InvalidSensitiveData)
/// when the hex string is malformed.
/// Returns [`Io`](CommandError::Io) if reading the input file fails.
/// Returns [`SensitiveDataMissing`](CommandError::SensitiveDataMissing)
/// when the sensitive data is empty or missing for a keyed hash or symmetric
/// key.
/// Returns [`CapacityExceeded`](CommandError::CapacityExceeded) when
/// the sensitive data exceeds the maximum allowed size.
/// Returns [`SensitiveDataDenied`](CommandError::SensitiveDataDenied)
/// when sensitive data is provided for an asymmetric key.
/// Returns [`UnsupportedKeyAlgorithm`](CommandError::UnsupportedKeyAlgorithm)
/// when the algorithm is not supported.
pub fn resolve_sensitive_data(
    data_hex: Option<&str>,
    input_path: Option<&Path>,
    alg: TpmAlgId,
) -> Result<Tpm2bSensitiveData, CommandError> {
    let bytes = if let Some(hex_str) = data_hex {
        hex::decode(hex_str).map_err(|_| CommandError::InvalidSensitiveData)?
    } else if let Some(path) = input_path {
        std::fs::read(path)?
    } else {
        Vec::new()
    };

    match alg {
        TpmAlgId::KeyedHash | TpmAlgId::SymCipher => {
            if bytes.is_empty() {
                return Err(CommandError::SensitiveDataMissing);
            }
            Tpm2bSensitiveData::try_from(bytes.as_slice())
                .map_err(|_| CommandError::CapacityExceeded)
        }
        TpmAlgId::Rsa | TpmAlgId::Ecc => {
            if !bytes.is_empty() {
                return Err(CommandError::SensitiveDataDenied);
            }
            Ok(Tpm2bSensitiveData::default())
        }
        _ => Err(CommandError::UnsupportedKeyAlgorithm),
    }
}

/// Fetches a map of all available names (virtual and persistent).
fn fetch_handle_names(
    state: &mut TaskState,
    device: &mut TpmDevice,
) -> Result<HashMap<TpmHandle, Tpm2bName>, CommandError> {
    let mut map = HashMap::new();

    for (vhandle, key) in state.cache.key_iter() {
        let name = tpm_make_name(key.public())?;
        map.insert(TpmUint32(*vhandle), name);
    }

    let handles = device.fetch_handles(TpmHt::Persistent)?;
    for h in handles {
        if let Ok((_, name)) = device.read_public(h) {
            map.insert(TpmUint32(h.0), name);
        }
    }

    Ok(map)
}
