// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{Hierarchy, OutputEncoding},
    command::CommandError,
    handle::Handle,
    pcr::read_all_pcrs,
    task::{Auth, TaskState},
};
use clap::Args;
use std::{collections::HashMap, path::PathBuf, str::FromStr};
use tpm2_crypto::{tpm_make_name, TpmPublicTemplate};
use tpm2_device::TpmDevice;
use tpm2_policy_language::{TpmPolicyExpression, TpmPolicyState};
use tpm2_protocol::{
    basic::{TpmHandle, TpmUint16, TpmUint32},
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bName, TpmAlgId, TpmHt, TpmRh, TpmaObject, TpmsSchemeHash,
        TpmtPublic, TpmtSymDefObject, TpmuKeyedhashScheme, TpmuPublicParms, TpmuSymKeyBits,
        TpmuSymMode,
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
pub fn parse_auth(s: &str) -> Result<(TpmHandle, Auth), String> {
    let (handle_str, auth_str) = s
        .split_once(':')
        .ok_or_else(|| "format must be <handle>:<value>".to_string())?;

    let handle_str = handle_str.trim();
    let auth_str = auth_str.trim();

    let handle = parse_handle_target(handle_str)?;
    let auth = hex::decode(auth_str)
        .map(Auth::Password)
        .map_err(|e| e.to_string())?;

    Ok((handle, auth))
}

/// Builds a map of handle-specific authorizations.
///
/// # Errors
///
/// Returns [`CommandError::InvalidInput`] if the `TPM2SH_AUTH` environment
/// variable contains malformed authentication entries.
pub fn build_auth_map(
    auth_entries: &[(TpmHandle, Auth)],
) -> Result<HashMap<TpmHandle, Auth>, CommandError> {
    let mut map = HashMap::new();

    if let Ok(env_str) = std::env::var("TPM2SH_AUTH") {
        for s in env_str.split(',') {
            if s.trim().is_empty() {
                continue;
            }
            let (handle, auth) =
                parse_auth(s).map_err(|e| CommandError::InvalidInput(format!("{s}: {e}")))?;
            map.insert(handle, auth);
        }
    }

    for (handle, auth) in auth_entries {
        map.insert(*handle, auth.clone());
    }

    Ok(map)
}

#[derive(Args, Debug, Clone)]
pub struct InputArgs {
    /// Input file path (defaults to stdin as hex-encoded DER)
    #[arg(short = 'I', long)]
    pub input: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct OutputArgs {
    /// Output file path (defaults to stdout as hex-encoded DER)
    #[arg(short = 'O', long)]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct OutputEncodingArgs {
    /// Output encoding for file output (ignored for stdout): pem or der
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
        let mut attributes =
            TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT | TpmaObject::SENSITIVE_DATA_ORIGIN;

        if !self.lock {
            attributes |= TpmaObject::NO_DA;
        }

        if alg.object_type() == TpmAlgId::KeyedHash {
            attributes |= TpmaObject::SIGN_ENCRYPT;
        } else {
            attributes |= TpmaObject::DECRYPT | TpmaObject::RESTRICTED;
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
) -> Result<(Tpm2bDigest, Vec<(TpmCommand, TpmAuthCommands)>), CommandError> {
    if let Some(expression) = &creation_args.policy_expression {
        let pcrs = read_all_pcrs(device)?;
        let names = fetch_handle_names(task_state, device)?;

        let policy_context = TpmPolicyState::new(names, pcrs)?;
        let ast = TpmPolicyExpression::new(expression, &policy_context)?;
        let (commands, final_digest) = ast.to_command_list(name_alg, &policy_context)?;

        Ok((final_digest, commands))
    } else {
        Ok((Tpm2bDigest::default(), Vec::new()))
    }
}

/// Constructs a `TpmtPublic` structure from a template, attributes, and policy.
///
/// This function applies default symmetric parameters (AES-128-CFB) and ensures
/// `KeyedHash` objects have a valid scheme (defaulting to HMAC if Null).
///
/// # Errors
///
/// Returns [`CommandError`] if the template conversion fails.
pub fn resolve_public_template(
    template: &TpmPublicTemplate,
    attributes: TpmaObject,
    auth_policy: Tpm2bDigest,
) -> Result<TpmtPublic, CommandError> {
    let symmetric = TpmtSymDefObject {
        algorithm: TpmAlgId::Aes,
        key_bits: TpmuSymKeyBits::Aes(TpmUint16::from(128)),
        mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
    };

    let template_with_attrs = template
        .clone()
        .with_object_attributes(attributes)
        .with_auth_policy(auth_policy)
        .with_symmetric(symmetric);

    let mut public_area: TpmtPublic = template_with_attrs.try_into()?;

    if public_area.object_type == TpmAlgId::KeyedHash {
        if let TpmuPublicParms::KeyedHash(parms) = &mut public_area.parameters {
            if parms.scheme.scheme == TpmAlgId::Null {
                parms.scheme.scheme = TpmAlgId::Hmac;
                parms.scheme.details = TpmuKeyedhashScheme::Hmac(TpmsSchemeHash {
                    hash_alg: public_area.name_alg,
                });
            }
        }
    }

    Ok(public_area)
}

/// Fetches the mapping of persistent handles to their names from the device.
///
/// # Errors
///
/// Returns [`CommandError::Device`] if fetching handles fails.
pub fn fetch_persistent_names(
    device: &mut TpmDevice,
) -> Result<HashMap<TpmHandle, Tpm2bName>, CommandError> {
    let mut map = HashMap::new();
    let handles = device.fetch_handles(TpmHt::Persistent)?;

    for h in handles {
        if let Ok((_, name)) = device.read_public(h) {
            map.insert(h, name);
        }
    }

    Ok(map)
}

/// Fetches a map of all available names (virtual and persistent).
fn fetch_handle_names(
    state: &mut TaskState,
    device: &mut TpmDevice,
) -> Result<HashMap<TpmHandle, Tpm2bName>, CommandError> {
    let mut map = fetch_persistent_names(device)?;

    for (vhandle, key) in state.cache.key_iter() {
        let name = tpm_make_name(key.public())?;
        map.insert(TpmUint32(*vhandle), name);
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tpm2_protocol::{basic::TpmUint32, data::TpmRh};

    #[test]
    fn parse_auth_trims_whitespace() {
        let (handle, auth) = parse_auth(" owner : deadbeef ").unwrap();
        assert_eq!(handle, TpmUint32(TpmRh::Owner as u32));
        assert!(matches!(auth, Auth::Password(bytes) if bytes == hex::decode("deadbeef").unwrap()));
    }

    #[test]
    fn build_auth_map_wraps_entry_in_error() {
        env::set_var("TPM2SH_AUTH", "owner:not-hex");
        let empty_entries = vec![];
        let err = build_auth_map(&empty_entries).unwrap_err();
        assert!(matches!(err, CommandError::InvalidInput(msg) if msg.contains("owner:not-hex")));
        env::remove_var("TPM2SH_AUTH");
    }
}
