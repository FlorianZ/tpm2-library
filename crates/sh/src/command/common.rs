// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    error::device_err,
    handle::Handle,
    pcr::read_all_pcrs,
    task::{Auth, TaskState},
};
use anyhow::{Context, Result, anyhow};
use std::{collections::HashMap, str::FromStr};
use tpm2_crypto::{TpmPublicTemplate, tpm_make_name};
use tpm2_device::TpmDevice;
use tpm2_policy_language::{TpmPolicyContext, TpmPolicyExpression};
use tpm2_protocol::{
    basic::{TpmHandle, TpmUint16, TpmUint32},
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bName, TpmAlgId, TpmHt, TpmRh, TpmaObject, TpmtPublic,
        TpmtSymDefObject, TpmuSymKeyBits, TpmuSymMode,
    },
    frame::{TpmAuthCommands, TpmCommandValue as TpmCommand},
};

fn parse_handle_target(s: &str) -> Result<TpmHandle, String> {
    match s {
        "owner" => Ok(TpmUint32::new(TpmRh::Owner as u32)),
        "platform" => Ok(TpmUint32::new(TpmRh::Platform as u32)),
        "endorsement" => Ok(TpmUint32::new(TpmRh::Endorsement as u32)),
        "null" => Ok(TpmUint32::new(TpmRh::Null as u32)),
        "lockout" => Ok(TpmUint32::new(TpmRh::Lockout as u32)),
        _ => {
            let handle = Handle::from_str(s).map_err(|e| e.to_string())?;
            let value = handle.value().ok_or("handle pattern not allowed here")?;
            Ok(TpmUint32::new(value))
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
/// Returns an error if the `TPM2SH_AUTH` environment variable contains
/// malformed authentication entries.
pub fn build_auth_map(auth_entries: &[(TpmHandle, Auth)]) -> Result<HashMap<TpmHandle, Auth>> {
    let mut map = HashMap::new();

    if let Ok(env_str) = std::env::var("TPM2SH_AUTH") {
        for s in env_str.split(',') {
            if s.trim().is_empty() {
                continue;
            }
            let (handle, auth) = parse_auth(s).map_err(|e| anyhow!("invalid input: {s}: {e}"))?;
            map.insert(handle, auth);
        }
    }

    for (handle, auth) in auth_entries {
        map.insert(*handle, auth.clone());
    }

    Ok(map)
}

/// Parses a password into a TPM authorization value.
///
/// # Errors
///
/// Returns an error when the hex string is malformed or the password is too
/// long.
pub fn parse_password(password: Option<&str>) -> Result<Tpm2bAuth> {
    match password {
        Some(hex_str) => Tpm2bAuth::try_from(
            hex::decode(hex_str)
                .map_err(|_| anyhow!("password is not a valid hex string"))?
                .as_slice(),
        )
        .map_err(|_| anyhow!("capacity exceeded")),
        None => Ok(Tpm2bAuth::default()),
    }
}

fn parse_auth_attributes(
    password: Option<&str>,
    policy_expression: Option<&str>,
    lock: bool,
) -> TpmaObject {
    let mut attributes = TpmaObject::empty();

    if !lock {
        attributes |= TpmaObject::NO_DA;
    }
    if password.is_some() || policy_expression.is_none() {
        attributes |= TpmaObject::USER_WITH_AUTH;
    }
    if policy_expression.is_some() {
        attributes |= TpmaObject::ADMIN_WITH_POLICY;
    }

    attributes
}

/// Creates object attributes for `TPM2_Create` / `TPM2_CreatePrimary`.
///
/// Usage bits (`DECRYPT`, `SIGN_ENCRYPT`, `RESTRICTED`) come from the
/// algorithm string. Created objects also get `FIXED_TPM`, `FIXED_PARENT`,
/// and `SENSITIVE_DATA_ORIGIN`.
///
/// # Errors
///
/// Returns an error when attribute construction fails.
pub fn parse_creation_attributes(
    password: Option<&str>,
    policy_expression: Option<&str>,
    lock: bool,
    alg: &TpmPublicTemplate,
) -> Result<TpmaObject> {
    let mut attributes =
        TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT | TpmaObject::SENSITIVE_DATA_ORIGIN;
    attributes |= parse_auth_attributes(password, policy_expression, lock);
    attributes |= alg.usage_attributes();
    Ok(attributes)
}

/// Creates object attributes for `TPM2_Import`.
///
/// Imported keys are not TPM-generated, so they omit `FIXED_TPM`,
/// `FIXED_PARENT`, and `SENSITIVE_DATA_ORIGIN`. Usage bits come from the
/// algorithm string.
///
/// # Errors
///
/// Returns an error when attribute construction fails.
pub fn parse_import_attributes(
    password: Option<&str>,
    policy_expression: Option<&str>,
    lock: bool,
    alg: &TpmPublicTemplate,
) -> Result<TpmaObject> {
    Ok(parse_auth_attributes(password, policy_expression, lock) | alg.usage_attributes())
}

/// Resolves the policy expression (if any) into a policy digest and a list of
/// commands.
///
/// # Errors
///
/// Returns an error when policy parsing, name resolution, or PCR reading fails.
#[allow(clippy::type_complexity)]
pub fn build_policy_command_list(
    policy_expression: Option<&str>,
    task_state: &mut TaskState,
    device: &mut TpmDevice,
    name_alg: TpmAlgId,
) -> Result<(Tpm2bDigest, Vec<(TpmCommand, TpmAuthCommands)>)> {
    if let Some(expression) = policy_expression {
        let pcrs = read_all_pcrs(device)?;
        let names = fetch_handle_names(task_state, device)?;

        let policy_context = {
            let mut b = TpmPolicyContext::builder().with_names(names);
            for (alg, bank) in pcrs {
                b = b.with_pcr_bank(alg, bank);
            }
            b.build().context("policy")?
        };
        let ast = TpmPolicyExpression::parse(expression, &policy_context).context("policy")?;
        let compiled = ast.compile(name_alg, &policy_context).context("policy")?;
        let (commands, final_digest) = compiled.into_parts();

        Ok((final_digest, commands))
    } else {
        Ok((Tpm2bDigest::default(), Vec::new()))
    }
}

/// Returns the default symmetric parameters (AES-128-CFB) used to wrap the
/// sensitive area of storage and sealed objects.
#[must_use]
pub fn default_symmetric() -> TpmtSymDefObject {
    TpmtSymDefObject {
        algorithm: TpmAlgId::Aes,
        key_bits: TpmuSymKeyBits::Aes(TpmUint16::from(128)),
        mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
    }
}

/// Constructs a `TpmtPublic` structure from a template, attributes, and policy.
///
/// Restricted storage parents get AES-128-CFB wrapping. Other objects keep a
/// NULL symmetric definition.
///
/// # Errors
///
/// Returns an error if the template conversion fails.
pub fn resolve_public_template(
    template: &TpmPublicTemplate,
    attributes: TpmaObject,
    auth_policy: Tpm2bDigest,
) -> Result<TpmtPublic> {
    let symmetric = if template.is_storage_parent() {
        default_symmetric()
    } else {
        TpmtSymDefObject::default()
    };

    let template_with_attrs = template
        .clone()
        .with_object_attributes(attributes)
        .with_auth_policy(auth_policy)
        .with_symmetric(symmetric);

    Ok((&template_with_attrs).try_into()?)
}

/// Fetches the mapping of persistent handles to their names from the device.
///
/// # Errors
///
/// Returns an error if fetching handles fails.
pub fn fetch_persistent_names(device: &mut TpmDevice) -> Result<HashMap<TpmHandle, Tpm2bName>> {
    let mut map = HashMap::new();
    let handles = device
        .fetch_handles(TpmHt::Persistent)
        .map_err(device_err)?;

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
) -> Result<HashMap<TpmHandle, Tpm2bName>> {
    let mut map = fetch_persistent_names(device)?;

    for (vhandle, key) in state.cache.key_iter() {
        let name = tpm_make_name(key.public())?;
        map.insert(vhandle, name);
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
        assert_eq!(handle, TpmUint32::new(TpmRh::Owner as u32));
        assert!(matches!(auth, Auth::Password(bytes) if bytes == hex::decode("deadbeef").unwrap()));
    }

    #[test]
    fn build_auth_map_wraps_entry_in_error() {
        unsafe {
            env::set_var("TPM2SH_AUTH", "owner:not-hex");
        }
        let empty_entries = vec![];
        let err = build_auth_map(&empty_entries).unwrap_err();
        assert!(err.to_string().contains("owner:not-hex"));
        unsafe {
            env::remove_var("TPM2SH_AUTH");
        }
    }
}
