// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Task,
    error::device_err,
    handle::handle_type,
    io::read_file_input,
    task::{Auth, TaskState},
};
use anyhow::{Context, Result, anyhow};
use argh::FromArgs;
use std::{ffi::CString, path::PathBuf};
use tpm2_device::{TpmDevice, with_device};
use tpm2_protocol::{
    TpmUnmarshal,
    basic::{TpmHandle, TpmUint32},
    data::{
        Tpm2bData, Tpm2bEncryptedSecret, Tpm2bPrivate, Tpm2bPublic, TpmCc, TpmHt, TpmtSymDefObject,
    },
    frame::{TpmLoadCommand, TpmLoadResponse},
};
use tpm2_tpmkey::{TpmKeyFile, TpmKeyType};
use tpm2_vtpm::{VtpmPolicyCommand, vtpm_policy_command_from_parts};

/// Loads a PEM or DER TPMKey file to cache.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "load", help_triggers("-h", "--help", "help"))]
pub struct Load {
    /// input file path (defaults to stdin as PEM)
    #[argh(option, short = 'I')]
    pub input: Option<PathBuf>,

    /// parent's TPM handle as an eight characters hex string
    #[argh(positional)]
    pub parent: crate::handle::Handle,

    /// load to the kernel keyring as a trusted key with the given name
    #[argh(option)]
    pub kernel: Option<String>,
}

impl Task for Load {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<()> {
        let input_bytes = read_file_input(self.input.as_deref())?;
        let tpm_key =
            TpmKeyFile::from_pem(&input_bytes).or_else(|_| TpmKeyFile::from_der(&input_bytes))?;
        let parent = self
            .parent
            .require_value()
            .map_err(|_| anyhow!("handle pattern not allowed: {}", self.parent))?;

        if let Some(name) = &self.kernel {
            return Self::load_kernel_key(&tpm_key, name, writer, TpmUint32::new(parent));
        }

        if tpm_key.auth_policy().is_some() {
            return Err(anyhow!("authPolicy extension is not supported for loading"));
        }

        let public = Self::parse_public(tpm_key.public())?;
        let private = Self::parse_private(tpm_key.private())?;

        with_device(task_state.device.clone().as_ref(), |device| -> Result<()> {
            let (parent_public, parent_handle_ref) =
                Self::parent_from_handle(task_state, device, TpmUint32::new(parent))?;
            let (parent_handle, _, auth) = task_state.resolve_auth(device, parent_handle_ref)?;

            let object_private = if tpm_key.secret().is_empty() {
                private
            } else {
                let (in_sym_seed, rest) = Tpm2bEncryptedSecret::unmarshal(tpm_key.secret())
                    .map_err(|_| anyhow!("invalid TPM2B_ENCRYPTED_SECRET in secret field"))?;
                if !rest.is_empty() {
                    return Err(anyhow!("trailing data in secret field"));
                }

                task_state.import_key(
                    device,
                    parent_handle,
                    &public,
                    &private,
                    &in_sym_seed,
                    &Tpm2bData::default(),
                    &TpmtSymDefObject::default(),
                    std::slice::from_ref(&auth),
                )?
            };

            let (object_handle, public) = Self::run_load(
                task_state,
                device,
                parent_handle,
                &object_private,
                &public,
                &[auth],
            )?;

            let policy_blob = if tpm_key.policy().is_empty() {
                None
            } else {
                let mut policy_vec: Vec<Box<dyn VtpmPolicyCommand>> = Vec::new();
                for cmd in tpm_key.policy() {
                    if cmd.cc() == TpmCc::PolicyAuthorize {
                        return Err(anyhow!("PolicyAuthorize is not supported for loading"));
                    }
                    policy_vec.push(vtpm_policy_command_from_parts(cmd.cc(), cmd.body())?);
                }
                Some(policy_vec)
            };

            let object_context = device.save_context(object_handle).map_err(device_err)?;
            let vhandle = task_state.cache.save_transient(
                object_context,
                &public.inner,
                &parent_public.inner,
                policy_blob.as_deref(),
            )?;

            writeln!(writer, "{vhandle:08x}")?;
            Ok(())
        })
    }

    fn is_local(&self) -> bool {
        self.kernel.is_some()
    }
}

impl Load {
    fn load_kernel_key(
        tpm_key: &TpmKeyFile,
        name: &str,
        writer: &mut dyn std::io::Write,
        parent_handle: TpmHandle,
    ) -> Result<()> {
        if tpm_key.kind() != TpmKeyType::SealedData {
            return Err(anyhow!("kernel trusted keys require sealed data"));
        }

        if handle_type(parent_handle.value()) != Some(TpmHt::Persistent) {
            return Err(anyhow!("kernel trusted keys require a persistent parent"));
        }

        if !tpm_key.empty_auth() {
            return Err(anyhow!(
                "kernel trusted keys require an empty authorization value"
            ));
        }

        let public = Self::parse_public(tpm_key.public())?;
        if !tpm_key.policy().is_empty()
            || tpm_key.auth_policy().is_some()
            || !public.inner.auth_policy.is_empty()
        {
            return Err(anyhow!(
                "kernel trusted keys do not support policy authorization"
            ));
        }

        if !tpm_key.secret().is_empty() {
            return Err(anyhow!("kernel trusted keys do not support import secrets"));
        }

        let trimmed_key = TpmKeyFile::new()
            .with_kind(tpm_key.kind())
            .with_empty_auth(tpm_key.empty_auth())
            .with_parent(parent_handle)
            .with_public_bytes(tpm_key.public())?
            .with_private_bytes(tpm_key.private())?;

        let der = trimmed_key.to_der()?;
        let payload = format!("load {}", hex::encode(der));

        let type_c = CString::new("trusted")
            .map_err(|_| anyhow!("invalid input: type contains null byte"))?;
        let desc_c =
            CString::new(name).map_err(|_| anyhow!("invalid input: name contains null byte"))?;
        let payload_c = CString::new(payload)
            .map_err(|_| anyhow!("invalid input: payload contains null byte"))?;

        let ret = unsafe {
            libc::syscall(
                libc::SYS_add_key,
                type_c.as_ptr(),
                desc_c.as_ptr(),
                payload_c.as_ptr().cast::<libc::c_void>(),
                payload_c.as_bytes().len(),
                libc::KEY_SPEC_USER_KEYRING,
            )
        };

        if ret < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENODEV) {
                return Err(error).context(
                    "kernel trusted-key backend unavailable; check CONFIG_TRUSTED_KEYS and CONFIG_TRUSTED_KEYS_TPM",
                );
            }
            return Err(error).context("failed to add trusted key to the user keyring");
        }

        writeln!(writer, "{ret}")?;
        Ok(())
    }

    fn parse_public(public: &[u8]) -> Result<Tpm2bPublic> {
        let (public, rest) = Tpm2bPublic::unmarshal(public)?;
        if !rest.is_empty() {
            return Err(anyhow!("malformed data"));
        }
        Ok(public)
    }

    fn parse_private(private: &[u8]) -> Result<Tpm2bPrivate> {
        let (private, rest) = Tpm2bPrivate::unmarshal(private)?;
        if !rest.is_empty() {
            return Err(anyhow!("malformed data"));
        }
        Ok(private)
    }

    fn parent_from_handle(
        task_state: &mut TaskState,
        device: &mut TpmDevice,
        parent: TpmHandle,
    ) -> Result<(Tpm2bPublic, TpmHandle)> {
        let value = parent.value();

        if handle_type(value) == Some(TpmHt::Persistent) {
            let (public, _) = device
                .read_public(TpmUint32::new(value))
                .map_err(device_err)?;
            Ok((Tpm2bPublic { inner: public }, parent))
        } else {
            let key = task_state
                .cache
                .find_by_handle(TpmUint32::new(value))
                .ok_or_else(|| anyhow!("parent missing"))?;
            Ok((
                Tpm2bPublic {
                    inner: key.public().clone(),
                },
                parent,
            ))
        }
    }

    fn run_load(
        task_state: &mut TaskState,
        device: &mut TpmDevice,
        parent_handle: TpmHandle,
        in_private: &tpm2_protocol::data::Tpm2bPrivate,
        in_public: &Tpm2bPublic,
        auths: &[Auth],
    ) -> Result<(TpmHandle, Tpm2bPublic)> {
        let cmd = TpmLoadCommand {
            in_private: *in_private,
            in_public: in_public.clone(),
            handles: [parent_handle],
        };

        let resp = task_state.execute(device, &cmd, auths)?;
        let resp = resp.unmarshal::<TpmLoadResponse>()?;

        task_state.track(device, resp.handles[0])?;
        Ok((resp.handles[0], in_public.clone()))
    }
}
