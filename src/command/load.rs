// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Task,
    command::CommandError,
    io::read_file_input,
    response::parse_response,
    task::{Auth, TaskState},
    unmarshal::TpmUnmarshal,
};
use argh::FromArgs;
use std::{ffi::CString, path::PathBuf};
use tpm2_device::{with_device, TpmDevice};
use tpm2_protocol::{
    basic::{TpmHandle, TpmUint32},
    data::{
        Tpm2bData, Tpm2bEncryptedSecret, Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmHt,
        TpmtSymDefObject,
    },
    frame::{TpmLoadCommand, TpmLoadResponse},
};
use tpm2_tpmkey::TpmKeyFile;
use tpm2_vtpm::{vtpm_policy_command_from_parts, VtpmPolicyCommand};

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
    ) -> Result<(), CommandError> {
        let input_bytes = read_file_input(self.input.as_deref())?;

        let tpm_key = TpmKeyFile::from_pem(&input_bytes).map_err(CommandError::from)?;
        let public = Self::parse_public(tpm_key.public())?;
        let private = Self::parse_private(tpm_key.private())?;

        with_device(
            task_state.device.clone(),
            |device| -> Result<(), CommandError> {
                let (parent_public, parent_handle_ref) = {
                    let Some(parent) = self.parent.value() else {
                        return Err(CommandError::PatternNotAllowed(self.parent.to_string()));
                    };
                    Self::parent_from_handle(task_state, device, TpmUint32::new(parent))?
                };

                if let Some(name) = &self.kernel {
                    return Self::load_kernel_key(&tpm_key, name, writer, parent_handle_ref);
                }

                let (parent_handle, _, auth) =
                    task_state.resolve_auth(device, parent_handle_ref)?;

                let object_private = if tpm_key.secret().is_empty() {
                    private
                } else {
                    let in_sym_seed = Tpm2bEncryptedSecret::try_from(tpm_key.secret())
                        .map_err(|_| CommandError::CapacityExceeded)?;

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
                        policy_vec.push(vtpm_policy_command_from_parts(cmd.cc(), cmd.body())?);
                    }
                    Some(policy_vec)
                };

                let object_context = device.save_context(object_handle)?;
                let vhandle = task_state.cache.save_transient(
                    object_context,
                    &public.inner,
                    &parent_public.inner,
                    &policy_blob,
                )?;

                writeln!(writer, "{vhandle:08x}")?;
                Ok(())
            },
        )
    }
}

impl Load {
    fn load_kernel_key(
        tpm_key: &TpmKeyFile,
        name: &str,
        writer: &mut dyn std::io::Write,
        parent_handle: TpmHandle,
    ) -> Result<(), CommandError> {
        if tpm_key.public_alg() != TpmAlgId::KeyedHash {
            return Err(CommandError::UnsupportedKeyAlgorithm);
        }

        let trimmed_key = TpmKeyFile::new()
            .with_kind(tpm_key.kind())
            .with_empty_auth(tpm_key.empty_auth())
            .with_parent(parent_handle)
            .with_public_bytes(tpm_key.public())
            .map_err(CommandError::from)?
            .with_private_bytes(tpm_key.private())
            .map_err(CommandError::from)?;

        let der = trimmed_key.to_der().map_err(CommandError::from)?;
        let payload = format!("load {}", hex::encode(der));

        let type_c = CString::new("trusted")
            .map_err(|_| CommandError::InvalidInput("type contains null byte".to_string()))?;
        let desc_c = CString::new(name)
            .map_err(|_| CommandError::InvalidInput("name contains null byte".to_string()))?;
        let payload_c = CString::new(payload)
            .map_err(|_| CommandError::InvalidInput("payload contains null byte".to_string()))?;

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
            return Err(CommandError::Io(std::io::Error::last_os_error()));
        }

        writeln!(writer, "{ret}")?;
        Ok(())
    }

    fn parse_public(public: &[u8]) -> Result<Tpm2bPublic, CommandError> {
        let (public, rest) = Tpm2bPublic::unmarshal(public).map_err(CommandError::Unmarshal)?;
        if !rest.is_empty() {
            return Err(CommandError::MalformedData);
        }
        Ok(public)
    }

    fn parse_private(private: &[u8]) -> Result<Tpm2bPrivate, CommandError> {
        let (private, rest) = Tpm2bPrivate::unmarshal(private).map_err(CommandError::Unmarshal)?;
        if !rest.is_empty() {
            return Err(CommandError::MalformedData);
        }
        Ok(private)
    }

    fn parent_from_handle(
        task_state: &mut TaskState,
        device: &mut TpmDevice,
        parent: TpmHandle,
    ) -> Result<(Tpm2bPublic, TpmHandle), CommandError> {
        let value = parent.value();

        if (value >> 24) as u8 == TpmHt::Persistent as u8 {
            let (public, _) = device.read_public(TpmUint32::new(value))?;
            Ok((Tpm2bPublic { inner: public }, parent))
        } else {
            let key = task_state
                .cache
                .find_by_handle(TpmUint32::new(value))
                .ok_or(CommandError::ParentMissing)?;
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
    ) -> Result<(TpmHandle, Tpm2bPublic), CommandError> {
        let cmd = TpmLoadCommand {
            in_private: *in_private,
            in_public: in_public.clone(),
            handles: [parent_handle],
        };

        let resp = task_state.execute(device, &cmd, auths)?;
        let resp = parse_response::<TpmLoadResponse>(resp)?;

        task_state.track(device, resp.handles[0])?;
        Ok((resp.handles[0], in_public.clone()))
    }
}
