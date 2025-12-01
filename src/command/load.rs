// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Task,
    command::{AuthArgs, CommandError, InputArgs},
    io::read_file_input,
    task::{Auth, TaskState},
};
use clap::Args;
use tpm2_device::{with_device, TpmDevice};
use tpm2_protocol::{
    basic::{TpmHandle, TpmUint32},
    data::{Tpm2bPublic, TpmCc, TpmHt},
    frame::TpmLoadCommand,
};
use tpm2_tpmkey::TpmKeyFile;
use tpm2_vtpm::{vtpm_policy_command_from_parts, VtpmPolicyCommand};

/// Loads a PEM or DER TPMKey file to cache.
#[derive(Args, Debug)]
#[command(verbatim_doc_comment)]
pub struct Load {
    #[clap(flatten)]
    pub auth_args: AuthArgs,

    #[clap(flatten)]
    pub input_args: InputArgs,

    /// Parent's TPM handle as an eight characters hex string.
    pub parent: crate::handle::Handle,
}

impl Task for Load {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<(), CommandError> {
        with_device(
            task_state.device.clone(),
            |device| -> Result<(), CommandError> {
                let input_bytes = read_file_input(self.input_args.input.as_deref())?;
                if input_bytes.is_empty() {
                    return Ok(());
                }

                let tpm_key = TpmKeyFile::from_pem(&input_bytes)
                    .or_else(|_| TpmKeyFile::from_der(&input_bytes).map_err(CommandError::from))?;

                let (parent_public, parent_handle_ref) = {
                    let Some(parent) = self.parent.value() else {
                        return Err(CommandError::PatternNotAllowed(self.parent.to_string()));
                    };
                    Self::parent_from_handle(task_state, device, TpmUint32(parent))?
                };

                let (parent_handle, _, auth) = task_state.resolve_auth(
                    device,
                    parent_handle_ref,
                    &self.auth_args.build_auth_map()?,
                )?;

                let (object_handle, public) = Self::run_load(
                    task_state,
                    device,
                    parent_handle,
                    tpm_key.private(),
                    tpm_key.public(),
                    &[auth],
                )?;

                let policy_blob = if let Some(policy) = &tpm_key.policy() {
                    let mut policy_vec: Vec<Box<dyn VtpmPolicyCommand>> = Vec::new();
                    for cmd in policy.policy() {
                        policy_vec.push(vtpm_policy_command_from_parts(cmd.cc(), cmd.body())?);
                    }
                    Some(policy_vec)
                } else {
                    None
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
    fn parent_from_handle(
        task_state: &mut TaskState,
        device: &mut TpmDevice,
        parent: TpmHandle,
    ) -> Result<(Tpm2bPublic, TpmHandle), CommandError> {
        let value = parent.0;

        let ht_byte = (parent.0 >> 24) as u8;
        let ht = TpmHt::try_from(ht_byte).map_err(|_| CommandError::InvalidHandleType(ht_byte))?;

        if ht == TpmHt::Persistent {
            let (public, _) = device.read_public(TpmUint32(value))?;
            Ok((Tpm2bPublic { inner: public }, parent))
        } else {
            let key = task_state
                .cache
                .find_by_handle(TpmUint32(value))
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

        let (resp, _) = task_state.execute(device, &cmd, auths)?;

        let resp = resp
            .Load()
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::Load))?;

        task_state.track(device, resp.handles[0])?;
        Ok((resp.handles[0], in_public.clone()))
    }
}
