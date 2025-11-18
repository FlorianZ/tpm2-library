//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    alg::AlgError,
    cli::Task,
    command::{AuthArgs, CommandError, InputArgs},
    io::read_file_input,
    task::{TaskAuth, TaskState},
};
use clap::Args;
use tpm2_device::{with_device, TpmDevice};
use tpm2_policy_language::{TpmHandleClass, TpmHandleRef};
use tpm2_protocol::{
    basic::TpmBuffer,
    constant::TPM_MAX_COMMAND_SIZE,
    data::{Tpm2bName, Tpm2bPublic, TpmCc},
    frame::TpmLoadCommand,
    TpmHandle, TpmMarshal, TpmWriter,
};
use tpm2_tpmkey::TpmKey;

/// Loads a PEM or DER TPMKey file to cache.
#[derive(Args, Debug)]
#[command(verbatim_doc_comment)]
pub struct Load {
    #[clap(flatten)]
    pub auth_args: AuthArgs,

    #[clap(flatten)]
    pub input_args: InputArgs,
}

impl Task for Load {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
    ) -> Result<(), CommandError> {
        with_device(
            task_state.device.clone(),
            |device| -> Result<(), CommandError> {
                let input_bytes = read_file_input(self.input_args.input.as_deref())?;
                if input_bytes.is_empty() {
                    return Ok(());
                }

                let tpm_key = TpmKey::from_pem(&input_bytes)
                    .or_else(|_| TpmKey::from_der(&input_bytes).map_err(AlgError::from))?;

                let parent_public = tpm_key
                    .parent_public()
                    .cloned()
                    .ok_or(CommandError::InvalidInput("parent missing".to_string()))?;

                let parent_handle = Self::fetch_parent(task_state, device, &parent_public)?;

                let parent_vhandle_opt = task_state
                    .cache
                    .key_iter()
                    .find(|(_, key)| key.public == parent_public.inner)
                    .map(|(vhandle, _)| *vhandle);

                let parent_handle_ref = if let Some(vhandle) = parent_vhandle_opt {
                    TpmHandleRef::new(TpmHandleClass::Vtpm, vhandle)
                } else {
                    TpmHandleRef::new(TpmHandleClass::Tpm, parent_handle.0)
                };

                let (policy_blob, name_alg, parent_empty_auth) =
                    task_state.resolve_policy(device, &parent_handle_ref, parent_handle)?;

                let (auths, policy_session_auth) = task_state.build_auth(
                    device,
                    &policy_blob,
                    name_alg,
                    parent_empty_auth,
                    &self.auth_args,
                )?;

                let run_load_result = Self::run_load(
                    task_state,
                    device,
                    parent_handle,
                    tpm_key.private(),
                    tpm_key.public(),
                    &auths,
                );

                if let Some(TaskAuth::Session(vhandle)) = policy_session_auth {
                    if let Err(e) = task_state.remove_session(device, vhandle) {
                        log::error!("vtpm:{vhandle:08x}: {e}");
                    }
                }

                let (object_handle, _, loaded_public) =
                    run_load_result.inspect_err(|e: &CommandError| {
                        log::debug!("run_load failed: {e}");
                    })?;

                let policy_blob = if let Some(policy) = &tpm_key.policy {
                    let mut buf = vec![0u8; TPM_MAX_COMMAND_SIZE as usize];
                    let len = {
                        let mut writer = TpmWriter::new(&mut buf);
                        let count = u32::try_from(policy.policy.len())?;
                        count.marshal(&mut writer).map_err(CommandError::Marshal)?;

                        for cmd in &policy.policy {
                            cmd.code()
                                .marshal(&mut writer)
                                .map_err(CommandError::Marshal)?;
                            TpmBuffer::<{ TPM_MAX_COMMAND_SIZE as usize }>::try_from(cmd.body())
                                .map_err(CommandError::Unmarshal)?
                                .marshal(&mut writer)
                                .map_err(CommandError::Marshal)?;
                        }
                        writer.len()
                    };
                    buf.truncate(len);
                    Some(buf)
                } else {
                    None
                };

                let object_context = device.save_context(object_handle)?;
                let vhandle = task_state.cache.save_context(
                    object_context,
                    &loaded_public.inner,
                    &parent_public.inner,
                    tpm_key.empty_auth.unwrap_or_default(),
                    &policy_blob,
                )?;

                writeln!(writer, "vtpm:{vhandle:08x}")?;
                Ok(())
            },
        )
    }
}

impl Load {
    fn fetch_parent(
        task_state: &mut TaskState,
        device: &mut TpmDevice,
        parent_public: &Tpm2bPublic,
    ) -> Result<TpmHandle, CommandError> {
        if let Some((phandle, _)) = device.find_persistent(&parent_public.inner)? {
            return Ok(phandle);
        }

        let vhandle_opt = task_state
            .cache
            .key_iter()
            .find(|(_, key)| key.public == parent_public.inner)
            .map(|(vhandle, _)| *vhandle);

        if let Some(vhandle) = vhandle_opt {
            return Ok(task_state
                .load_context(device, &TpmHandleRef::new(TpmHandleClass::Vtpm, vhandle))?);
        }

        Err(CommandError::UnknownParent)
    }

    fn run_load(
        task_state: &mut TaskState,
        device: &mut TpmDevice,
        parent_handle: TpmHandle,
        in_private: &tpm2_protocol::data::Tpm2bPrivate,
        in_public: &Tpm2bPublic,
        auths: &[TaskAuth],
    ) -> Result<(TpmHandle, Tpm2bName, Tpm2bPublic), CommandError> {
        let cmd = TpmLoadCommand {
            parent_handle,
            in_private: *in_private,
            in_public: in_public.clone(),
        };
        let handles = [parent_handle.0];

        let (resp, _) = task_state.execute(device, &cmd, &handles, auths)?;

        let resp = resp
            .Load()
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::Load))?;

        task_state.track_handle(resp.object_handle)?;
        Ok((resp.object_handle, resp.name, in_public.clone()))
    }
}
