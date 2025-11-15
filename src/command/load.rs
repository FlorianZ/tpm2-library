//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    alg::AlgError,
    cli::Task,
    command::{AuthArgs, CommandError, InputArgs},
    device::{with_device, Device},
    io::read_file_input,
    task::TaskState,
    vtpm::VtpmKey,
};
use clap::Args;
use tpm2_policy_language::{Auth, Handle, HandleClass};
use tpm2_protocol::{
    data::{Tpm2bName, Tpm2bPublic, TpmCc, TpmaObject},
    frame::TpmLoadCommand,
    TpmHandle,
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
    fn run(&self, task_state: &mut TaskState) -> Result<(), CommandError> {
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

                let mut policy_session_auth: Option<Auth> = None;

                let parent_vhandle_opt = task_state
                    .cache
                    .key_iter()
                    .find(|(_, key)| key.public == parent_public)
                    .map(|(vhandle, _)| *vhandle);

                let (policy_blob, name_alg, parent_empty_auth) =
                    if let Some(parent_vhandle) = parent_vhandle_opt {
                        task_state.cache.fetch_policy(parent_vhandle)?
                    } else {
                        (
                            Vec::new(),
                            parent_public.inner.name_alg,
                            parent_public
                                .inner
                                .object_attributes
                                .contains(TpmaObject::ADMIN_WITH_POLICY)
                                && !parent_public
                                    .inner
                                    .object_attributes
                                    .contains(TpmaObject::USER_WITH_AUTH),
                        )
                    };

                let all_auths = self.auth_args.auths(parent_empty_auth);
                let (cmd_auths, policy_auths) = if parent_empty_auth {
                    (Vec::new(), all_auths.as_ref())
                } else {
                    (
                        vec![all_auths.first().cloned().unwrap_or_default()],
                        all_auths.get(1..).unwrap_or_default(),
                    )
                };

                let mut auths = cmd_auths;

                if !policy_blob.is_empty() {
                    if let Some(session_auth) = task_state.build_policy_session(
                        device,
                        &policy_blob,
                        name_alg,
                        policy_auths,
                    )? {
                        auths = vec![session_auth.clone()];
                        policy_session_auth = Some(session_auth);
                    }
                }

                let (object_handle, _, loaded_public) = Self::run_load(
                    task_state,
                    device,
                    parent_handle,
                    tpm_key.private(),
                    tpm_key.public(),
                    &auths,
                )
                .inspect_err(|e: &CommandError| {
                    log::debug!("run_load failed: {e}");
                    if let Some(Auth::Session(vhandle)) = policy_session_auth {
                        if let Err(e) = task_state.cache.remove(device, vhandle) {
                            log::error!("vtpm:{vhandle:08x}: {e}");
                        }
                    }
                })?;

                if let Some(Auth::Session(vhandle)) = policy_session_auth {
                    if let Err(e) = task_state.cache.remove(device, vhandle) {
                        log::error!("vtpm:{vhandle:08x}: {e}");
                    }
                }

                let policy_blob = if let Some(policy) = &tpm_key.policy {
                    Some(VtpmKey::policy_from_tpmkey_policy(policy)?)
                } else {
                    None
                };

                let vhandle = task_state.cache.save_context(
                    device,
                    object_handle,
                    &loaded_public,
                    &parent_public,
                    tpm_key.empty_auth.unwrap_or_default(),
                    &policy_blob,
                )?;

                writeln!(task_state.writer, "vtpm:{vhandle:08x}")?;
                Ok(())
            },
        )
    }
}

impl Load {
    fn fetch_parent(
        task_state: &mut TaskState,
        device: &mut Device,
        parent_public: &Tpm2bPublic,
    ) -> Result<TpmHandle, CommandError> {
        if let Some((phandle, _)) = device.find_persistent(&parent_public.inner)? {
            return Ok(phandle);
        }

        let vhandle_opt = task_state
            .cache
            .key_iter()
            .find(|(_, key)| key.public == *parent_public)
            .map(|(vhandle, _)| *vhandle);

        if let Some(vhandle) = vhandle_opt {
            return Ok(task_state.load_context(device, &Handle::new(HandleClass::Vtpm, vhandle))?);
        }

        Err(CommandError::UnknownParent)
    }

    fn run_load(
        task_state: &mut TaskState,
        device: &mut Device,
        parent_handle: TpmHandle,
        in_private: &tpm2_protocol::data::Tpm2bPrivate,
        in_public: &Tpm2bPublic,
        auths: &[Auth],
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

        task_state.cache.track(resp.object_handle)?;
        Ok((resp.object_handle, resp.name, in_public.clone()))
    }
}
