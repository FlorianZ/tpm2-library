// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Task,
    command::{
        common::{build_policy_command_list, resolve_public_template},
        CommandError, CreationArgs, HierarchyArgs,
    },
    task::TaskState,
};
use clap::Args;
use tpm2_crypto::TpmPublicTemplate;
use tpm2_device::with_device;
use tpm2_protocol::{
    basic::TpmUint32,
    data::{
        Tpm2bData, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmCc, TpmRh,
        TpmlPcrSelection, TpmsSensitiveCreate,
    },
    frame::TpmCreatePrimaryCommand,
};

/// Creates a new primary key in a specified hierarchy.
#[derive(Args, Debug, Clone)]
pub struct CreatePrimary {
    #[clap(flatten)]
    pub hierarchy_args: HierarchyArgs,

    /// Key algorithm
    #[arg(value_parser = clap::value_parser!(TpmPublicTemplate))]
    pub algorithm: TpmPublicTemplate,

    #[clap(flatten)]
    pub creation_args: CreationArgs,
}

impl Task for CreatePrimary {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<(), CommandError> {
        with_device(task_state.device.clone(), |device| {
            let primary_handle: TpmRh = self.hierarchy_args.hierarchy.into();

            let user_auth = self.creation_args.parse_password()?;
            let object_attributes = self.creation_args.parse_attributes(&self.algorithm)?;

            let (auth_policy_digest, policy_commands) = build_policy_command_list(
                &self.creation_args,
                task_state,
                device,
                self.algorithm.name_alg(),
            )?;

            let public_area =
                resolve_public_template(&self.algorithm, object_attributes, auth_policy_digest)?;

            let cmd = TpmCreatePrimaryCommand {
                in_sensitive: Tpm2bSensitiveCreate {
                    inner: TpmsSensitiveCreate {
                        user_auth,
                        data: Tpm2bSensitiveData::default(),
                    },
                },
                in_public: Tpm2bPublic { inner: public_area },
                outside_info: Tpm2bData::default(),
                creation_pcr: TpmlPcrSelection::default(),
                handles: [(primary_handle as u32).into()],
            };

            let auth = task_state
                .auth_map
                .get(&TpmUint32(primary_handle as u32))
                .cloned()
                .unwrap_or_default();

            let (resp, _) = task_state.execute(device, &cmd, &[auth])?;

            let resp = resp
                .CreatePrimary()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::CreatePrimary))?;

            let object_handle = resp.handles[0];
            task_state.track(device, object_handle)?;
            let object_context = device.save_context(object_handle)?;

            let policy_blob = task_state.save_vtpm_policy(device, policy_commands)?;

            let vhandle = task_state.cache.save_transient(
                object_context,
                &resp.out_public.inner,
                &Tpm2bPublic::default().inner,
                &Some(policy_blob),
            )?;
            writeln!(writer, "{vhandle:08x}")?;
            Ok(())
        })
    }
}
