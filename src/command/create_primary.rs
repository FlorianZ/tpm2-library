//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    alg::Alg,
    cli::Task,
    command::{deny_keyedhash, AuthArgs, CommandError, CreationArgs, HierarchyArgs},
    device::with_device,
    task::{is_empty_auth, TaskState},
    template::build_public,
};
use clap::Args;
use tpm2_protocol::{
    data::{
        Tpm2bData, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmCc,
        TpmRh, TpmlPcrSelection, TpmsSensitiveCreate,
    },
    frame::TpmCreatePrimaryCommand,
};

/// Creates a new primary key in a specified hierarchy.
#[derive(Args, Debug, Clone)]
pub struct CreatePrimary {
    #[clap(flatten)]
    pub hierarchy_args: HierarchyArgs,

    /// Key algorithm
    #[arg(value_parser = clap::value_parser!(Alg))]
    pub algorithm: Alg,

    #[clap(flatten)]
    pub auth_args: AuthArgs,

    #[clap(flatten)]
    pub creation_args: CreationArgs,
}

impl Task for CreatePrimary {
    fn run(&self, task_state: &mut TaskState) -> Result<(), CommandError> {
        with_device(task_state.device.clone(), |device| {
            deny_keyedhash(&self.algorithm)?;

            let primary_handle: TpmRh = self.hierarchy_args.hierarchy.into();
            let handles = [primary_handle as u32];

            let (object_attributes, user_auth) = self.creation_args.parse(&self.algorithm)?;
            let public_template =
                build_public(&self.algorithm, Tpm2bDigest::default(), object_attributes);

            let cmd = TpmCreatePrimaryCommand {
                primary_handle: (primary_handle as u32).into(),
                in_sensitive: Tpm2bSensitiveCreate {
                    inner: TpmsSensitiveCreate {
                        user_auth,
                        data: Tpm2bSensitiveData::default(),
                    },
                },
                in_public: Tpm2bPublic {
                    inner: public_template,
                },
                outside_info: Tpm2bData::default(),
                creation_pcr: TpmlPcrSelection::default(),
            };

            let empty_auth = is_empty_auth(&cmd.in_public.inner);

            let (resp, _) =
                task_state.execute(device, &cmd, &handles, &self.auth_args.auths(empty_auth))?;

            let resp = resp
                .CreatePrimary()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::CreatePrimary))?;

            let object_handle = resp.object_handle;
            task_state.track_handle(object_handle)?;
            let vhandle = task_state.cache.save_context(
                device,
                object_handle,
                &resp.out_public.inner,
                &Tpm2bPublic::default().inner,
                empty_auth,
                &None,
            )?;
            writeln!(task_state.writer, "vtpm:{vhandle:08x}")?;
            Ok(())
        })
    }
}
