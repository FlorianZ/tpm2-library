// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::SubCommand,
    command::{deny_keyedhash, deny_too_many_auths, CommandError, CreationArgs, HierarchyArgs},
    device::with_device,
    job::Job,
    key::Alg,
    template::build_public,
};
use clap::Args;
use tpm2_protocol::{
    data::{
        Tpm2bData, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmCc, TpmRh,
        TpmlPcrSelection, TpmsSensitiveCreate,
    },
    message::TpmCreatePrimaryCommand,
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
    pub creation_args: CreationArgs,
}

impl SubCommand for CreatePrimary {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        deny_too_many_auths(job.auth_list, 1)?;

        with_device(job.device.clone(), |device| {
            deny_keyedhash(&self.algorithm)?;

            let primary_handle: TpmRh = self.hierarchy_args.hierarchy.into();
            let auths = vec![job.auth_list.first().cloned().unwrap_or_default()];
            let handles = [primary_handle as u32];

            let (object_attributes, user_auth, auth_policy) =
                self.creation_args.parse(&self.algorithm)?;
            let public_template = build_public(&self.algorithm, auth_policy, object_attributes);

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

            let (resp, _) = job.execute(device, &cmd, &handles, &auths)?;

            let resp = resp
                .CreatePrimary()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::CreatePrimary))?;

            let object_handle = resp.object_handle;
            job.cache.track(object_handle)?;
            let vhandle = job.cache.save_context(
                device,
                object_handle,
                &resp.out_public,
                &Tpm2bPublic::default(),
            )?;
            writeln!(job.writer, "vtpm:{vhandle:08x}")?;
            Ok(())
        })
    }
}
