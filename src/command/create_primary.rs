// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    auth::Auth,
    cli::{Hierarchy, SubCommand},
    command::{deny_keyedhash, CommandError},
    device::{with_device, DeviceError},
    job::Job,
    key::Alg,
    template::build_public,
};
use clap::Args;
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmCc, TpmRh,
        TpmlPcrSelection, TpmsSensitiveCreate,
    },
    message::TpmCreatePrimaryCommand,
};

/// Creates a new primary key in a specified hierarchy.
#[derive(Args, Debug)]
pub struct CreatePrimary {
    /// Hierarchy: owner, platform, or endorsement
    #[arg(short = 'H', long)]
    pub hierarchy: Option<Hierarchy>,

    /// Key algorithm
    #[arg(value_parser = clap::value_parser!(Alg))]
    pub algorithm: Alg,

    /// Hierarchy auth: 'password:<hex>' or 'session:<handle>'
    #[arg(short = 'p', long = "parent-auth")]
    pub parent_auth: Option<Auth>,

    /// Key auth: 'password:<hex>' or 'policy:<hex>'
    #[arg(short = 'a', long = "auth")]
    pub auth: Option<Auth>,
}

impl SubCommand for CreatePrimary {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            deny_keyedhash(&self.algorithm)?;

            let primary_handle: TpmRh = self.hierarchy.unwrap_or_default().into();
            let mut auths = vec![self.parent_auth.clone().unwrap_or_default()];
            let auth = self.auth.clone().unwrap_or_default();
            let handles = [primary_handle as u32];

            let user_auth = match &auth {
                Auth::Password(p) => Tpm2bAuth::try_from(p.as_slice())?,
                Auth::Session(_) | Auth::Policy(_) => Tpm2bAuth::default(),
            };

            let auth_policy = match &auth {
                Auth::Policy(p) => Tpm2bAuth::try_from(p.as_slice())?,
                Auth::Session(_) | Auth::Password(_) => Tpm2bAuth::default(),
            };

            let object_attributes = self.algorithm.clone().into();
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

            let (resp, _) = job.execute(device, &cmd, &handles, &mut auths)?;

            let resp = resp
                .CreatePrimary()
                .map_err(|_| DeviceError::ResponseMismatch(TpmCc::CreatePrimary))?;

            let object_handle = resp.object_handle;
            device.name_cache_add(object_handle.0, resp.name);
            job.key_cache.track(object_handle)?;

            job.key_cache
                .save_context(device, object_handle, &resp.out_public, &resp.name)?;
            Ok(())
        })
    }
}
