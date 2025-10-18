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
use argh::FromArgs;
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmCc, TpmRh,
        TpmlPcrSelection, TpmsSensitiveCreate,
    },
    message::TpmCreatePrimaryCommand,
};

/// Creates a new primary key in a specified hierarchy.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "create-primary")]
pub struct CreatePrimary {
    /// hierarchy: owner, platform, or endorsement
    #[argh(option, short = 'H')]
    pub hierarchy: Option<Hierarchy>,

    /// key algorithm
    #[argh(positional)]
    pub algorithm: Alg,

    /// hierachy auth: 'password:<hex>' or 'session:<handle>'
    #[argh(option, arg_name = "parent-auth", short = 'p')]
    pub parent_auth: Option<Auth>,

    /// key auth: 'password:<hex>' or 'policy:<hex>'
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<Auth>,
}

impl SubCommand for CreatePrimary {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            deny_keyedhash(&self.algorithm)?;

            let primary_handle: TpmRh = self.hierarchy.unwrap_or_default().into();

            let parent_auth = job.resolve_auth_session(
                device,
                self.parent_auth.clone(),
                (primary_handle as u32).into(),
            )?;
            let auth = self.auth.clone().unwrap_or(Auth::Password(Vec::new()));
            let handles = [primary_handle as u32];
            let auths = std::slice::from_ref(&parent_auth);

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

            let (resp, _) = job.execute(device, &cmd, &handles, auths)?;

            let resp = resp
                .CreatePrimary()
                .map_err(|_| DeviceError::ResponseMismatch(TpmCc::CreatePrimary))?;

            let object_handle = resp.object_handle;
            device.add_name_to_cache(object_handle.0, resp.name);
            job.key_cache.track(object_handle)?;

            job.key_cache
                .save_context(device, object_handle, &resp.out_public, &resp.name)?;
            Ok(())
        })
    }
}
