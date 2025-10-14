// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use super::{deny_keyedhash, CommandError};
use crate::{
    cli::{get_auth, Hierarchy, SubCommand},
    context::ContextCache,
    device::{with_device, Auth, Device, DeviceError},
    key::Alg,
    template::{build_public_template, default_attributes},
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc};
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
        TpmCc, TpmRh, TpmSe, TpmlPcrSelection, TpmsSensitiveCreate,
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

    /// auth for the hierarchy: 'password://<hex>' or 'session://<handle>'
    /// Uses TPM2SH_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<String>,

    /// hmac auth: 'password://<hex>' or 'session://<handle>'
    /// Uses TPM2SH_HMAC_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'm', long = "hmac-auth")]
    pub hmac_auth: Option<String>,
}

impl SubCommand for CreatePrimary {
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        _plain: bool,
    ) -> Result<(), CommandError> {
        let auth = get_auth(
            self.auth.as_ref(),
            "TPM2SH_AUTH",
            &context.session_map,
            &[TpmSe::Policy],
        )?;
        with_device(device, |device| {
            deny_keyedhash(&self.algorithm)?;

            let primary_handle: TpmRh = self.hierarchy.unwrap_or_default().into();
            let handles = [primary_handle as u32];
            let auths = std::slice::from_ref(&auth);

            let new_obj_user_auth = match &auth {
                Auth::Password(p) => Tpm2bAuth::try_from(p.as_slice())?,
                Auth::Tracked(_) => Tpm2bAuth::default(),
            };

            let user_with_auth = !new_obj_user_auth.is_empty();
            let object_attributes = default_attributes(&self.algorithm, user_with_auth);
            let public_template =
                build_public_template(&self.algorithm, Tpm2bDigest::default(), object_attributes);

            let cmd = TpmCreatePrimaryCommand {
                primary_handle: (primary_handle as u32).into(),
                in_sensitive: Tpm2bSensitiveCreate {
                    inner: TpmsSensitiveCreate {
                        user_auth: new_obj_user_auth,
                        data: Tpm2bSensitiveData::default(),
                    },
                },
                in_public: Tpm2bPublic {
                    inner: public_template,
                },
                outside_info: Tpm2bData::default(),
                creation_pcr: TpmlPcrSelection::default(),
            };

            let (resp, _) = context.execute(device, &cmd, &handles, auths)?;

            let resp = resp
                .CreatePrimary()
                .map_err(|_| DeviceError::ResponseMismatch(TpmCc::CreatePrimary))?;

            let object_handle = resp.object_handle;
            device.add_name_to_cache(object_handle.0, resp.name);
            context.track(object_handle)?;

            context.new_context(device, object_handle, &resp.name)?;
            Ok(())
        })
    }
}
