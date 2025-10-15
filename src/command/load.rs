// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use super::CommandError;
use crate::{
    cli::SubCommand,
    context::ContextCache,
    convert::{from_env_to_auth, from_input_to_bytes},
    device::{self, Auth, Device, DeviceError},
    key::AnyKey,
    uri::Uri,
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc};
use tpm2_protocol::{
    data::{Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmCc, TpmSe},
    message::TpmLoadCommand,
    TpmHandle, TpmParse,
};

/// Loads a key under a parent and caches its context.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "load")]
pub struct Load {
    /// parent: 'tpm:<handle>', or 'key:<name grip>'
    #[argh(positional)]
    pub parent: Uri,

    /// input: PKCS#1, PKCS#8, SEC1 or TPMKey file
    #[argh(positional)]
    pub input: Option<Uri>,

    /// parent auth: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_PARENT_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'p')]
    pub parent_auth: Option<String>,

    /// auth: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<String>,

    /// hmac auth: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_HMAC_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'm', long = "hmac-auth")]
    pub hmac_auth: Option<String>,
}

impl SubCommand for Load {
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        _plain: bool,
    ) -> Result<(), CommandError> {
        let parent_auth = from_env_to_auth(
            self.parent_auth.as_ref(),
            "TPM2SH_PARENT_AUTH",
            &context.session_map,
            Some(TpmSe::Policy),
        )?;
        device::with_device(device, |device| -> Result<(), CommandError> {
            let parent_handle = context.load_parent(device, &self.parent)?;
            let input_bytes = from_input_to_bytes(self.input.as_ref())?;

            let (object_handle, name) =
                Self::run_input(context, device, parent_handle, &input_bytes, &[parent_auth])?;

            context.new_context(device, object_handle, &name)?;
            Ok(())
        })
    }
}

impl Load {
    fn run_input(
        context: &mut ContextCache,
        device: &mut Device,
        parent_handle: TpmHandle,
        input_bytes: &[u8],
        auths: &[Auth],
    ) -> Result<(TpmHandle, Tpm2bName), CommandError> {
        let tpm_key = match AnyKey::try_from(input_bytes)? {
            AnyKey::Tpm(key) => key,
            AnyKey::External(_) => {
                let imported_key = context.import_key(device, parent_handle, input_bytes, auths)?;
                Box::new(imported_key)
            }
        };

        let (in_public, _) = Tpm2bPublic::parse(&tpm_key.pub_key)?;
        let (in_private, _) = Tpm2bPrivate::parse(&tpm_key.priv_key)?;

        let load_cmd = TpmLoadCommand {
            parent_handle: parent_handle.0.into(),
            in_private,
            in_public,
        };
        let handles = [parent_handle.0];

        let (resp, _) = context.execute(device, &load_cmd, &handles, auths)?;

        let resp = resp
            .Load()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::Load))?;

        device.add_name_to_cache(resp.object_handle.0, resp.name);
        context.track(resp.object_handle)?;
        Ok((resp.object_handle, resp.name))
    }
}
