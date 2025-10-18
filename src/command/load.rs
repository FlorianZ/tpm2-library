// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    auth::Auth,
    cli::SubCommand,
    command::CommandError,
    convert::from_input_to_bytes,
    device::{with_device, Device, DeviceError},
    job::Job,
    key::AnyKey,
    uri::Uri,
};
use argh::FromArgs;
use tpm2_protocol::{
    data::{Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmCc},
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
    #[argh(option, arg_name = "auth", short = 'p')]
    pub parent_auth: Option<Auth>,
}

impl SubCommand for Load {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| -> Result<(), CommandError> {
            let parent_handle = job.key_cache.load_parent(device, &self.parent)?;

            let parent_auth =
                job.resolve_auth_session(device, self.parent_auth.clone(), parent_handle)?;
            let auth_list = vec![parent_auth];

            let input_bytes = from_input_to_bytes(self.input.as_ref())?;

            let (object_handle, name, public) =
                Self::run_input(job, device, parent_handle, &input_bytes, &auth_list)?;

            job.key_cache
                .save_context(device, object_handle, &public, &name)?;
            Ok(())
        })
    }
}

impl Load {
    fn run_input(
        job: &mut Job,
        device: &mut Device,
        parent_handle: TpmHandle,
        input_bytes: &[u8],
        auths: &[Auth],
    ) -> Result<(TpmHandle, Tpm2bName, Tpm2bPublic), CommandError> {
        let tpm_key = match AnyKey::try_from(input_bytes)? {
            AnyKey::Tpm(key) => key,
            AnyKey::External(_) => {
                let imported_key = job.import_key(device, parent_handle, input_bytes, auths)?;
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

        let (resp, _) = job.execute(device, &load_cmd, &handles, auths)?;

        let resp = resp
            .Load()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::Load))?;

        device.name_cache_add(resp.object_handle.0, resp.name);
        job.key_cache.track(resp.object_handle)?;
        Ok((resp.object_handle, resp.name, load_cmd.in_public))
    }
}
