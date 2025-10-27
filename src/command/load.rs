// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    auth::Auth,
    cli::SubCommand,
    command::{deny_parent, deny_too_many_auths, CommandError, InputArgs},
    device::{with_device, Device},
    handle::{Handle, HandleClass},
    io::read_file_input,
    job::Job,
    key::{AnyKey, KeyError, TpmKey},
};
use clap::Args;
use tpm2_protocol::{
    data::{Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmCc},
    message::TpmLoadCommand,
    TpmHandle, TpmParse,
};

/// Loads a PEM or DER TPMKey file to cache.
#[derive(Args, Debug)]
#[command(verbatim_doc_comment)]
pub struct Load {
    #[clap(flatten)]
    pub input_args: InputArgs,
}

impl SubCommand for Load {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        deny_parent(job.parent)?;
        deny_too_many_auths(job.auth_list, 1)?;
        with_device(job.device.clone(), |device| -> Result<(), CommandError> {
            let input_bytes = read_file_input(self.input_args.input.as_deref())?;

            let tpm_key = match AnyKey::try_from(input_bytes.as_slice())? {
                AnyKey::Tpm(key) => key,
                AnyKey::External(_) => return Err(CommandError::InvalidFormat),
            };

            let parent_pub_key_bytes = tpm_key
                .parent_pub_key
                .as_ref()
                .ok_or(CommandError::ParentMissing)?;
            let (parent_public, _) =
                Tpm2bPublic::parse(parent_pub_key_bytes).map_err(KeyError::from)?;

            let parent_handle = Self::fetch_parent(job, device, &parent_public)?;

            let (object_handle, _, loaded_public) =
                Self::run_load(job, device, parent_handle, &tpm_key, job.auth_list)?;

            let vhandle =
                job.cache
                    .save_context(device, object_handle, &loaded_public, &parent_public)?;
            writeln!(job.writer, "vtpm:{vhandle:08x}")?;
            Ok(())
        })
    }
}

impl Load {
    fn fetch_parent(
        job: &mut Job,
        device: &mut Device,
        parent_public: &Tpm2bPublic,
    ) -> Result<TpmHandle, CommandError> {
        if let Some((phandle, _)) = device.find_persistent(&parent_public.inner)? {
            return Ok(phandle);
        }

        let vhandle_opt = job
            .cache
            .key_iter()
            .find(|(_, key)| key.public == *parent_public)
            .map(|(vhandle, _)| *vhandle);

        if let Some(vhandle) = vhandle_opt {
            return Ok(job.load_context(device, &Handle((HandleClass::Vtpm, vhandle)))?);
        }

        Err(CommandError::UnknownParent)
    }

    fn run_load(
        job: &mut Job,
        device: &mut Device,
        parent_handle: TpmHandle,
        tpm_key: &TpmKey,
        auths: &[Auth],
    ) -> Result<(TpmHandle, Tpm2bName, Tpm2bPublic), CommandError> {
        let (in_public, _) = Tpm2bPublic::parse(&tpm_key.pub_key)?;
        let (in_private, _) = Tpm2bPrivate::parse(&tpm_key.priv_key)?;

        let cmd = TpmLoadCommand {
            parent_handle,
            in_private,
            in_public: in_public.clone(),
        };
        let handles = [parent_handle.0];

        let (resp, _) = job.execute(device, &cmd, &handles, auths)?;

        let resp = resp
            .Load()
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::Load))?;

        job.cache.track(resp.object_handle)?;
        Ok((resp.object_handle, resp.name, in_public))
    }
}
