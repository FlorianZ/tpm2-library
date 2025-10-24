// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    auth::Auth,
    cli::SubCommand,
    command::{CommandError, InputArgs, ParenLoadArgs},
    device::{with_device, Device},
    handle::{Handle, HandleClass},
    io::read_file_input,
    job::Job,
    key::{AnyKey, KeyError},
};
use clap::Args;
use tpm2_protocol::{
    data::{Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmCc, TpmHt},
    message::TpmLoadCommand,
    TpmHandle, TpmParse,
};

/// Loads a key under a parent and caches its context.
#[derive(Args, Debug)]
pub struct Load {
    #[clap(flatten)]
    pub parent_args: ParenLoadArgs,

    #[clap(flatten)]
    pub input_args: InputArgs,
}

impl SubCommand for Load {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| -> Result<(), CommandError> {
            let input_bytes = read_file_input(self.input_args.input.as_deref())?;
            let auths = vec![self.parent_args.auth.clone().unwrap_or_default()];

            let (parent_handle, parent_public) =
                if let Some(parent_handle_uri) = self.parent_args.parent {
                    let handle = job.key_cache.load_parent(device, &parent_handle_uri)?;
                    let (public, _) = device.read_public(handle)?;
                    let public_2b = Tpm2bPublic { inner: public };
                    (handle, public_2b)
                } else {
                    let tpm_key = match AnyKey::try_from(input_bytes.as_slice())? {
                        AnyKey::Tpm(key) => key,
                        AnyKey::External(_) => return Err(CommandError::ParentMissing),
                    };

                    let parent_pub_key_bytes = tpm_key
                        .parent_pub_key
                        .as_ref()
                        .ok_or(CommandError::ParentMissing)?;
                    let (parent_public, _) =
                        Tpm2bPublic::parse(parent_pub_key_bytes).map_err(KeyError::from)?;

                    let handle = Load::load_hierarchy(job, device, &parent_public)?;
                    (handle, parent_public)
                };

            let (object_handle, _, public) =
                Self::run_input(job, device, parent_handle, &input_bytes, &auths)?;

            job.key_cache
                .save_context(device, object_handle, &public, &parent_public)?;
            Ok(())
        })
    }
}

impl Load {
    fn load_hierarchy(
        job: &mut Job,
        device: &mut Device,
        parent_public: &Tpm2bPublic,
    ) -> Result<TpmHandle, CommandError> {
        let mut parent_stack = Vec::new();
        let mut current_target = parent_public.clone();

        let root_handle = 'search: loop {
            let persistent_handles = device.fetch_handles((TpmHt::Persistent as u32) << 24)?;
            for handle in persistent_handles {
                if let Ok((public, _)) = device.read_public(handle.value().into()) {
                    if public == current_target.inner {
                        break 'search handle.value().into();
                    }
                }
            }

            if let Some((vhandle, key)) = job
                .key_cache
                .contexts
                .iter()
                .find(|(_, key)| key.public == current_target)
            {
                parent_stack.push(*vhandle);

                if key.parent.inner.object_type == TpmAlgId::Null {
                    let hierarchy_handle = key.context.hierarchy as u32;
                    break 'search hierarchy_handle.into();
                }

                current_target = key.parent.clone();
            } else {
                return Err(CommandError::UnknownParent);
            }
        };

        let mut parent_handle = root_handle;
        while let Some(vhandle) = parent_stack.pop() {
            parent_handle = job
                .key_cache
                .load_context(device, &Handle((HandleClass::Vtpm, vhandle)))?;
        }

        Ok(parent_handle)
    }

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
            .map_err(|_| CommandError::ResponseMismatch(TpmCc::Load))?;

        job.key_cache.track(resp.object_handle)?;
        Ok((resp.object_handle, resp.name, load_cmd.in_public))
    }
}
