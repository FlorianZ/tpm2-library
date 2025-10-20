// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    auth::Auth,
    cli::SubCommand,
    command::{CommandError, HierarchyAuthArgs},
    device::{with_device, Device, DeviceError},
    job::Job,
    scheme::Scheme,
};
use clap::Args;
use std::str::FromStr;
use tpm2_protocol::{
    data::{TpmCc, TpmHt, TpmRh},
    message::TpmEvictControlCommand,
    TpmHandle,
};

/// Make transient key persistent or persistent object evicted.
#[derive(Args, Debug)]
pub struct Evict {
    #[clap(flatten)]
    pub hierarchy_args: HierarchyAuthArgs,

    /// Input transient key: 'key:<name vhandle>'
    #[arg(short = 'I', long)]
    pub input: Option<String>,

    /// Persistent handle: 'tpm:<handle>'
    #[arg(short = 'O', long)]
    pub output: String,
}

impl Evict {
    fn run_evict_control(
        job: &mut Job,
        device: &mut Device,
        auth_handle: TpmHandle,
        object_target_handle: TpmHandle,
        persistent_target_handle: TpmHandle,
        auths: &mut [Auth],
    ) -> Result<(), CommandError> {
        let cmd = TpmEvictControlCommand {
            auth: auth_handle,
            object_handle: object_target_handle.0.into(),
            persistent_handle: persistent_target_handle,
        };
        let handles_for_session = [auth_handle.0];

        let (resp, _) = job.execute(device, &cmd, &handles_for_session, auths)?;
        resp.EvictControl()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::EvictControl))?;
        Ok(())
    }
}

impl SubCommand for Evict {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |dev| -> Result<(), CommandError> {
            let persistent_handle_uri = Scheme::from_str(&self.output)?;
            let persistent_handle_val = match persistent_handle_uri {
                Scheme::Tpm(h) if (h >> 24) as u8 == TpmHt::Persistent as u8 => Ok(h),
                Scheme::Tpm(h) => Err(CommandError::InvalidInput(h.to_string())),
                ref uri => Err(CommandError::InvalidInput(uri.to_string())),
            }?;
            let persistent_handle = TpmHandle(persistent_handle_val);
            let auth_handle: TpmHandle = if (persistent_handle.0 & 0x00FF_FFFF) <= 0x007F_FFFF {
                (TpmRh::Owner as u32).into()
            } else {
                (TpmRh::Platform as u32).into()
            };
            let mut auths = vec![self.hierarchy_args.auth.clone().unwrap_or_default()];
            let (object_handle, persistent_handle, vhandle) =
                if let Some(object_handle_str) = &self.input {
                    let vhandle_uri = Scheme::from_str(object_handle_str)?;
                    let vhandle = match &vhandle_uri {
                        Scheme::Transient(vhandle) => Ok(*vhandle),
                        ref uri => Err(CommandError::InvalidInput(uri.to_string())),
                    }?;
                    let transient_handle = job.key_cache.load_context(dev, &vhandle_uri)?;
                    (transient_handle, persistent_handle, vhandle)
                } else {
                    (persistent_handle, persistent_handle, 0)
                };
            Self::run_evict_control(
                job,
                dev,
                auth_handle,
                object_handle,
                persistent_handle,
                &mut auths,
            )?;
            if vhandle != 0 {
                job.key_cache.remove_context(vhandle)?;
            }
            Ok(())
        })
    }
}
