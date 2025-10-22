// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::SubCommand,
    command::{CommandError, HierarchyAuthArgs},
    device::with_device,
    handle::Handle,
    job::Job,
};
use clap::Args;
use tpm2_protocol::{data::TpmRh, TpmHandle};

/// Create persistent object from transient object.
#[derive(Args, Debug)]
pub struct Evict {
    #[clap(flatten)]
    pub hierarchy_args: HierarchyAuthArgs,

    /// Input key: 'vtpm:<vhandle>'
    pub input: Handle,

    /// Persistent handle: 'tpm:<handle>'
    pub output: Handle,
}

impl SubCommand for Evict {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |dev| -> Result<(), CommandError> {
            let persistent_handle_val = match self.output {
                Handle::Tpm(h) => Ok(h),
                Handle::Vtpm(_) => Err(CommandError::InvalidInput(self.output.to_string())),
            }?;
            let persistent_handle = TpmHandle(persistent_handle_val);

            let auth_handle: TpmHandle = if (persistent_handle.0 & 0x00FF_FFFF) <= 0x007F_FFFF {
                (TpmRh::Owner as u32).into()
            } else {
                (TpmRh::Platform as u32).into()
            };

            let vhandle = match self.input {
                Handle::Vtpm(vh) => Ok(vh),
                Handle::Tpm(_) => Err(CommandError::InvalidInput(self.input.to_string())),
            }?;
            let transient_handle = job.key_cache.load_context(dev, &self.input)?;

            let auths = vec![self.hierarchy_args.auth.clone().unwrap_or_default()];
            dev.evict_control(
                job,
                auth_handle,
                transient_handle,
                persistent_handle,
                &auths,
            )
            .map_err(CommandError::Device)?;

            job.key_cache.remove_context(vhandle)?;

            Ok(())
        })
    }
}
