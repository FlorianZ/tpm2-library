// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::SubCommand,
    command::CommandError,
    device::with_device,
    handle::{Handle, HandleClass, HandleError},
    job::Job,
};
use clap::Args;
use tpm2_protocol::{data::TpmRh, TpmHandle};

/// Create persistent object from transient object.
#[derive(Args, Debug)]
pub struct Evict {
    /// Input key: 'vtpm:<vhandle>'
    pub input: Handle,

    /// Persistent handle: 'tpm:<handle>'
    pub output: Handle,
}

impl SubCommand for Evict {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |dev| -> Result<(), CommandError> {
            let persistent_handle_val = match self.output.class() {
                HandleClass::Tpm => Ok(self.output.value()),
                HandleClass::Vtpm => Err(CommandError::Handle(HandleError::InvalidHandle)),
            }?;
            let persistent_handle = TpmHandle(persistent_handle_val);

            let auth_handle: TpmHandle = if (persistent_handle.0 & 0x00FF_FFFF) <= 0x007F_FFFF {
                (TpmRh::Owner as u32).into()
            } else {
                (TpmRh::Platform as u32).into()
            };

            let transient_handle = job.load_context(dev, &self.input)?;

            let auths = vec![job.auth_list.first().cloned().unwrap_or_default()];

            job.evict_control(auth_handle, transient_handle, persistent_handle, &auths)?;

            let vhandle = match self.input.class() {
                HandleClass::Vtpm => Ok(self.input.value()),
                HandleClass::Tpm => Err(CommandError::Handle(HandleError::InvalidHandle)),
            }?;
            job.cache.remove(dev, vhandle)?;

            job.cache.untrack(transient_handle.0);

            Ok(())
        })
    }
}
