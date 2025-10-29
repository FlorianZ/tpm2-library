// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Job,
    command::{AuthArgs, CommandError},
    device::with_device,
    handle::{Handle, HandleClass, HandleError},
    session::Session,
};
use clap::Args;
use tpm2_protocol::TpmHandle;

/// Create persistent object from transient object.
#[derive(Args, Debug)]
pub struct Evict {
    /// Input key: 'vtpm:<vhandle>'
    pub input: Handle,

    /// Persistent handle: 'tpm:<handle>'
    pub output: Handle,

    #[clap(flatten)]
    pub auth_args: AuthArgs,
}

impl Job for Evict {
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
        with_device(job.device.clone(), |dev| -> Result<(), CommandError> {
            let persistent_handle_val = match self.output.class() {
                HandleClass::Tpm => Ok(self.output.value()),
                HandleClass::Vtpm => Err(CommandError::Handle(HandleError::InvalidHandle)),
            }?;
            let persistent_handle = TpmHandle(persistent_handle_val);

            let transient_handle = job.load_context(dev, &self.input)?;

            job.evict_control(
                dev,
                transient_handle,
                persistent_handle,
                &self.auth_args.auths(),
            )?;

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
