//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Task,
    command::{AuthArgs, CommandError},
    device::with_device,
    session::Session,
};
use clap::Args;
use tpm2_policy_language::{Handle, HandleClass};
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

impl Task for Evict {
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
        let vhandle = self
            .input
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.input.to_string()))?;
        let persistent_handle_val = self
            .output
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.output.to_string()))?;

        with_device(job.device.clone(), |dev| -> Result<(), CommandError> {
            if self.output.class() != HandleClass::Tpm {
                return Err(CommandError::InvalidHandle);
            }
            let persistent_handle = TpmHandle(persistent_handle_val);

            let transient_handle = job.load_context(dev, &self.input)?;

            job.evict_control(
                dev,
                transient_handle,
                persistent_handle,
                &self.auth_args.auths(),
            )?;

            job.cache.remove(dev, vhandle)?;

            job.cache.untrack(transient_handle.0);

            Ok(())
        })
    }
}
