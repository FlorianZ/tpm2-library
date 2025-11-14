//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Task,
    command::{AuthArgs, CommandError},
    device::with_device,
    task::TaskState,
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
    fn run(&self, task_state: &mut TaskState) -> Result<(), CommandError> {
        let vhandle = self
            .input
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.input.to_string()))?;
        let persistent_handle_val = self
            .output
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.output.to_string()))?;

        with_device(
            task_state.device.clone(),
            |dev| -> Result<(), CommandError> {
                if self.output.class() != HandleClass::Tpm {
                    return Err(CommandError::InvalidHandle);
                }
                let persistent_handle = TpmHandle(persistent_handle_val);

                let transient_handle = task_state.load_context(dev, &self.input)?;

                task_state.evict_control(
                    dev,
                    transient_handle,
                    persistent_handle,
                    &self.auth_args.auths(),
                )?;

                task_state.cache.remove(dev, vhandle)?;

                task_state.cache.untrack(transient_handle.0);

                Ok(())
            },
        )
    }
}
