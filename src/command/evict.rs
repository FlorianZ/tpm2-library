// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Task,
    command::{AuthArgs, CommandError},
    task::TaskState,
};
use clap::Args;
use tpm2_device::with_device;
use tpm2_protocol::{basic::TpmUint32, data::TpmHt};

/// Create persistent object from transient object.
#[derive(Args, Debug)]
pub struct Evict {
    /// Transient handle as an eight character hex string.
    pub input: crate::handle::Handle,

    /// Persistent handle as an eight character hex string.
    pub output: crate::handle::Handle,

    #[clap(flatten)]
    pub auth_args: AuthArgs,
}

impl Task for Evict {
    fn run(
        &self,
        task_state: &mut TaskState,
        _writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<(), CommandError> {
        let input_handle = self
            .input
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.input.to_string()))?;
        let input_ht =
            TpmHt::try_from((input_handle >> 24) as u8).map_err(|_| CommandError::InvalidHandle)?;
        if input_ht != TpmHt::Transient {
            return Err(CommandError::InvalidHandle);
        }

        let output_handle = self
            .output
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.output.to_string()))?;
        let output_ht = TpmHt::try_from((output_handle >> 24) as u8)
            .map_err(|_| CommandError::InvalidHandle)?;
        if output_ht != TpmHt::Persistent {
            return Err(CommandError::InvalidHandle);
        }

        with_device(
            task_state.device.clone(),
            |dev| -> Result<(), CommandError> {
                let persistent_handle = TpmUint32(output_handle);
                let transient_handle =
                    task_state.load_key_by_handle(dev, TpmUint32(input_handle))?;
                task_state.evict_control(
                    dev,
                    transient_handle,
                    persistent_handle,
                    &self.auth_args.build_auth_map(),
                )?;
                task_state.cache.remove(input_handle)?;
                task_state.untrack(transient_handle);
                Ok(())
            },
        )
    }
}
