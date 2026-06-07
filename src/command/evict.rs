// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli::Task, command::CommandError, task::TaskState};
use argh::FromArgs;
use tpm2_device::with_device;
use tpm2_protocol::{basic::TpmUint32, data::TpmHt};

/// Create persistent object from transient object.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "evict", help_triggers("-h", "--help", "help"))]
pub struct Evict {
    /// transient handle as an eight character hex string
    #[argh(positional)]
    pub input: crate::handle::Handle,

    /// persistent handle as an eight character hex string
    #[argh(positional)]
    pub output: crate::handle::Handle,
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

        if (input_handle >> 24) as u8 != TpmHt::Transient as u8 {
            return Err(CommandError::InvalidHandle);
        }

        let output_handle = self
            .output
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.output.to_string()))?;

        if (output_handle >> 24) as u8 != TpmHt::Persistent as u8 {
            return Err(CommandError::InvalidHandle);
        }

        with_device(
            task_state.device.clone(),
            |dev| -> Result<(), CommandError> {
                let persistent_handle = TpmUint32::new(output_handle);
                let transient_handle =
                    task_state.load_key_by_handle(dev, TpmUint32::new(input_handle))?;

                let (public, parent, policy) = {
                    let key = task_state
                        .cache
                        .find_by_handle(TpmUint32::new(input_handle))
                        .ok_or(CommandError::UnknownHandle(self.input.to_string()))?;
                    (
                        key.public().clone(),
                        key.parent().clone(),
                        Some(key.policy().clone()),
                    )
                };

                task_state.evict_control(dev, transient_handle, persistent_handle)?;

                task_state
                    .cache
                    .save_persistent(persistent_handle, &public, &parent, &policy)?;

                task_state.cache.remove(input_handle)?;
                task_state.untrack(transient_handle);
                Ok(())
            },
        )
    }
}
