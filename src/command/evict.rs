// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli::Task, handle::handle_type, task::TaskState};
use anyhow::{Result, anyhow};
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
    ) -> Result<()> {
        let input_handle = self
            .input
            .require_value()
            .map_err(|_| anyhow!("handle pattern not allowed: {}", self.input))?;

        if handle_type(input_handle) != Some(TpmHt::Transient) {
            return Err(anyhow!("invalid handle"));
        }

        let output_handle = self
            .output
            .require_value()
            .map_err(|_| anyhow!("handle pattern not allowed: {}", self.output))?;

        if handle_type(output_handle) != Some(TpmHt::Persistent) {
            return Err(anyhow!("invalid handle"));
        }

        with_device(task_state.device.clone().as_ref(), |dev| -> Result<()> {
            let persistent_handle = TpmUint32::new(output_handle);
            let transient_handle =
                task_state.load_key_by_handle(dev, TpmUint32::new(input_handle))?;

            let (public, parent, policy) = {
                let key = task_state
                    .cache
                    .find_by_handle(TpmUint32::new(input_handle))
                    .ok_or_else(|| anyhow!("unknown handle: {}", self.input))?;
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
        })
    }
}
