// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::Task, response::parse_response, task::TaskState};
use anyhow::{Result, anyhow};
use argh::FromArgs;
use std::path::PathBuf;
use tpm2_device::with_device;
use tpm2_protocol::{
    basic::TpmUint32,
    frame::{TpmUnsealCommand, TpmUnsealResponse},
};

/// Retrieves data from a sealed data object.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "unseal", help_triggers("-h", "--help", "help"))]
pub struct Unseal {
    /// TPM handle as a eight characters hex string
    #[argh(positional)]
    pub handle: crate::handle::Handle,

    /// output file path (defaults to stdout as hex)
    #[argh(option, short = 'O')]
    pub output: Option<PathBuf>,
}

impl Task for Unseal {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<()> {
        let handle = self
            .handle
            .require_value()
            .map_err(|_| anyhow!("handle pattern not allowed: {}", self.handle))?;

        with_device(task_state.device.clone(), |device| {
            let (item_handle, _, auth) = task_state.resolve_auth(device, TpmUint32::new(handle))?;

            let unseal_cmd = TpmUnsealCommand {
                handles: [item_handle],
            };

            let resp = task_state.execute(device, &unseal_cmd, &[auth])?;
            let out_data = parse_response::<TpmUnsealResponse>(resp)?.out_data;

            if let Some(path) = &self.output {
                std::fs::write(path, out_data.as_ref())?;
            } else {
                writeln!(writer, "{}", hex::encode(out_data.as_ref()))?;
            }

            Ok(())
        })
    }
}
