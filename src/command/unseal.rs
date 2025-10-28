// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::{deny_too_many_auths, CommandError},
    device::with_device,
    handle::Handle,
    session::Session,
};
use clap::Args;
use std::io::IsTerminal;
use tpm2_protocol::{data::TpmCc, message::TpmUnsealCommand};

/// Retrieves data from a sealed data object.
#[derive(Args, Debug)]
#[command(about = "Retrieves data from a sealed data object.")]
pub struct Unseal {
    /// Input: 'tpm:<persistent handle>' or 'vtpm:<transient handle>'
    pub input: Handle,

    /// Force hex output when redirecting to a file or pipe
    #[arg(long)]
    pub hex: bool,
}

impl Task for Unseal {
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
        deny_too_many_auths(job.auth_list, 1)?;

        with_device(job.device.clone(), |device| {
            let item_handle = job.load_context(device, &self.input)?;

            let unseal_cmd = TpmUnsealCommand {
                item_handle: item_handle.0.into(),
            };
            let unseal_handles = [item_handle.0];

            let (resp, _) = job.execute(device, &unseal_cmd, &unseal_handles, job.auth_list)?;

            let out_data = resp
                .Unseal()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::Unseal))?
                .out_data;

            if self.hex || std::io::stdout().is_terminal() {
                writeln!(job.writer, "{}", hex::encode(out_data.as_ref()))?;
            } else {
                job.writer.write_all(out_data.as_ref())?;
            }
            Ok(())
        })
    }
}
