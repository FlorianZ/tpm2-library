// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand, command::CommandError, device::with_device, handle::Handle, job::Job,
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

impl SubCommand for Unseal {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let item_handle = job.load_context(device, &self.input, &[])?;
            let auths = vec![job.auth_list.first().cloned().unwrap_or_default()];

            let unseal_cmd = TpmUnsealCommand {
                item_handle: item_handle.0.into(),
            };
            let unseal_handles = [item_handle.0];

            let (resp, _) = job.execute(device, &unseal_cmd, &unseal_handles, &auths)?;

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
