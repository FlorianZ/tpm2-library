// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Job,
    command::{AuthArgs, CommandError},
    device::with_device,
    session::Session,
};
use clap::Args;
use std::io::IsTerminal;
use tpm2_policy_language::Handle;
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

    #[clap(flatten)]
    pub auth_args: AuthArgs,
}

impl Job for Unseal {
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
        self.input
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.input.to_string()))?;

        with_device(job.device.clone(), |device| {
            let item_handle = job.load_context(device, &self.input)?;

            let unseal_cmd = TpmUnsealCommand {
                item_handle: item_handle.0.into(),
            };
            let unseal_handles = [item_handle.0];

            let (resp, _) = job.execute(
                device,
                &unseal_cmd,
                &unseal_handles,
                &self.auth_args.auths(),
            )?;

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
