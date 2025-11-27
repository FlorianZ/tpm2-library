// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::{AuthArgs, CommandError, OutputArgs},
    task::TaskState,
};
use clap::{Args, ValueEnum};
use tpm2_device::with_device;
use tpm2_protocol::{basic::TpmUint32, data::TpmCc, frame::TpmUnsealCommand};

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum UnsealEncoding {
    #[default]
    Hex,
    Binary,
}

/// Retrieves data from a sealed data object.
#[derive(Args, Debug)]
#[command(about = "Retrieves data from a sealed data object.")]
pub struct Unseal {
    /// TPM handle as a eight characters hex string.
    pub handle: crate::handle::Handle,

    #[clap(flatten)]
    pub auth_args: AuthArgs,

    #[clap(flatten)]
    pub output_args: OutputArgs,

    /// Output encoding (only applies to file output).
    #[arg(short = 'e', long, value_enum, default_value_t = UnsealEncoding::default())]
    pub encoding: UnsealEncoding,
}

impl Task for Unseal {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<(), CommandError> {
        let Some(handle) = self.handle.value() else {
            return Err(CommandError::PatternNotAllowed(self.handle.to_string()));
        };

        with_device(task_state.device.clone(), |device| {
            let (item_handle, _, auth) = task_state.resolve_auth(
                device,
                TpmUint32(handle),
                &self.auth_args.build_auth_map(),
            )?;

            let unseal_cmd = TpmUnsealCommand {
                handles: [item_handle.0.into()],
            };

            let (resp, _) = task_state
                .execute(device, &unseal_cmd, &[auth])
                .map_err(Into::<CommandError>::into)?;

            let out_data = resp
                .Unseal()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::Unseal))?
                .out_data;

            if let Some(path) = &self.output_args.output {
                let bytes = match self.encoding {
                    UnsealEncoding::Hex => hex::encode(out_data.as_ref()).into_bytes(),
                    UnsealEncoding::Binary => out_data.to_vec(),
                };
                std::fs::write(path, bytes)?;
            } else {
                writeln!(writer, "{}", hex::encode(out_data.as_ref()))?;
            }

            Ok(())
        })
    }
}
