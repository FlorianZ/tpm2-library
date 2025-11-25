// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::{AuthArgs, CommandError},
    task::TaskState,
};
use clap::Args;
use tpm2_device::with_device;
use tpm2_protocol::{data::TpmCc, frame::TpmUnsealCommand, TpmHandle};

/// Retrieves data from a sealed data object.
#[derive(Args, Debug)]
#[command(about = "Retrieves data from a sealed data object.")]
pub struct Unseal {
    /// TPM handle as a eight characters hex string.
    pub handle: crate::handle::Handle,

    #[clap(flatten)]
    pub auth_args: AuthArgs,
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
                TpmHandle(handle),
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

            writeln!(writer, "{}", hex::encode(out_data.as_ref()))?;
            Ok(())
        })
    }
}
