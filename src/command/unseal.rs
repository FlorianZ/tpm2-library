//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::{AuthArgs, CommandError},
    task::{TaskAuth, TaskState},
};
use clap::Args;
use tpm2_device::with_device;
use tpm2_policy_language::TpmHandleRef;
use tpm2_protocol::{data::TpmCc, frame::TpmUnsealCommand};

/// Retrieves data from a sealed data object.
#[derive(Args, Debug)]
#[command(about = "Retrieves data from a sealed data object.")]
pub struct Unseal {
    /// Input: 'tpm:<persistent handle>' or 'vtpm:<transient handle>'
    pub input: TpmHandleRef,

    /// Force hex output when redirecting to a file or pipe
    #[arg(long)]
    pub hex: bool,

    #[clap(flatten)]
    pub auth_args: AuthArgs,
}

impl Task for Unseal {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
    ) -> Result<(), CommandError> {
        if self.input.value().is_none() {
            return Err(CommandError::PatternNotAllowed(self.input.to_string()));
        }

        with_device(task_state.device.clone(), |device| {
            let item_handle = task_state.load_context(device, &self.input)?;

            let (policy_blob, name_alg, empty_auth) =
                task_state.resolve_policy(device, &self.input, item_handle)?;

            let (auths, policy_session_auth) = task_state.build_auth(
                device,
                &policy_blob,
                name_alg,
                empty_auth,
                &self.auth_args,
            )?;

            let unseal_cmd = TpmUnsealCommand {
                item_handle: item_handle.0.into(),
            };
            let unseal_handles = [item_handle.0];

            let execution_result = task_state.execute(device, &unseal_cmd, &unseal_handles, &auths);

            if let Some(TaskAuth::Session(vhandle)) = policy_session_auth {
                if let Err(e) = task_state.remove_session(device, vhandle) {
                    log::error!("vtpm:{vhandle:08x}: {e}");
                }
            }

            let (resp, _) = execution_result.map_err(Into::<CommandError>::into)?;

            let out_data = resp
                .Unseal()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::Unseal))?
                .out_data;

            if self.hex || task_state.is_tty {
                writeln!(writer, "{}", hex::encode(out_data.as_ref()))?;
            } else {
                writer.write_all(out_data.as_ref())?;
            }
            Ok(())
        })
    }
}
