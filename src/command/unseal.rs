//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::{AuthArgs, CommandError},
    device::with_device,
    task::{TaskError, TaskState},
};
use clap::Args;
use tpm2_policy_language::{Auth, Handle, HandleClass};
use tpm2_protocol::{data::TpmCc, frame::TpmUnsealCommand};

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

impl Task for Unseal {
    fn run(&self, task_state: &mut TaskState) -> Result<(), CommandError> {
        let vhandle = self
            .input
            .value()
            .ok_or_else(|| CommandError::PatternNotAllowed(self.input.to_string()))?;

        with_device(task_state.device.clone(), |device| {
            let item_handle = task_state.load_context(device, &self.input)?;

            let mut auths = self.auth_args.auths().to_vec();
            let mut policy_session_auth: Option<Auth> = None;

            let key_info = if self.input.class() == HandleClass::Vtpm {
                task_state.cache.fetch_policy(vhandle).ok()
            } else {
                None
            };

            if self.auth_args.auths().as_ref() == [Auth::default()] {
                if let Some((policy_blob, name_alg)) = key_info {
                    if !policy_blob.is_empty() {
                        if let Some(session_auth) =
                            task_state.build_policy_session(device, &policy_blob, name_alg)?
                        {
                            auths = vec![session_auth.clone()];
                            policy_session_auth = Some(session_auth);
                        }
                    }
                }
            }

            let unseal_cmd = TpmUnsealCommand {
                item_handle: item_handle.0.into(),
            };
            let unseal_handles = [item_handle.0];

            let (resp, _) = task_state
                .execute(device, &unseal_cmd, &unseal_handles, &auths)
                .map_err(|e: TaskError| {
                    if let Some(Auth::Session(vhandle)) = policy_session_auth {
                        if let Err(e) = task_state.cache.remove(device, vhandle) {
                            log::error!("vtpm:{vhandle:08x}: {e}");
                        }
                    }
                    Into::<CommandError>::into(e)
                })?;

            if let Some(Auth::Session(vhandle)) = policy_session_auth {
                if let Err(e) = task_state.cache.remove(device, vhandle) {
                    log::error!("vtpm:{vhandle:08x}: {e}");
                }
            }

            let out_data = resp
                .Unseal()
                .map_err(|_| CommandError::ResponseMismatch(TpmCc::Unseal))?
                .out_data;

            if self.hex || task_state.is_tty {
                writeln!(task_state.writer, "{}", hex::encode(out_data.as_ref()))?;
            } else {
                task_state.writer.write_all(out_data.as_ref())?;
            }
            Ok(())
        })
    }
}
