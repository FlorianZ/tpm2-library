// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    auth::Auth,
    cli::SubCommand,
    command::CommandError,
    device::{with_device, DeviceError},
    job::Job,
    uri::Uri,
};
use clap::Args;
use std::io::IsTerminal;
use tpm2_protocol::{data::TpmCc, message::TpmUnsealCommand};

/// Retrieves data from a sealed data object.
#[derive(Args, Debug)]
#[command(about = "Retrieves data from a sealed data object.")]
pub struct Unseal {
    /// Input: 'tpm:<persistent handle>' or 'key:<grip>'
    pub input: Uri,

    /// Key auth: 'password:<hex>' or 'session:<handle>'
    #[arg(short = 'a', long = "auth")]
    pub auth: Option<Auth>,

    /// Force hex output when redirecting to a file or pipe
    #[arg(long)]
    pub hex: bool,
}

impl SubCommand for Unseal {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            match self.input {
                Uri::Tpm(handle) => {
                    if (handle >> 24) as u8 != tpm2_protocol::data::TpmHt::Persistent as u8 {
                        return Err(CommandError::InvalidInput(self.input.to_string()));
                    }
                }
                Uri::Key(_) => {}
                Uri::Path(_) | Uri::Session(_) | Uri::Password(_) | Uri::Policy(_) => {
                    return Err(CommandError::InvalidInput(self.input.to_string()));
                }
            }
            let item_handle = job.key_cache.load_context(device, &self.input)?;
            let mut auths = vec![self.auth.clone().unwrap_or_default()];

            let unseal_cmd = TpmUnsealCommand {
                item_handle: item_handle.0.into(),
            };
            let unseal_handles = [item_handle.0];
            let (unseal_resp, _) = job.execute(device, &unseal_cmd, &unseal_handles, &mut auths)?;
            let out_data = unseal_resp
                .Unseal()
                .map_err(|_| DeviceError::ResponseMismatch(TpmCc::Unseal))?
                .out_data;

            if self.hex || std::io::stdout().is_terminal() {
                writeln!(job.key_cache.writer, "{}", hex::encode(out_data.as_ref()))?;
            } else {
                job.key_cache.writer.write_all(out_data.as_ref())?;
            }
            Ok(())
        })
    }
}
