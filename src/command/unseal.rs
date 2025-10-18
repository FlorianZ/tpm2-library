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
use argh::FromArgs;
use std::str::FromStr;
use tpm2_protocol::{data::TpmCc, message::TpmUnsealCommand};

/// Retrieves data from a sealed data object.
#[derive(FromArgs, Debug)]
#[argh(
    subcommand,
    name = "unseal",
    note = "Retrieves data from a sealed data object."
)]
pub struct Unseal {
    /// input: 'tpm:<handle>' or 'key:<grip>'
    #[argh(positional)]
    pub input: String,

    /// key auth: 'password:<hex>' or 'session:<handle>'
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<Auth>,
}

impl SubCommand for Unseal {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let input = Uri::from_str(&self.input)?;
            if matches!(input, Uri::Path(_)) {
                return Err(CommandError::InvalidInput(format!("{input}")));
            }
            let item_handle = job.context_cache.load_context(device, &input)?;

            let auth = job.resolve_auth_session(device, self.auth.clone(), item_handle)?;
            let auth_list = vec![auth];
            let unseal_cmd = TpmUnsealCommand {
                item_handle: item_handle.0.into(),
            };
            let unseal_handles = [item_handle.0];
            let (unseal_resp, _) = job.execute(device, &unseal_cmd, &unseal_handles, &auth_list)?;
            let out_data = unseal_resp
                .Unseal()
                .map_err(|_| DeviceError::ResponseMismatch(TpmCc::Unseal))?
                .out_data;
            job.context_cache.write_data(None, &out_data)?;
            Ok(())
        })
    }
}
