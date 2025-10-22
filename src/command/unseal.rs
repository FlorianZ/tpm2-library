// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{AuthArgs, CommandError},
    device::{with_device, DeviceError},
    handle::Handle,
    job::Job,
    key_cache::KeyCacheError,
};
use clap::Args;
use std::io::IsTerminal;
use tpm2_protocol::{
    data::{TpmCc, TpmRcBase},
    message::TpmUnsealCommand,
};

/// Retrieves data from a sealed data object.
#[derive(Args, Debug)]
#[command(about = "Retrieves data from a sealed data object.")]
pub struct Unseal {
    /// Input: 'tpm:<persistent handle>' or 'vtpm:<transient handle>'
    pub input: Handle,

    #[clap(flatten)]
    pub auth_args: AuthArgs,

    /// Force hex output when redirecting to a file or pipe
    #[arg(long)]
    pub hex: bool,
}

impl SubCommand for Unseal {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            match self.input {
                Handle::Tpm(_) | Handle::Vtpm(_) => {}
            }
            let item_handle = job.key_cache.load_context(device, &self.input)?;
            let auths = self
                .auth_args
                .auth
                .clone()
                .map_or_else(Vec::new, |a| vec![a]);

            let unseal_cmd = TpmUnsealCommand {
                item_handle: item_handle.0.into(),
            };
            let unseal_handles = [item_handle.0];

            let result = job.execute(device, &unseal_cmd, &unseal_handles, &auths);
            let out_data = match result {
                Ok((resp, _)) => {
                    resp.Unseal()
                        .map_err(|_| CommandError::ResponseMismatch(TpmCc::Unseal))?
                        .out_data
                }
                Err(KeyCacheError::Device(DeviceError::TpmRc(rc)))
                    if rc.base() == TpmRcBase::AuthFail || rc.base() == TpmRcBase::AuthMissing =>
                {
                    return Err(CommandError::AuthenticationDenied);
                }
                Err(KeyCacheError::Device(DeviceError::TpmRc(rc)))
                    if rc.base() == TpmRcBase::Lockout =>
                {
                    return Err(CommandError::DictionaryAttackLocked);
                }
                Err(e) => return Err(e.into()),
            };

            if self.hex || !std::io::stdout().is_terminal() {
                writeln!(job.key_cache.writer, "{}", hex::encode(out_data.as_ref()))?;
            } else {
                job.key_cache.writer.write_all(out_data.as_ref())?;
            }
            Ok(())
        })
    }
}
