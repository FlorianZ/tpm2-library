// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    auth::Auth,
    cli::SubCommand,
    command::CommandError,
    device::{with_device, Device, DeviceError},
    job::Job,
    uri::Uri,
};
use clap::Args;
use std::str::FromStr;
use tpm2_protocol::{
    data::{TpmCc, TpmHt, TpmRh},
    message::TpmEvictControlCommand,
    TpmHandle,
};

/// Stores a cached key to non-volatile memory.
#[derive(Args, Debug)]
pub struct Save {
    /// Input: [<parent>] <name grip> <persistent-handle>
    pub input: Vec<String>,

    /// Key auth: 'password:<hex>' or 'session:<handle>'
    #[arg(short = 'a', long = "auth")]
    pub auth: Option<Auth>,
}

impl Save {
    /// Makes a transient key persistent.
    fn save_persistent(
        job: &mut Job,
        device: &mut Device,
        transient_handle: TpmHandle,
        persistent_handle: TpmHandle,
        auths: &mut [Auth],
    ) -> Result<(), CommandError> {
        if !job.key_cache.handles.contains_key(&transient_handle.0) {
            return Err(CommandError::InvalidInput(format!(
                "transient handle {transient_handle} not tracked"
            )));
        }

        let auth_handle = TpmRh::Owner;
        let cmd = TpmEvictControlCommand {
            auth: (auth_handle as u32).into(),
            object_handle: transient_handle.0.into(),
            persistent_handle,
        };
        let handles = [auth_handle as u32];

        let (resp, _) = job.execute(device, &cmd, &handles, auths)?;

        resp.EvictControl()
            .map_err(|_| DeviceError::ResponseMismatch(TpmCc::EvictControl))?;
        job.key_cache.handles.remove(&transient_handle.0);
        Ok(())
    }
}

impl SubCommand for Save {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        with_device(job.device.clone(), |dev| -> Result<(), CommandError> {
            let (_parent_uri_opt, grip_str, handle_str) = match self.input.len() {
                2 => (None, &self.input[0], &self.input[1]),
                3 => (Some(&self.input[0]), &self.input[1], &self.input[2]),
                _ => {
                    return Err(CommandError::InvalidInput(
                        "invalid number of arguments for save command".to_string(),
                    ));
                }
            };

            let handle_uri = Uri::from_str(handle_str)?;
            let handle = match handle_uri {
                Uri::Tpm(h) => Ok(h),
                _ => Err(CommandError::InvalidInput(
                    "output must be a 'tpm:'".to_string(),
                )),
            }?;

            let mut auths = vec![self.auth.clone().unwrap_or_default()];

            if (handle >> 24) as u8 != TpmHt::Persistent as u8 {
                return Err(CommandError::InvalidInput(
                    "output must be a persistent handle".to_string(),
                ));
            }
            let persistent_handle = TpmHandle(handle);

            let grip_uri = Uri::from_str(grip_str)?;
            if !matches!(grip_uri, Uri::Key(_)) {
                return Err(CommandError::InvalidInput(
                    "input must be a 'key'".to_string(),
                ));
            }
            let transient_handle = job.key_cache.load_context(dev, &grip_uri)?;

            Self::save_persistent(job, dev, transient_handle, persistent_handle, &mut auths)?;

            if let Uri::Key(grip) = grip_uri {
                job.key_cache.remove_context(&grip)?;
            }

            writeln!(job.key_cache.writer, "tpm:{handle:08x}")?;
            Ok(())
        })
    }
}