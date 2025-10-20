// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{AuthArgs, CommandError},
    device::with_device,
    job::Job,
    uri::Uri,
};
use clap::Args;
use std::str::FromStr;
use tpm2_protocol::data::TpmHt;

/// Deletes TPM objects, and cached keys and sessions.
#[derive(Args, Debug)]
pub struct Delete {
    /// Inputs: 'tpm:<handle>', 'key:<name vhandle>', or 'vtpm:<handle>'
    pub inputs: Vec<String>,

    #[clap(flatten)]
    pub auth_args: AuthArgs,
}

impl SubCommand for Delete {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        if self.inputs.is_empty() {
            return Ok(());
        }

        with_device(job.device.clone(), |dev| -> Result<(), CommandError> {
            for input_str in &self.inputs {
                let uri = Uri::from_str(input_str)?;
                let uri_str = uri.to_string();

                match uri {
                    Uri::Session(_) => {
                        if let Some(session) = job.session_cache.remove(&uri_str)? {
                            if let Err(err) = dev.flush_session(session.context) {
                                log::warn!("{uri}: {err}");
                            }
                        }
                    }
                    Uri::Key(ref vhandle) => {
                        let handle = job.key_cache.load_context(dev, &uri)?;
                        dev.flush_context(handle.0)?;
                        job.key_cache.remove_context(*vhandle)?;
                        job.key_cache.untrack(handle.0);
                    }
                    Uri::Tpm(handle) => {
                        if (handle >> 24) as u8 == TpmHt::Persistent as u8 {
                            return Err(CommandError::InvalidInput(handle.to_string()));
                        }
                        let handle = job.key_cache.load_context(dev, &uri)?;
                        dev.flush_context(handle.0)?;
                    }
                    Uri::Path(_) | Uri::Password(_) | Uri::Policy(_) => {
                        return Err(CommandError::InvalidInput(uri.to_string()));
                    }
                }
            }
            Ok(())
        })
    }

    fn is_local(&self) -> bool {
        false
    }
}
