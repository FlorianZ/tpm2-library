// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{AuthArgs, CommandError},
    device::with_device,
    job::Job,
    scheme::Scheme,
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
                let uri = Scheme::from_str(input_str)?;
                match uri {
                    Scheme::Session(vhandle) => {
                        if let Some(session) = job.session_cache.remove(vhandle)? {
                            if let Err(err) = dev.flush_session(session.context) {
                                log::warn!("{uri}: {err}");
                            }
                        }
                    }
                    Scheme::Key(ref vhandle) => {
                        let handle = job.key_cache.load_context(dev, &uri)?;
                        dev.flush_context(handle.0)?;
                        job.key_cache.remove_context(*vhandle)?;
                        job.key_cache.untrack(handle.0);
                    }
                    Scheme::Tpm(handle) => {
                        if (handle >> 24) as u8 == TpmHt::Persistent as u8 {
                            return Err(CommandError::InvalidInput(handle.to_string()));
                        }
                        let handle = job.key_cache.load_context(dev, &uri)?;
                        dev.flush_context(handle.0)?;
                    }
                    Scheme::Path(_) | Scheme::Password(_) | Scheme::Policy(_) => {
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
