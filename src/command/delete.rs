// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    auth::Auth, cli::SubCommand, command::CommandError, device::with_device, job::Job, uri::Uri,
};
use clap::Args;
use std::str::FromStr;

/// Deletes TPM objects, and cached keys and sessions.
#[derive(Args, Debug)]
pub struct Delete {
    /// Inputs: 'tpm:<handle>', 'key:<name grip>', or 'session:<handle>'
    pub inputs: Vec<String>,

    /// Persistent auth: 'password:<hex>' or 'session:<handle>'
    #[arg(short = 'a', long = "auth")]
    pub auth: Option<Auth>,
}

impl SubCommand for Delete {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
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
                    Uri::Key(ref grip) => {
                        let handle = job.key_cache.load_context(dev, &uri)?;
                        dev.flush_context(handle.0)?;
                        job.key_cache.remove_context(grip)?;
                    }
                    Uri::Tpm(_) => {
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
