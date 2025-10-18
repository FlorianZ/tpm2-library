// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    auth::Auth,
    cli::SubCommand,
    command::{CommandError, OutputEncoding},
    convert::{from_input_to_bytes, from_tpm_key_to_output},
    device::with_device,
    job::Job,
    uri::Uri,
};
use argh::FromArgs;
use std::str::FromStr;

/// Convert external keys to TPM keys.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "convert")]
pub struct Convert {
    /// parent key under which to import
    #[argh(positional)]
    pub parent: String,

    /// optional: <input file> [<output file>]
    #[argh(positional, greedy)]
    pub files: Vec<String>,

    /// parent auth: 'password:<hex>' or 'session:<handle>'
    #[argh(option, arg_name = "auth", short = 'p')]
    pub parent_auth: Option<Auth>,

    /// output encoding: pem or der
    #[argh(option, default = "Default::default()")]
    pub encoding: OutputEncoding,
}

impl SubCommand for Convert {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        let (input_str, output_str) = match self.files.len() {
            0 => (None, None),
            1 => (Some(&self.files[0]), None),
            2 => (Some(&self.files[0]), Some(&self.files[1])),
            _ => {
                return Err(CommandError::InvalidInput(
                    "too many arguments for convert command".to_string(),
                ))
            }
        };

        let parent_uri = Uri::from_str(&self.parent)?;
        let input_uri = input_str
            .map(|s| Uri::from_str(s))
            .transpose()?
            .unwrap_or(Uri::Path("-".into()));
        let output_uri = output_str.map(|s| Uri::from_str(s)).transpose()?;

        with_device(job.device.clone(), |device| {
            let parent_handle = job.key_cache.load_parent(device, &parent_uri)?;
            let parent_auth =
                job.resolve_auth_session(device, self.parent_auth.clone(), parent_handle)?;
            let input_bytes = from_input_to_bytes(Some(&input_uri))?;
            let tpm_key = job.import_key(device, parent_handle, &input_bytes, &[parent_auth])?;
            from_tpm_key_to_output(
                &mut job.key_cache,
                &tpm_key,
                output_uri.as_ref(),
                self.encoding,
            )
        })
    }
}
