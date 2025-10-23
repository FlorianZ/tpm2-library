// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{CommandError, InputArgs, OutputArgs, OutputEncodingArgs, ParentAuthArgs},
    device::with_device,
    io::{read_file_input, write_file_output},
    job::Job,
};
use clap::Args;

/// Convert external keys to TPM keys.
#[derive(Args, Debug)]
pub struct Convert {
    #[clap(flatten)]
    pub parent_args: ParentAuthArgs,

    #[clap(flatten)]
    pub input_args: InputArgs,

    #[clap(flatten)]
    pub output_args: OutputArgs,

    #[clap(flatten)]
    pub output_encoding_args: OutputEncodingArgs,
}

impl SubCommand for Convert {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let parent_handle = job
                .key_cache
                .load_parent(device, &self.parent_args.parent)?;
            let auths = vec![self.parent_args.auth.clone().unwrap_or_default()];
            let input_bytes = read_file_input(self.input_args.input.as_deref())?;
            let tpm_key = job.import_key(device, parent_handle, &input_bytes, &auths)?;
            write_file_output(
                &mut job.key_cache,
                &tpm_key,
                self.output_args.output.as_deref(),
                self.output_encoding_args.output_encoding,
            )
        })
    }
}
