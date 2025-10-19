// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{CommandError, InputArgs, OutputArgs, OutputEncoding, ParentAuthArgs},
    convert::{from_input_to_bytes, from_tpm_key_to_output},
    device::with_device,
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

    /// Output encoding: pem or der
    #[arg(long, default_value_t = Default::default(), value_parser = clap::value_parser!(OutputEncoding))]
    pub encoding: OutputEncoding,
}

impl SubCommand for Convert {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let parent_handle = job
                .key_cache
                .load_parent(device, &self.parent_args.parent)?;
            let mut auths = vec![self.parent_args.auth.clone().unwrap_or_default()];
            let input_bytes = from_input_to_bytes(self.input_args.input.as_ref())?;
            let tpm_key = job.import_key(device, parent_handle, &input_bytes, &mut auths)?;
            from_tpm_key_to_output(
                &mut job.key_cache,
                &tpm_key,
                self.output_args.output.as_ref(),
                self.encoding,
            )
        })
    }
}
