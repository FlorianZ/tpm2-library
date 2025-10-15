// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::SubCommand, command::CommandError, convert::from_str_to_tpm_rc, Job};
use argh::FromArgs;
use tpm2_protocol::data::TpmRc;

/// Prints a TPM return code in human-readable format.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "return-code")]
pub struct ReturnCode {
    /// return code in hex or decimal
    #[argh(positional, from_str_fn(from_str_to_tpm_rc))]
    pub rc: TpmRc,
}

impl SubCommand for ReturnCode {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        writeln!(job.context_cache.writer, "{}", self.rc)?;
        Ok(())
    }

    fn is_local(&self) -> bool {
        true
    }
}
