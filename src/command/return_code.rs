// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::SubCommand, command::CommandError, convert::from_str_to_tpm_rc, job::Job};
use clap::Args;
use tpm2_protocol::data::TpmRc;

/// Prints a TPM return code in human-readable format.
#[derive(Args, Debug)]
pub struct ReturnCode {
    /// Return code in hex or decimal
    #[arg(value_parser = from_str_to_tpm_rc)]
    pub rc: TpmRc,
}

impl SubCommand for ReturnCode {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        writeln!(job.key_cache.writer, "{}", self.rc)?;
        Ok(())
    }

    fn is_local(&self) -> bool {
        true
    }
}
