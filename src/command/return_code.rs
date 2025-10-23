// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::SubCommand, command::CommandError, job::Job};
use clap::Args;
use tpm2_protocol::data::TpmRc;

fn parse_rc(rc_str: &str) -> Result<TpmRc, String> {
    let rc_str = rc_str.strip_prefix("0x").unwrap_or(rc_str);
    let rc_u32 = u32::from_str_radix(rc_str, 16).map_err(|_| "malformed value".to_string())?;

    TpmRc::try_from(rc_u32).map_err(|_| "unknown discriminant".to_string())
}

/// Prints a TPM return code in human-readable format.
#[derive(Args, Debug)]
pub struct ReturnCode {
    /// Return code in hex or decimal
    #[arg(value_parser = parse_rc)]
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
