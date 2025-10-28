// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::SubCommand, command::CommandError, parse_hex_u32, session::Session};
use clap::Args;
use tpm2_protocol::data::TpmRc;

fn parse_rc(rc_str: &str) -> Result<TpmRc, String> {
    let rc_u32 = parse_hex_u32(rc_str).map_err(|_| "malformed value".to_string())?;
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
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
        writeln!(job.writer, "{}", self.rc)?;
        Ok(())
    }

    fn is_local(&self) -> bool {
        true
    }
}
