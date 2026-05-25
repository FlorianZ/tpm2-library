// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::Task, command::CommandError, io::parse_u32, task::TaskState};
use argh::FromArgs;
use tpm2_protocol::data::TpmRc;

fn parse_rc(rc_str: &str) -> Result<TpmRc, String> {
    let rc_u32 = parse_u32(rc_str).map_err(|_| "malformed value".to_string())?;
    TpmRc::try_from(rc_u32).map_err(|_| "unknown discriminant".to_string())
}

/// Prints a TPM return code in human-readable format.
#[derive(FromArgs, Debug)]
#[argh(
    subcommand,
    name = "return-code",
    help_triggers("-h", "--help", "help")
)]
pub struct ReturnCode {
    /// return code in hex or decimal
    #[argh(positional, from_str_fn(parse_rc))]
    pub rc: TpmRc,
}

impl Task for ReturnCode {
    fn run(
        &self,
        _task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<(), CommandError> {
        writeln!(writer, "{}", self.rc)?;
        Ok(())
    }

    fn is_local(&self) -> bool {
        true
    }
}
