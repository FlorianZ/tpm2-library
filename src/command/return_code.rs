// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use super::CommandError;
use crate::{cli::SubCommand, context::ContextCache, convert::from_str_to_tpm_rc, device::Device};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc};
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
    fn run(
        &self,
        _device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        _plain: bool,
    ) -> Result<(), CommandError> {
        writeln!(context.writer, "{}", self.rc)?;
        Ok(())
    }

    fn is_local(&self) -> bool {
        true
    }
}
