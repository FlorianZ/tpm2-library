// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::CommandError,
    context::ContextCache,
    device::Device,
    key::{self, KeyError},
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc};
use tabled::Tabled;
use tpm2_protocol::{data::Tpm2bPublic, TpmParse};

#[derive(Tabled)]
struct KeyRow {
    #[tabled(rename = "GRIP")]
    grip: String,
    #[tabled(rename = "DETAILS")]
    details: String,
}

/// Lists cached keys.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "key", note = "Lists keys from local cache.")]
pub struct Key {}

impl SubCommand for Key {
    fn run(
        &self,
        _device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        plain: bool,
    ) -> Result<(), CommandError> {
        let mut rows: Vec<KeyRow> = Vec::new();

        for (grip, key) in &context.contexts {
            let (public_blob, _) =
                Tpm2bPublic::parse(&key.public).map_err(|e| KeyError::Device(e.into()))?;

            rows.push(KeyRow {
                grip: grip.clone(),
                details: key::format_alg_from_public(&public_blob.inner),
            });
        }

        rows.sort_unstable_by(|a, b| a.grip.cmp(&b.grip));

        super::print_table(&mut context.writer, rows, plain)?;

        Ok(())
    }

    fn is_local(&self) -> bool {
        true
    }
}
