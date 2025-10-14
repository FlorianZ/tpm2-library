// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::CommandError,
    context::{ContextCache, ContextItem},
    device::{Device, DeviceError},
    key,
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc};
use tabled::Tabled;

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
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        plain: bool,
    ) -> Result<(), CommandError> {
        let device_rc = device.ok_or(DeviceError::NotAvailable)?;
        let mut rows: Vec<KeyRow> = Vec::new();

        for item_result in context.loaded_contexts(device_rc) {
            match item_result? {
                ContextItem::Loaded(loaded_context) => {
                    let grip = loaded_context.grip.clone();
                    let alg_string = key::format_alg_from_public(&loaded_context.public);
                    rows.push(KeyRow {
                        grip,
                        details: alg_string,
                    });
                }
                ContextItem::Stale(grip) => {
                    log::warn!("key://{grip} stale");
                }
            }
        }

        rows.sort_unstable_by(|a, b| a.grip.cmp(&b.grip));

        super::print_table(&mut context.writer, rows, plain)?;

        Ok(())
    }
}
