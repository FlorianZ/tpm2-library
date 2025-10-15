// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::CommandError,
    context::ContextCache,
    device::{Device, DeviceError},
    key,
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc};
use tabled::Tabled;
use tpm2_protocol::{
    data::{TpmRcBase, TpmsContext, TpmtPublic},
    TpmParse,
};

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

impl Key {
    fn list_keys(
        context: &ContextCache,
        device: &Rc<RefCell<Device>>,
    ) -> (Vec<KeyRow>, Vec<String>) {
        let mut rows = Vec::new();
        let mut stale_grips = Vec::new();

        for (grip, context_blob) in &context.contexts {
            let context_struct = match TpmsContext::parse(context_blob) {
                Ok((cs, _)) => cs,
                Err(e) => {
                    log::warn!("Failed to parse context for grip {grip}: {e}");
                    continue;
                }
            };

            let live_handle = {
                let mut device_guard = device.borrow_mut();
                match device_guard.load_context(context_struct) {
                    Ok(h) => h,
                    Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::ReferenceH0 => {
                        stale_grips.push(grip.clone());
                        continue;
                    }
                    Err(e) => {
                        log::warn!("Skipping unloadable context {grip}: {e}");
                        continue;
                    }
                }
            };

            let public_result: Result<(TpmtPublic, _), DeviceError> = {
                let mut device_guard = device.borrow_mut();
                device_guard.read_public(live_handle.into())
            };

            match public_result {
                Ok((public, _)) => {
                    let alg_string = key::format_alg_from_public(&public);
                    rows.push(KeyRow {
                        grip: grip.clone(),
                        details: alg_string,
                    });
                }
                Err(e) => {
                    log::warn!("Failed to read public area for context {grip}: {e}");
                }
            }

            if let Err(e) = device.borrow_mut().flush_context(live_handle) {
                log::error!("Failed to flush temporary context for handle {live_handle:08x}: {e}");
            }
        }

        (rows, stale_grips)
    }
}

impl SubCommand for Key {
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        plain: bool,
    ) -> Result<(), CommandError> {
        let device_rc = device.ok_or(DeviceError::NotAvailable)?;

        let (mut rows, stale_grips) = Self::list_keys(context, &device_rc);

        for grip in stale_grips {
            context.remove_context(&grip)?;
        }

        rows.sort_unstable_by(|a, b| a.grip.cmp(&b.grip));

        super::print_table(&mut context.writer, rows, plain)?;

        Ok(())
    }
}
