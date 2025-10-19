// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{print_table, CommandError},
    device::with_device,
    job::Job,
    key::{self, KeyCacheError, KeyError},
};
use clap::Args;
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
#[derive(Args, Debug)]
#[command(about = "Lists keys from local cache.")]
pub struct Key {}

impl Key {
    fn refresh(job: &mut Job) -> Result<(), KeyCacheError> {
        let grips: Vec<String> = job.key_cache.contexts.keys().cloned().collect();
        if grips.is_empty() {
            return Ok(());
        }

        with_device(job.device.clone(), |device| {
            for grip in grips {
                let uri = crate::uri::Uri::Key(grip);
                match job.key_cache.load_context(device, &uri) {
                    Ok(handle) => {
                        device.flush_context(handle.0)?;
                    }
                    Err(KeyCacheError::ContextNotFound(_)) => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        })
    }
}

impl SubCommand for Key {
    fn run(&self, job: &mut Job, plain: bool) -> Result<(), CommandError> {
        Key::refresh(job)?;

        let mut rows: Vec<KeyRow> = Vec::new();
        for (grip, key) in &job.key_cache.contexts {
            let (public_blob, _) =
                Tpm2bPublic::parse(&key.public).map_err(|e| KeyError::Device(e.into()))?;
            rows.push(KeyRow {
                grip: grip.clone(),
                details: key::format_alg_from_public(&public_blob.inner),
            });
        }
        rows.sort_unstable_by(|a, b| a.grip.cmp(&b.grip));
        print_table(&mut job.key_cache.writer, rows, plain)?;
        Ok(())
    }

    fn is_local(&self) -> bool {
        false
    }
}
