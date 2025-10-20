// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{print_table, CommandError},
    device::with_device,
    job::Job,
    key::{self, KeyCacheError},
    uri::Uri,
};
use clap::Args;
use tabled::Tabled;

#[derive(Tabled)]
struct KeyRow {
    #[tabled(rename = "HANDLE")]
    handle: String,
    #[tabled(rename = "DETAILS")]
    details: String,
}

/// Lists cached keys.
#[derive(Args, Debug)]
#[command(about = "Lists keys from local cache.")]
pub struct Key {}

impl Key {
    fn refresh(job: &mut Job) -> Result<(), KeyCacheError> {
        let vhandles: Vec<u32> = job.key_cache.contexts.keys().copied().collect();
        with_device(job.device.clone(), |device| {
            for vhandle in vhandles {
                let uri = Uri::Key(vhandle);
                match job.key_cache.load_context(device, &uri) {
                    Ok(handle) => {
                        device.flush_context(handle.0)?;
                        job.key_cache.untrack(handle.0);
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
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        Key::refresh(job)?;
        let mut rows: Vec<KeyRow> = Vec::new();
        for (vhandle, key) in &job.key_cache.contexts {
            rows.push(KeyRow {
                handle: format!("{vhandle:08x}"),
                details: key::format_alg_from_public(&key.public.inner),
            });
        }
        rows.sort_unstable_by(|a, b| a.handle.cmp(&b.handle));
        print_table(&mut job.key_cache.writer, rows)?;
        Ok(())
    }

    fn is_local(&self) -> bool {
        false
    }
}
