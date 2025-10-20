// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::SubCommand,
    command::{print_table, CommandError},
    device::with_device,
    job::Job,
    key::{format_alg_from_public, KeyCacheError},
    scheme::Scheme,
};
use clap::Args;
use tabled::Tabled;
use tpm2_protocol::data::TpmSe;

#[derive(Tabled)]
struct VirtualRow {
    #[tabled(rename = "HANDLE")]
    handle: String,
    #[tabled(rename = "TYPE")]
    handle_type: String,
    #[tabled(rename = "DETAILS")]
    details: String,
}

/// Lists objects inside TPM memory.
#[derive(Args, Debug)]
#[command(about = "Lists objects inside TPM memory")]
pub struct Virtual {}

impl Virtual {
    fn fetch_session_rows(job: &mut Job, rows: &mut Vec<VirtualRow>) {
        let mut vhandles: Vec<u32> = Vec::new();
        for (_, session) in &job.session_cache {
            let handle = session.context.saved_handle.0;
            if session.session_type == TpmSe::Policy {
                vhandles.push(handle);
            }
        }
        for vhandle in vhandles {
            rows.push(VirtualRow {
                handle: format!("{vhandle:08x}"),
                handle_type: "policy".to_string(),
                details: String::new(),
            });
        }
    }

    fn fetch_transient_rows(job: &mut Job, rows: &mut Vec<VirtualRow>) {
        for (vhandle, key) in &job.key_cache.contexts {
            rows.push(VirtualRow {
                handle: format!("{vhandle:08x}"),
                handle_type: "transient".to_string(),
                details: format_alg_from_public(&key.public.inner),
            });
        }
    }

    fn refresh_transient(job: &mut Job) -> Result<(), KeyCacheError> {
        let vhandles: Vec<u32> = job.key_cache.contexts.keys().copied().collect();
        with_device(job.device.clone(), |device| {
            for vhandle in vhandles {
                let uri = Scheme::Transient(vhandle);
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

impl SubCommand for Virtual {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        Self::refresh_transient(job)?;
        let mut rows: Vec<VirtualRow> = Vec::new();
        Self::fetch_session_rows(job, &mut rows);
        Self::fetch_transient_rows(job, &mut rows);
        rows.sort_unstable_by(|a, b| a.handle.cmp(&b.handle));
        print_table(&mut job.key_cache.writer, rows)?;
        Ok(())
    }
}
