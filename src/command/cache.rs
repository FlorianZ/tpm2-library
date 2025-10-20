// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::SubCommand,
    command::{print_table, CommandError},
    device::{with_device, Device, DeviceError},
    job::Job,
    key::format_alg_from_public,
    key_cache::KeyCacheError,
    scheme::{Handle, Scheme},
};
use clap::Args;
use tabled::Tabled;
use tpm2_protocol::data::{TpmRcBase, TpmSe};

#[derive(Tabled)]
struct CacheRow {
    #[tabled(rename = "HANDLE")]
    handle: String,
    #[tabled(rename = "TYPE")]
    handle_type: String,
    #[tabled(rename = "DETAILS")]
    details: String,
}

/// Lists cached TPM objects.
#[derive(Args, Debug)]
#[command(about = "Lists cached TPM objects.")]
pub struct Cache {}

impl Cache {
    fn fetch_session_rows(job: &mut Job, rows: &mut Vec<CacheRow>) {
        let mut vhandles: Vec<u32> = Vec::new();
        for session in job.session_cache.sessions.values() {
            let handle = session.context.saved_handle.0;
            if session.session_type == TpmSe::Policy {
                vhandles.push(handle);
            }
        }
        for vhandle in vhandles {
            if job.session_cache.get(vhandle).is_ok() {
                rows.push(CacheRow {
                    handle: format!("{vhandle:08x}"),
                    handle_type: "policy".to_string(),
                    details: String::new(),
                });
            }
        }
    }

    fn fetch_transient_rows(job: &mut Job, rows: &mut Vec<CacheRow>) {
        for (vhandle, key) in &job.key_cache.contexts {
            rows.push(CacheRow {
                handle: format!("{vhandle:08x}"),
                handle_type: "transient".to_string(),
                details: format_alg_from_public(&key.public.inner),
            });
        }
    }

    fn refresh_key_cache(device: &mut Device, job: &mut Job) -> Result<(), CommandError> {
        let vhandles: Vec<u32> = job.key_cache.contexts.keys().copied().collect();
        for vhandle in vhandles {
            let uri = Scheme::Vtpm(Handle::Transient(vhandle));
            match job.key_cache.load_context(device, &uri) {
                Ok(handle) => {
                    device.flush_context(handle.0)?;
                    job.key_cache.untrack(handle.0);
                }
                Err(KeyCacheError::ContextNotFound(_)) => {}
                Err(KeyCacheError::Device(DeviceError::TpmRc(rc)))
                    if rc.base() == TpmRcBase::ReferenceH0 =>
                {
                    log::debug!("vtpm:{vhandle:08x} stale");
                    job.key_cache.remove_context(vhandle)?;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }

    fn refresh_session_cache(device: &mut Device, job: &mut Job) -> Result<(), CommandError> {
        let vhandles: Vec<u32> = job.session_cache.sessions.keys().copied().collect();
        for vhandle in vhandles {
            let Ok(session) = job.session_cache.get(vhandle) else {
                continue;
            };
            let context_to_load = session.context.clone();

            match device.load_context(context_to_load) {
                Ok(live_handle) => match device.save_context(live_handle) {
                    Ok(new_context) => {
                        if let Ok(s) = job.session_cache.get_mut(vhandle) {
                            s.context = new_context;
                        }
                        if let Err(e) = device.flush_context(live_handle) {
                            log::warn!("vtpm:{vhandle:08x}: {e}");
                            return Err(e.into());
                        }
                    }
                    Err(e) => {
                        log::warn!("vtpm:{vhandle:08x}: {e}");
                        if let Err(flush_err) = device.flush_context(live_handle) {
                            log::warn!("vtpm:{vhandle:08x}: {flush_err}");
                        }
                        return Err(e.into());
                    }
                },
                Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::ReferenceH0 => {
                    log::debug!("vtpm:{vhandle:08x} stale");
                    job.session_cache.remove(vhandle)?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

impl SubCommand for Cache {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            Self::refresh_session_cache(device, job)?;
            Self::refresh_key_cache(device, job)
        })?;
        let mut rows: Vec<CacheRow> = Vec::new();
        Self::fetch_session_rows(job, &mut rows);
        Self::fetch_transient_rows(job, &mut rows);
        rows.sort_unstable_by(|a, b| a.handle.cmp(&b.handle));
        print_table(&mut job.key_cache.writer, rows)?;
        Ok(())
    }
}
