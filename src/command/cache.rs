// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::SubCommand,
    command::{print_table, CommandError, Tabled},
    device::{with_device, Device, DeviceError},
    handle::{Handle, HandleClass},
    job::Job,
    key::format_alg_from_public,
    key_cache::KeyCacheError,
};
use clap::Args;
use tpm2_protocol::data::{TpmHt, TpmRcBase};

struct CacheRow {
    handle: String,
    handle_type: String,
    details: String,
}

impl Tabled for CacheRow {
    fn headers() -> Vec<String> {
        vec![
            "HANDLE".to_string(),
            "TYPE".to_string(),
            "DETAILS".to_string(),
        ]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.handle.clone(),
            self.handle_type.clone(),
            self.details.clone(),
        ]
    }
}

/// Lists cached TPM objects.
#[derive(Args, Debug)]
#[command(about = "Lists cached TPM objects.")]
pub struct Cache {}

impl Cache {
    fn fetch_session_rows(job: &mut Job, rows: &mut Vec<CacheRow>) {
        for session in job.session_cache.sessions.values() {
            let vhandle = session.context.saved_handle.0;
            if (vhandle >> 24) as u8 == TpmHt::PolicySession as u8 {
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
            let handle_type = Handle((HandleClass::Vtpm, vhandle));
            match job.key_cache.load_context(device, &handle_type) {
                Ok(handle) => {
                    device.flush_context(handle)?;
                    job.key_cache.untrack(handle.0);
                }
                Err(KeyCacheError::ContextNotFound(_)) => {}
                Err(KeyCacheError::Device(DeviceError::TpmRc(rc))) => {
                    if rc.base() == TpmRcBase::ReferenceH0 {
                        log::debug!("vtpm:{vhandle:08x} stale");
                        job.key_cache.remove_context(vhandle)?;
                    } else {
                        return Err(KeyCacheError::Device(DeviceError::TpmRc(rc)).into());
                    }
                }
                Err(e) => return Err(e.into()),
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
                    Ok(context) => match job.session_cache.get_mut(vhandle) {
                        Ok(session) => {
                            session.context = context;
                            job.session_cache.dirty.insert(vhandle);
                        }
                        Err(err) => {
                            log::debug!("vtpm:{vhandle:08x}: {err}");
                        }
                    },
                    Err(e) => {
                        log::warn!("vtpm:{vhandle:08x}: {e}");
                        if let Err(flush_err) = device.flush_context(live_handle.into()) {
                            log::warn!("vtpm:{vhandle:08x}: {flush_err}");
                        }
                        return Err(e.into());
                    }
                },
                Err(DeviceError::TpmRc(rc)) => {
                    if rc.base() == TpmRcBase::ReferenceH0 {
                        log::debug!("vtpm:{vhandle:08x} stale");
                        job.session_cache.remove(vhandle)?;
                    } else {
                        return Err(DeviceError::TpmRc(rc).into());
                    }
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
        print_table(&mut job.key_cache.writer, &rows)?;
        Ok(())
    }
}
