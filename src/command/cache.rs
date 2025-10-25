// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::SubCommand,
    command::{print_table, CommandError, Tabled},
    device::{with_device, DeviceError},
    handle::{Handle, HandleClass},
    job::{Job, JobError},
    vtpm::{VtpmKey, VtpmSession},
};
use clap::Args;
use tpm2_protocol::data::TpmRcBase;

struct CacheRow {
    handle: String,
    class: String,
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
            self.class.clone(),
            self.details.clone(),
        ]
    }
}

/// Lists cached TPM objects.
#[derive(Args, Debug)]
#[command(about = "Lists cached TPM objects.")]
pub struct Cache {}

impl Cache {
    fn refresh_cache(job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |dev| {
            let vhandles: Vec<u32> = job.cache.contexts.keys().copied().collect();

            for vhandle in vhandles {
                let context_is_key = job
                    .cache
                    .contexts
                    .get(&vhandle)
                    .is_some_and(|ctx| ctx.as_any().is::<VtpmKey>());
                let context_is_session = !context_is_key
                    && job
                        .cache
                        .contexts
                        .get(&vhandle)
                        .is_some_and(|ctx| ctx.as_any().is::<VtpmSession>());

                let handle_ref = Handle((HandleClass::Vtpm, vhandle));

                if context_is_key {
                    match job.load_context(dev, &handle_ref, &[]) {
                        Ok(handle) => {
                            dev.flush_context(handle)?;
                            job.cache.untrack(handle.0);
                        }
                        Err(JobError::Device(DeviceError::TpmRc(rc)))
                            if rc.base() == TpmRcBase::ReferenceH0 =>
                        {
                            log::debug!("vtpm:{vhandle:08x} is stale");
                            job.cache.remove(dev, vhandle)?;
                        }
                        Err(e) => return Err(e.into()),
                    }
                } else if context_is_session {
                    match job.load_context(dev, &handle_ref, &[]) {
                        Ok(handle) => match dev.save_context(handle.0) {
                            Ok(new_context) => {
                                if let Some(session) =
                                    job.cache.contexts.get_mut(&vhandle).and_then(|ctx| {
                                        ctx.as_any_mut().downcast_mut::<VtpmSession>()
                                    })
                                {
                                    session.context = new_context;
                                    job.cache.mark_dirty(vhandle);
                                } else {
                                    let _ = dev.flush_context(handle);
                                }
                                job.cache.untrack(handle.0);
                            }
                            Err(save_err) => {
                                log::warn!("vtpm:{vhandle:08x}: {save_err}");
                                if let Err(flush_err) = dev.flush_context(handle) {
                                    log::warn!("vtpm:{vhandle:08x}: {flush_err}");
                                }
                                job.cache.remove(dev, vhandle)?;
                                if !matches!(save_err, DeviceError::TpmRc(rc) if rc.base() == TpmRcBase::ReferenceH0)
                                {
                                    return Err(save_err.into());
                                }
                            }
                        },
                        Err(JobError::Device(DeviceError::TpmRc(rc)))
                            if rc.base() == TpmRcBase::ReferenceH0 =>
                        {
                            log::debug!("vtpm:{vhandle:08x} is stale");
                            job.cache.remove(dev, vhandle)?;
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Ok(())
        })
    }
}

impl SubCommand for Cache {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        Self::refresh_cache(job)?;

        let mut rows: Vec<CacheRow> = job
            .cache
            .contexts
            .values()
            .map(|ctx| CacheRow {
                handle: format!("{:08x}", ctx.handle()),
                class: ctx.class().to_string(),
                details: ctx.details(),
            })
            .collect();
        rows.sort_unstable_by(|a, b| a.handle.cmp(&b.handle));

        print_table(&mut job.writer, &rows)?;
        Ok(())
    }
}
