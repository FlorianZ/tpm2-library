// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Task,
    command::{print_table, CommandError, Tabled},
    device::with_device,
    session::Session,
    vtpm::{RefreshAction, VtpmSession},
};
use clap::Args;

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
    fn refresh_cache(job: &mut Session) -> Result<(), CommandError> {
        with_device(job.device.clone(), |dev| {
            let vhandles: Vec<u32> = job.cache.contexts.keys().copied().collect();
            let mut handles_to_remove = Vec::new();
            let mut encountered_error: Option<CommandError> = None;

            for vhandle in vhandles {
                if let Some(context) = job.cache.contexts.get_mut(&vhandle) {
                    match context.refresh(dev) {
                        Ok(RefreshAction::Keep) => {}
                        Ok(RefreshAction::Stale) => {
                            log::debug!("vtpm:{vhandle:08x} is stale");
                            handles_to_remove.push(vhandle);
                        }
                        Ok(RefreshAction::Updated(context)) => {
                            if let Some(session) = job
                                .cache
                                .contexts
                                .get_mut(&vhandle)
                                .and_then(|ctx| ctx.as_any_mut().downcast_mut::<VtpmSession>())
                            {
                                session.context = *context;
                                job.cache.mark_dirty(vhandle);
                            } else {
                                log::error!("vtpm:{vhandle:08x}: context type mismatch");
                                handles_to_remove.push(vhandle);
                            }
                        }
                        Err(e) => {
                            log::warn!("vtpm:{vhandle:08x}: {e}");
                            handles_to_remove.push(vhandle);
                            if encountered_error.is_none() {
                                encountered_error = Some(CommandError::from(e));
                            }
                        }
                    }
                }
            }

            for vhandle in handles_to_remove {
                if let Err(e) = job.cache.remove(dev, vhandle) {
                    log::error!("vtpm:{vhandle:08x}: {e}");
                    if encountered_error.is_none() {
                        encountered_error = Some(CommandError::from(e));
                    }
                }
            }

            if let Some(err) = encountered_error {
                Err(err)
            } else {
                Ok(())
            }
        })
    }
}

impl Task for Cache {
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
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
