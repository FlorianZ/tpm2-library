//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Task,
    command::{print_table, CommandError},
    device::with_device,
    task::TaskState,
    vtpm::{RefreshAction, VtpmSession},
};
use clap::Args;
use tabled::Tabled;

#[derive(Tabled)]
struct CacheRow {
    #[tabled(rename = "HANDLE")]
    handle: String,
    #[tabled(rename = "TYPE")]
    class: String,
    #[tabled(rename = "DETAILS")]
    details: String,
}

/// Lists cached TPM objects.
#[derive(Args, Debug)]
#[command(about = "Lists cached TPM objects.")]
pub struct Cache {}

impl Cache {
    fn refresh_cache(task_state: &mut TaskState) -> Result<(), CommandError> {
        with_device(task_state.device.clone(), |dev| {
            let vhandles: Vec<u32> = task_state.cache.contexts.keys().copied().collect();
            let mut results = Vec::with_capacity(vhandles.len());

            for &vhandle in &vhandles {
                if let Some(context) = task_state.cache.contexts.get_mut(&vhandle) {
                    results.push((vhandle, context.refresh(dev)));
                }
            }

            let mut errors: Vec<CommandError> = Vec::new();
            let mut handles_to_remove = Vec::new();

            for (vhandle, result) in results {
                match result {
                    Ok(RefreshAction::Keep) => {}
                    Ok(RefreshAction::Stale) => handles_to_remove.push(vhandle),
                    Ok(RefreshAction::Updated(new_context)) => {
                        if let Some(session) = task_state
                            .cache
                            .contexts
                            .get_mut(&vhandle)
                            .and_then(|ctx| ctx.as_any_mut().downcast_mut::<VtpmSession>())
                        {
                            session.context = *new_context;
                            task_state.cache.mark_dirty(vhandle);
                        } else {
                            log::error!("vtpm:{vhandle:08x}: context type mismatch on update");
                            handles_to_remove.push(vhandle);
                        }
                    }
                    Err(e) => {
                        log::warn!("vtpm:{vhandle:08x}: {e}");
                        errors.push(e.into());
                        handles_to_remove.push(vhandle);
                    }
                }
            }

            for vhandle in handles_to_remove {
                if let Err(e) = task_state.cache.remove(dev, vhandle) {
                    log::error!("vtpm:{vhandle:08x}: {e}");
                    errors.push(e.into());
                }
            }

            if let Some(err) = errors.into_iter().next() {
                Err(err)
            } else {
                Ok(())
            }
        })
    }
}

impl Task for Cache {
    fn run(&self, task_state: &mut TaskState) -> Result<(), CommandError> {
        Self::refresh_cache(task_state)?;

        let mut rows: Vec<CacheRow> = task_state
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

        print_table(task_state, &rows)?;
        Ok(())
    }
}
