//! SPDX-License-Identifier: GPL-3-0-or-later
//! Copyright (c) 2025 Opinsys Oy
//! Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Task,
    command::{print_table, CommandError},
    device::with_device,
    task::TaskState,
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
    fn refresh_cache(
        task_state: &mut TaskState,
        _writer: &mut dyn std::io::Write,
    ) -> Result<(), CommandError> {
        with_device(task_state.device.clone(), |dev| {
            let vhandles: Vec<u32> = task_state.cache.contexts.keys().copied().collect();
            let mut errors: Vec<CommandError> = Vec::new();
            let mut handles_to_remove = Vec::new();

            for &vhandle in &vhandles {
                if let Some(key) = task_state.cache.contexts.get_mut(&vhandle) {
                    match dev.refresh_key(key.context.clone()) {
                        Ok(true) => {
                            task_state.cache.mark_dirty(vhandle);
                        }
                        Ok(false) => handles_to_remove.push(vhandle),
                        Err(e) => {
                            log::warn!("vtpm:{vhandle:08x}: {e}");
                            errors.push(e.into());
                            handles_to_remove.push(vhandle);
                        }
                    }
                }
            }

            for vhandle in handles_to_remove {
                if let Err(e) = task_state.cache.remove(vhandle) {
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
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
    ) -> Result<(), CommandError> {
        Self::refresh_cache(task_state, writer)?;

        let mut rows: Vec<CacheRow> = task_state
            .cache
            .contexts
            .values()
            .map(|key| CacheRow {
                handle: format!("{:08x}", key.handle.0),
                class: "transient".to_string(),
                details: crate::alg::alg_details(&key.public),
            })
            .collect();
        rows.sort_unstable_by(|a, b| a.handle.cmp(&b.handle));

        print_table(&rows, writer, task_state.is_tty)?;
        Ok(())
    }
}
