// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::Task, error::device_err, task::TaskState};
use anyhow::{Result, anyhow};
use argh::FromArgs;
use tpm2_device::with_device;
use tpm2_protocol::{basic::TpmUint32, data::TpmHt};

/// Deletes active and cached objects.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "delete", help_triggers("-h", "--help", "help"))]
pub struct Delete {
    /// TPM handle as an eight characters hex string or wildcard pattern
    #[argh(positional)]
    pub handle: crate::handle::Handle,
}

impl Task for Delete {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
        _is_tty: bool,
    ) -> Result<()> {
        let tpm_result = delete_tpm_handles(task_state, writer, self.handle);
        let vtpm_result = delete_vtpm_handles(task_state, writer, self.handle);

        tpm_result.and(vtpm_result)
    }
}

/// Deletes TPM objects matching a pattern across sessions, transient, and persistent handles.
fn delete_tpm_handles(
    task_state: &mut TaskState,
    writer: &mut dyn std::io::Write,
    pattern: crate::handle::Handle,
) -> Result<()> {
    with_device(task_state.device.clone(), |dev| {
        let mut failed = false;

        for class in [
            TpmHt::HmacSession,
            TpmHt::PolicySession,
            TpmHt::Transient,
            TpmHt::Persistent,
        ] {
            let Ok(handles) = dev.fetch_handles(class) else {
                continue;
            };

            for handle in handles {
                let handle = handle.into();
                if !pattern.matches(handle) {
                    continue;
                }

                let result = match class {
                    TpmHt::HmacSession | TpmHt::PolicySession | TpmHt::Transient => dev
                        .flush_context(TpmUint32::new(handle))
                        .map_err(device_err)
                        .map(|()| {
                            if class == TpmHt::Transient {
                                task_state.untrack(TpmUint32::new(handle));
                            }
                        }),
                    TpmHt::Persistent => {
                        let persistent_handle = TpmUint32::new(handle);
                        task_state.evict_control(dev, persistent_handle, persistent_handle)
                    }
                    _ => Ok(()),
                };

                match result {
                    Ok(()) => {
                        if let Err(e) = writeln!(writer, "{handle:08x}") {
                            return Err(e.into());
                        }
                    }
                    Err(e) => {
                        log::error!("{handle:08x}: {e}");
                        failed = true;
                    }
                }
            }
        }

        if failed {
            Err(anyhow!("delete failed"))
        } else {
            Ok(())
        }
    })
}

/// Deletes vTPM objects (keys and sessions) matching the pattern.
fn delete_vtpm_handles(
    task_state: &mut TaskState,
    writer: &mut dyn std::io::Write,
    pattern: crate::handle::Handle,
) -> Result<()> {
    let matched_handles: Vec<u32> = task_state
        .cache
        .key_iter()
        .map(|(h, _)| *h)
        .filter(|&h| pattern.matches(h))
        .collect();

    if matched_handles.is_empty() {
        return Ok(());
    }

    let mut failed = false;

    for vhandle in matched_handles {
        match task_state.cache.remove(vhandle) {
            Ok(all_deleted_handles) => {
                for deleted_vhandle in all_deleted_handles {
                    if let Err(e) = writeln!(writer, "{deleted_vhandle:08x}") {
                        return Err(e.into());
                    }
                }
            }
            Err(e) => {
                log::error!("{vhandle:08x}: {e}");
                failed = true;
            }
        }
    }

    if failed {
        Err(anyhow!("delete failed"))
    } else {
        Ok(())
    }
}
