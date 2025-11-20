// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::{AuthArgs, CommandError},
    task::TaskState,
};
use clap::Args;
use tpm2_device::with_device;
use tpm2_protocol::{data::TpmHt, TpmHandle};
use tpm2_vtpm::{VtpmHandle, VtpmHandleClass};

/// Deletes active and cached objects.
#[derive(Args, Debug)]
pub struct Delete {
    /// Input: 'tpm:<handle pattern>', or 'vtpm:<handle pattern>'
    pub input: VtpmHandle,

    #[clap(flatten)]
    pub auth_args: AuthArgs,
}

impl Task for Delete {
    fn run(
        &self,
        task_state: &mut TaskState,
        writer: &mut dyn std::io::Write,
    ) -> Result<(), CommandError> {
        match self.input.class() {
            VtpmHandleClass::Tpm => {
                delete_tpm_handles(task_state, writer, &self.input, &self.auth_args)
            }
            VtpmHandleClass::Vtpm => delete_vtpm_handles(task_state, writer, &self.input),
        }
    }
}

/// Deletes TPM objects matching a pattern across sessions, transient, and persistent handles.
fn delete_tpm_handles(
    task_state: &mut TaskState,
    writer: &mut dyn std::io::Write,
    pattern: &VtpmHandle,
    auth_args: &AuthArgs,
) -> Result<(), CommandError> {
    with_device(task_state.device.clone(), |dev| {
        for class in [
            TpmHt::HmacSession,
            TpmHt::PolicySession,
            TpmHt::Transient,
            TpmHt::Persistent,
        ] {
            let handles = dev.fetch_handles(class)?;

            for handle in handles {
                let handle = handle.into();
                if !pattern.matches(handle) {
                    continue;
                }

                match class {
                    TpmHt::HmacSession | TpmHt::PolicySession | TpmHt::Transient => {
                        dev.flush_context(TpmHandle(handle))?;
                        if class == TpmHt::Transient {
                            task_state.untrack_handle(handle);
                        }
                    }
                    TpmHt::Persistent => {
                        let persistent_handle = TpmHandle(handle);
                        task_state.evict_control(
                            dev,
                            persistent_handle,
                            persistent_handle,
                            auth_args.auths(false).as_ref(),
                        )?;
                    }
                    _ => {}
                }

                writeln!(writer, "{handle}")?;
            }
        }
        Ok(())
    })
}

/// Deletes vTPM objects (keys and sessions) matching the pattern.
fn delete_vtpm_handles(
    task_state: &mut TaskState,
    writer: &mut dyn std::io::Write,
    pattern: &VtpmHandle,
) -> Result<(), CommandError> {
    let matched_handles: Vec<u32> = task_state
        .cache
        .key_iter()
        .map(|(h, _)| *h)
        .filter(|&h| pattern.matches(h))
        .collect();

    if matched_handles.is_empty() {
        return Ok(());
    }

    for vhandle in matched_handles {
        if task_state
            .cache
            .find_by_virtual_handle(TpmHandle(vhandle))
            .is_err()
        {
            continue;
        }

        let all_deleted_handles = task_state.cache.remove(vhandle)?;
        for deleted_vhandle in all_deleted_handles {
            writeln!(writer, "vtpm:{deleted_vhandle:08x}")?;
        }
    }
    Ok(())
}
