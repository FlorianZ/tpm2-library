// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::Task,
    command::{AuthArgs, CommandError},
    device::with_device,
    handle::HandlePattern,
    session::Session,
};
use clap::Args;
use tpm2_protocol::{data::TpmHt, TpmHandle};

/// Deletes active and cached objects.
#[derive(Args, Debug)]
pub struct Delete {
    /// Input: 'tpm:<handle pattern>', or 'vtpm:<handle pattern>'
    pub input: String,

    #[clap(flatten)]
    pub auth_args: AuthArgs,
}

impl Task for Delete {
    fn run(&self, job: &mut Session) -> Result<(), CommandError> {
        if let Some(pattern) = self.input.strip_prefix("tpm:") {
            delete_tpm_handles(job, pattern, &self.auth_args)
        } else if let Some(pattern) = self.input.strip_prefix("vtpm:") {
            delete_vtpm_handles(job, pattern)
        } else {
            Err(CommandError::InvalidInput(self.input.to_string()))
        }
    }
}

/// Deletes TPM objects matching a pattern across sessions, transient, and persistent handles.
fn delete_tpm_handles(
    job: &mut Session,
    pattern_str: &str,
    auth_args: &AuthArgs,
) -> Result<(), CommandError> {
    with_device(job.device.clone(), |dev| {
        let pattern = HandlePattern::new(pattern_str)?;

        for class in [
            TpmHt::HmacSession,
            TpmHt::PolicySession,
            TpmHt::Transient,
            TpmHt::Persistent,
        ] {
            let handles = dev.fetch_handles((class as u32) << 24)?;
            for handle in handles.into_iter().filter(|&h| pattern.matches(h.value())) {
                match class {
                    TpmHt::HmacSession | TpmHt::PolicySession | TpmHt::Transient => {
                        dev.flush_context(TpmHandle(handle.value()))?;
                        if class == TpmHt::Transient {
                            job.cache.untrack(handle.value());
                        }
                    }
                    TpmHt::Persistent => {
                        let persistent_handle = TpmHandle(handle.value());
                        job.evict_control(
                            dev,
                            persistent_handle,
                            persistent_handle,
                            auth_args.auths().as_ref(),
                        )?;
                    }
                    _ => {}
                }
                writeln!(job.writer, "{handle}")?;
            }
        }
        Ok(())
    })
}

/// Deletes vTPM objects (keys and sessions) matching the pattern.
fn delete_vtpm_handles(job: &mut Session, pattern_str: &str) -> Result<(), CommandError> {
    let pattern = HandlePattern::new(pattern_str)?;

    let matched_handles: Vec<u32> = job
        .cache
        .contexts
        .keys()
        .copied()
        .filter(|&h| pattern.matches(h))
        .collect();

    if matched_handles.is_empty() {
        return Ok(());
    }

    with_device(job.device.clone(), |dev| {
        for vhandle in matched_handles {
            if !job.cache.contexts.contains_key(&vhandle) {
                continue;
            }

            let all_deleted_handles = job.cache.remove(dev, vhandle)?;
            for deleted_vhandle in all_deleted_handles {
                writeln!(job.writer, "vtpm:{deleted_vhandle:08x}")?;
            }
        }
        Ok(())
    })
}
