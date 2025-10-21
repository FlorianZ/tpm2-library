// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{CommandError, HierarchyAuthArgs},
    device::{with_device, Device, DeviceError},
    job::Job,
    key_cache::KeyCacheError,
    scheme::{Handle, Scheme},
    wildcard::{WildcardError, WildcardPattern},
};
use clap::Args;
use tpm2_protocol::{
    data::{TpmHt, TpmRcBase, TpmRh},
    TpmHandle,
};

/// Deletes active and cached objects.
#[derive(Args, Debug)]
pub struct Delete {
    /// Input: 'tpm:<handle pattern>', or 'vtpm:<handle pattern>'
    pub input: String,

    #[clap(flatten)]
    pub hierarchy_args: HierarchyAuthArgs,
}

impl SubCommand for Delete {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        if let Some(pattern) = self.input.strip_prefix("tpm:") {
            delete_tpm_handles(job, pattern, &self.hierarchy_args)
        } else if let Some(pattern) = self.input.strip_prefix("vtpm:") {
            delete_vtpm_handles(job, pattern)
        } else {
            Err(CommandError::InvalidInput(self.input.to_string()))
        }
    }
}

impl From<WildcardError> for CommandError {
    fn from(err: WildcardError) -> Self {
        CommandError::InvalidInput(format!("Invalid handle pattern: {err}"))
    }
}

fn delete_tpm_handles(
    job: &mut Job,
    pattern: &str,
    hierarchy_args: &HierarchyAuthArgs,
) -> Result<(), CommandError> {
    let transient_res = delete_tpm_transient_handles(job, pattern);
    let persistent_res = delete_tpm_persistent_handles(job, pattern, hierarchy_args);
    transient_res.and(persistent_res)
}

fn delete_tpm_transient_handles(job: &mut Job, pattern: &str) -> Result<(), CommandError> {
    with_device(job.device.clone(), |dev| -> Result<(), CommandError> {
        let pattern = WildcardPattern::new(pattern)?;
        let handles = dev.fetch_handles((TpmHt::Transient as u32) << 24)?;
        for handle in handles.into_iter().filter(|&h| pattern.matches(h)) {
            dev.flush_context(handle.into())?;
            writeln!(job.key_cache.writer, "tpm:{handle:08x}")?;
            job.key_cache.untrack(handle);
        }
        Ok(())
    })
}

fn delete_tpm_persistent_handles(
    job: &mut Job,
    pattern: &str,
    hierarchy_args: &HierarchyAuthArgs,
) -> Result<(), CommandError> {
    with_device(job.device.clone(), |dev| -> Result<(), CommandError> {
        let pattern = WildcardPattern::new(pattern)?;
        let handles = dev.fetch_handles((TpmHt::Persistent as u32) << 24)?;
        for handle in handles.into_iter().filter(|&h| pattern.matches(h)) {
            let persistent_handle = TpmHandle(handle);
            let auth_handle_val: TpmHandle = if (handle & 0x00FF_FFFF) <= 0x007F_FFFF {
                (TpmRh::Owner as u32).into()
            } else {
                (TpmRh::Platform as u32).into()
            };
            let mut auths = vec![hierarchy_args.auth.clone().unwrap_or_default()];

            dev.evict_control(
                job,
                auth_handle_val,
                persistent_handle,
                persistent_handle,
                &mut auths,
            )?;
            writeln!(job.key_cache.writer, "tpm:{handle:08x}")?;
        }
        Ok(())
    })
}

fn delete_vtpm_handles(job: &mut Job, pattern_str: &str) -> Result<(), CommandError> {
    let pattern = WildcardPattern::new(pattern_str)?;

    let matched_transients: Vec<u32> = job
        .key_cache
        .contexts
        .keys()
        .copied()
        .filter(|&h| pattern.matches(h))
        .collect();

    let matched_sessions: Vec<u32> = job
        .session_cache
        .sessions
        .keys()
        .copied()
        .filter(|&h| pattern.matches(h))
        .collect();

    if matched_transients.is_empty() && matched_sessions.is_empty() {
        return Ok(());
    }

    with_device(job.device.clone(), |dev| {
        let delete_vtpm_transient_handles =
            |job: &mut Job, dev: &mut Device, vhandles: &[u32]| -> Result<(), CommandError> {
                for &vhandle in vhandles {
                    let uri = Scheme::Vtpm(Handle::Transient(vhandle));
                    match job.key_cache.load_context(dev, &uri) {
                        Ok(handle) => {
                            dev.flush_context(handle)?;
                            writeln!(job.key_cache.writer, "vtpm:{vhandle:08x}")?;
                            job.key_cache.untrack(handle.0);
                            job.key_cache.remove_context(vhandle)?;
                        }
                        Err(KeyCacheError::Device(DeviceError::TpmRc(rc)))
                            if rc.base() == TpmRcBase::ReferenceH0 =>
                        {
                            log::debug!("vtpm:{vhandle:08x} stale during load, removing");
                            writeln!(job.key_cache.writer, "vtpm:{vhandle:08x}")?;
                            job.key_cache.remove_context(vhandle)?;
                        }
                        Err(KeyCacheError::ContextNotFound(_)) => {
                            log::debug!(
                                "vtpm:{vhandle:08x} not found in cache, removing file if exists"
                            );
                            writeln!(job.key_cache.writer, "vtpm:{vhandle:08x}")?;
                            job.key_cache.remove_context(vhandle)?;
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                Ok(())
            };

        let delete_vtpm_session_handles =
            |job: &mut Job, dev: &mut Device, vhandles: &[u32]| -> Result<(), CommandError> {
                for &vhandle in vhandles {
                    let session_opt = job.session_cache.remove(vhandle)?;
                    if let Some(session) = session_opt {
                        match dev.flush_session(session.context) {
                            Ok(()) => {
                                writeln!(job.key_cache.writer, "vtpm:{vhandle:08x}")?;
                            }
                            Err(DeviceError::TpmRc(rc)) if rc.base() == TpmRcBase::ReferenceH0 => {
                                log::debug!("vtpm session:{vhandle:08x} stale during flush");
                                writeln!(job.key_cache.writer, "vtpm:{vhandle:08x}")?;
                            }
                            Err(e) => return Err(e.into()),
                        }
                    } else {
                        log::debug!("vtpm session:{vhandle:08x} not found in cache");
                        writeln!(job.key_cache.writer, "vtpm:{vhandle:08x}")?;
                    }
                }
                Ok(())
            };

        delete_vtpm_transient_handles(job, dev, &matched_transients)?;
        delete_vtpm_session_handles(job, dev, &matched_sessions)
    })
}
