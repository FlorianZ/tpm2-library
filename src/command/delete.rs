// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{CommandError, HierarchyAuthArgs},
    device::{with_device, Device, DeviceError},
    handle::{Handle, HandlePattern},
    job::Job,
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

fn delete_tpm_handles(
    job: &mut Job,
    pattern: &str,
    hierarchy_args: &HierarchyAuthArgs,
) -> Result<(), CommandError> {
    let session_res = delete_tpm_session_handles(job, pattern);
    let transient_res = delete_tpm_transient_handles(job, pattern);
    let persistent_res = delete_tpm_persistent_handles(job, pattern, hierarchy_args);

    session_res.and(transient_res).and(persistent_res)
}

fn for_each_tpm_handle<F>(
    job: &mut Job,
    pattern_str: &str,
    handle_type: TpmHt,
    mut action: F,
) -> Result<(), CommandError>
where
    F: FnMut(&mut Device, &mut Job, Handle) -> Result<(), CommandError>,
{
    with_device(job.device.clone(), |dev| {
        let pattern = HandlePattern::new(pattern_str)?;
        let handles = dev.fetch_handles((handle_type as u32) << 24)?;
        for handle in handles.into_iter().filter(|&h| pattern.matches(h.value())) {
            action(dev, job, handle)?;
        }
        Ok(())
    })
}

fn delete_tpm_session_handles(job: &mut Job, pattern: &str) -> Result<(), CommandError> {
    let action = |dev: &mut Device, job: &mut Job, handle: Handle| {
        dev.flush_context(TpmHandle(handle.value()))?;
        writeln!(job.key_cache.writer, "{handle}")?;
        Ok(())
    };

    let hmac_res = for_each_tpm_handle(job, pattern, TpmHt::HmacSession, action);
    let policy_res = for_each_tpm_handle(job, pattern, TpmHt::PolicySession, action);

    hmac_res.and(policy_res)
}

fn delete_tpm_transient_handles(job: &mut Job, pattern: &str) -> Result<(), CommandError> {
    for_each_tpm_handle(job, pattern, TpmHt::Transient, |dev, job, handle| {
        dev.flush_context(TpmHandle(handle.value()))?;
        writeln!(job.key_cache.writer, "{handle}")?;
        job.key_cache.untrack(handle.value());
        Ok(())
    })
}

fn delete_tpm_persistent_handles(
    job: &mut Job,
    pattern: &str,
    hierarchy_args: &HierarchyAuthArgs,
) -> Result<(), CommandError> {
    for_each_tpm_handle(job, pattern, TpmHt::Persistent, |dev, job, handle| {
        let persistent_handle = TpmHandle(handle.value());
        let auth_handle_val: TpmHandle = if (handle.value() & 0x00FF_FFFF) <= 0x007F_FFFF {
            (TpmRh::Owner as u32).into()
        } else {
            (TpmRh::Platform as u32).into()
        };
        let auths = vec![hierarchy_args.auth.clone().unwrap_or_default()];

        dev.evict_control(
            job,
            auth_handle_val,
            persistent_handle,
            persistent_handle,
            &auths,
        )?;
        writeln!(job.key_cache.writer, "{handle}")?;
        Ok(())
    })
}

fn delete_vtpm_session(job: &mut Job, dev: &mut Device, vhandle: u32) -> Result<(), CommandError> {
    let session_opt = job.session_cache.remove(vhandle)?;
    if let Some(session) = session_opt {
        match dev.flush_session(session.context) {
            Ok(()) => {}
            Err(DeviceError::TpmRc(rc)) => {
                if rc.base() == TpmRcBase::ReferenceH0 {
                    log::debug!("vtpm session:{vhandle:08x} stale");
                } else {
                    return Err(DeviceError::TpmRc(rc).into());
                }
            }
            Err(e) => return Err(e.into()),
        }
    } else {
        log::warn!("vtpm session:{vhandle:08x} not found");
    }
    writeln!(job.key_cache.writer, "vtpm:{vhandle:08x}")?;
    Ok(())
}

fn delete_vtpm_handles(job: &mut Job, pattern_str: &str) -> Result<(), CommandError> {
    let pattern = HandlePattern::new(pattern_str)?;

    let matched_keys: Vec<u32> = job
        .key_cache
        .contexts
        .keys()
        .copied()
        .filter(|&h| pattern.matches(h))
        .collect();

    for vhandle in matched_keys {
        job.key_cache.remove_context(vhandle)?;
        writeln!(job.key_cache.writer, "vtpm:{vhandle:08x}")?;
    }

    let matched_sessions: Vec<u32> = job
        .session_cache
        .sessions
        .keys()
        .copied()
        .filter(|&h| pattern.matches(h))
        .collect();

    if !matched_sessions.is_empty() {
        with_device(job.device.clone(), |dev| -> Result<(), CommandError> {
            for vhandle in matched_sessions {
                delete_vtpm_session(job, dev, vhandle)?;
            }
            Ok(())
        })?;
    }

    Ok(())
}
