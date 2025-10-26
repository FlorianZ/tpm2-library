// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::SubCommand,
    command::{deny_too_many_auths, CommandError},
    device::{with_device, Device},
    handle::HandlePattern,
    job::Job,
    vtpm::VtpmKey,
};
use clap::Args;
use std::collections::VecDeque;
use tpm2_protocol::{
    data::{TpmHt, TpmRh, TpmtPublic},
    TpmHandle,
};

/// Deletes active and cached objects.
#[derive(Args, Debug)]
pub struct Delete {
    /// Input: 'tpm:<handle pattern>', or 'vtpm:<handle pattern>'
    pub input: String,
}

impl Delete {
    /// Iteratively finds and removes child keys from the cache using BFS.
    fn delete_vtpm_children(
        job: &mut Job,
        dev: &mut Device,
        first_public: &TpmtPublic,
        deleted: &mut Vec<u32>,
    ) -> Result<(), CommandError> {
        let mut ancestor_list = VecDeque::new();
        ancestor_list.push_back(first_public.clone());

        while let Some(parent_public) = ancestor_list.pop_front() {
            let children_to_process: Vec<(u32, TpmtPublic)> = job
                .cache
                .key_iter()
                .filter(|(_, key)| key.parent.inner == parent_public)
                .map(|(vhandle, key)| (*vhandle, key.public.inner.clone()))
                .collect();

            for (child_vhandle, child_public) in children_to_process {
                if deleted.contains(&child_vhandle)
                    || !job.cache.contexts.contains_key(&child_vhandle)
                {
                    continue;
                }
                job.cache.remove(dev, child_vhandle)?;
                deleted.push(child_vhandle);
                ancestor_list.push_back(child_public);
            }
        }
        Ok(())
    }
}

impl SubCommand for Delete {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        if let Some(pattern) = self.input.strip_prefix("tpm:") {
            delete_tpm_handles(job, pattern)
        } else if let Some(pattern) = self.input.strip_prefix("vtpm:") {
            delete_vtpm_handles(job, pattern)
        } else {
            Err(CommandError::InvalidInput(self.input.to_string()))
        }
    }
}

/// Deletes TPM objects matching a pattern across sessions, transient, and persistent handles.
fn delete_tpm_handles(job: &mut Job, pattern_str: &str) -> Result<(), CommandError> {
    deny_too_many_auths(job.auth_list, 1)?;

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
                        let auth_handle: TpmHandle =
                            if (handle.value() & 0x00FF_FFFF) <= 0x007F_FFFF {
                                (TpmRh::Owner as u32).into()
                            } else {
                                (TpmRh::Platform as u32).into()
                            };
                        let auths = vec![job.auth_list.first().cloned().unwrap_or_default()];
                        job.evict_control(
                            auth_handle,
                            persistent_handle,
                            persistent_handle,
                            &auths,
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
fn delete_vtpm_handles(job: &mut Job, pattern_str: &str) -> Result<(), CommandError> {
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
        let mut deleted_vhandles = Vec::new();

        for vhandle in matched_handles {
            if deleted_vhandles.contains(&vhandle) || !job.cache.contexts.contains_key(&vhandle) {
                continue;
            }

            let maybe_public = if let Some(context) = job.cache.contexts.get(&vhandle) {
                context
                    .as_any()
                    .downcast_ref::<VtpmKey>()
                    .map(|key| key.public.inner.clone())
            } else {
                continue;
            };

            job.cache.remove(dev, vhandle)?;
            writeln!(job.writer, "vtpm:{vhandle:08x}")?;
            deleted_vhandles.push(vhandle);

            if let Some(public_key) = maybe_public {
                Delete::delete_vtpm_children(job, dev, &public_key, &mut deleted_vhandles)?;

                let deleted_children: Vec<u32> = deleted_vhandles
                    .iter()
                    .filter(|&&h| {
                        let vhandle_pos = deleted_vhandles.iter().position(|&x| x == vhandle);
                        let h_pos = deleted_vhandles.iter().position(|&x| x == h);
                        if let (Some(vp), Some(hp)) = (vhandle_pos, h_pos) {
                            hp > vp
                        } else {
                            false
                        }
                    })
                    .copied()
                    .collect();

                for child_vhandle in deleted_children {
                    writeln!(job.writer, "vtpm:{child_vhandle:08x}")?;
                }
            }
        }
        Ok(())
    })
}
