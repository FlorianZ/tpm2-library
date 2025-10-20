// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::SubCommand,
    command::{CommandError, HierarchyAuthArgs},
    device::with_device,
    job::Job,
    scheme::{Handle, Scheme},
};
use clap::Args;
use std::str::FromStr;
use tpm2_protocol::{data::TpmRh, TpmHandle};

/// Create persistent object from transient object.
#[derive(Args, Debug)]
pub struct Evict {
    #[clap(flatten)]
    pub hierarchy_args: HierarchyAuthArgs,

    /// Input key: 'vtpm:<vhandle>'
    #[arg(short = 'I', long)]
    pub input: String,

    /// Persistent handle: 'tpm:<handle>'
    #[arg(short = 'O', long)]
    pub output: String,
}

impl SubCommand for Evict {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |dev| -> Result<(), CommandError> {
            let persistent_handle_uri = Scheme::from_str(&self.output)?;
            let persistent_handle_val = match persistent_handle_uri {
                Scheme::Tpm(Handle::Persistent(h)) => Ok(h),
                uri => Err(CommandError::InvalidInput(uri.to_string())),
            }?;
            let persistent_handle = TpmHandle(persistent_handle_val);

            let auth_handle: TpmHandle = if (persistent_handle.0 & 0x00FF_FFFF) <= 0x007F_FFFF {
                (TpmRh::Owner as u32).into()
            } else {
                (TpmRh::Platform as u32).into()
            };

            let transient_uri = Scheme::from_str(&self.input)?;
            let vhandle = match &transient_uri {
                Scheme::Vtpm(Handle::Transient(vh)) => Ok(*vh),
                uri => Err(CommandError::InvalidInput(uri.to_string())),
            }?;
            let transient_handle = job.key_cache.load_context(dev, &transient_uri)?;

            let mut auths = vec![self.hierarchy_args.auth.clone().unwrap_or_default()];
            dev.evict_control(
                job,
                auth_handle,
                transient_handle,
                persistent_handle,
                &mut auths,
            )
            .map_err(CommandError::Device)?;

            job.key_cache.remove_context(vhandle)?;

            Ok(())
        })
    }
}
