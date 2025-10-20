// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::SubCommand,
    command::{AuthArgs, CommandError},
    convert::from_str_to_nv_handle,
    device::with_device,
    job::Job,
};
use clap::Args;
use tpm2_protocol::{data::TpmPt, TpmHandle};

/// Exports an endorsement key certificate.
#[derive(Args, Debug)]
pub struct Certificate {
    /// NV-index: 'tpm:<handle>'
    #[arg(value_name = "nv-index", value_parser = from_str_to_nv_handle)]
    pub nv_index: TpmHandle,

    #[clap(flatten)]
    pub auth_args: AuthArgs,
}

impl SubCommand for Certificate {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        with_device(job.device.clone(), |device| {
            let max_read_size = device.get_tpm_property(TpmPt::NvBufferMax)? as usize;
            let handle = self.nv_index.0;
            let mut auths = vec![self.auth_args.auth.clone().unwrap_or_default()];
            if let Some(cert_bytes) =
                job.read_certificate(device, &mut auths, handle, max_read_size)?
            {
                let pem_cert = pem::encode(&pem::Pem::new("CERTIFICATE", cert_bytes));
                writeln!(job.key_cache.writer, "{pem_cert}")?;
            } else {
                log::warn!("{handle:08x}: no certificate");
            }
            Ok(())
        })
    }
}
