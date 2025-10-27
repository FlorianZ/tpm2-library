// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::SubCommand,
    command::{deny_too_many_auths, CommandError},
    device::with_device,
    handle::Handle,
    job::Job,
};
use clap::Args;
use tpm2_protocol::data::TpmPt;

/// Exports an endorsement key certificate.
#[derive(Args, Debug)]
pub struct Certificate {
    /// NV-index: 'tpm:<handle>'
    #[arg(value_name = "nv-index")]
    pub nv_index: Handle,
}

impl SubCommand for Certificate {
    fn run(&self, job: &mut Job) -> Result<(), CommandError> {
        deny_too_many_auths(job.auth_list, 1)?;

        with_device(job.device.clone(), |device| {
            let max_read_size = device.get_tpm_property(TpmPt::NvBufferMax)? as usize;
            let handle = self.nv_index.value();
            let auths = job.auth_list;

            if let Some(cert_bytes) = job.read_certificate(device, auths, handle, max_read_size)? {
                let pem_cert = pem::encode(&pem::Pem::new("CERTIFICATE", cert_bytes));
                writeln!(job.writer, "{pem_cert}")?;
            } else {
                log::warn!("{handle:08x}: no certificate");
            }
            Ok(())
        })
    }
}
