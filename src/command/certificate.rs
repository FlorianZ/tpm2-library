// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    auth::Auth, cli::SubCommand, command::CommandError, convert::from_str_to_handle,
    device::with_device, job::Job,
};
use argh::FromArgs;
use tpm2_protocol::{data::TpmPt, TpmHandle};

/// Exports an endorsement key certificate.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "certificate")]
pub struct Certificate {
    /// nv-index
    #[argh(positional, arg_name = "nv-index", from_str_fn(from_str_to_handle))]
    pub nv_index: TpmHandle,

    /// nv-index auth: 'password:<hex>' or 'session:<handle>'
    #[argh(option, arg_name = "auth", short = 'p')]
    pub auth: Option<Auth>,
}

impl SubCommand for Certificate {
    fn run(&self, job: &mut Job, _plain: bool) -> Result<(), CommandError> {
        let auth = job.resolve_auth_session(self.auth.clone())?;
        with_device(job.device.clone(), |device| {
            let max_read_size = device.get_tpm_property(TpmPt::NvBufferMax)? as usize;

            let handle = self.nv_index.0;

            if let Some(cert_bytes) =
                job.read_certificate(device, &[auth], handle, max_read_size)?
            {
                let pem_cert = pem::encode(&pem::Pem::new("CERTIFICATE", cert_bytes));
                writeln!(job.context_cache.writer, "{pem_cert}")?;
            } else {
                log::warn!("{handle:08x}: no certificate");
            }
            Ok(())
        })
    }
}
