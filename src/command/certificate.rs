// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{get_auth, SubCommand},
    command::CommandError,
    context::ContextCache,
    convert::from_str_to_handle,
    device::{self, Device},
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc};
use tpm2_protocol::{data::TpmPt, TpmHandle};

/// Exports an endorsement key certificate.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "certificate")]
pub struct Certificate {
    /// non-volatile (NV) index
    #[argh(positional, arg_name = "nv-index", from_str_fn(from_str_to_handle))]
    pub nv_index: TpmHandle,

    /// auth for the NV index: 'password://<hex>' or 'session://<handle>'
    /// Uses TPM2SH_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<String>,
}

impl SubCommand for Certificate {
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        _plain: bool,
    ) -> Result<(), CommandError> {
        let auth = get_auth(
            self.auth.as_ref(),
            "TPM2SH_AUTH",
            &context.session_map,
            &[tpm2_protocol::data::TpmSe::Policy],
        )?;
        device::with_device(device, |device| {
            let max_read_size = device.get_tpm_property(TpmPt::NvBufferMax)? as usize;

            let handle = self.nv_index.0;

            if let Some(cert_bytes) =
                context.read_certificate(device, &[auth], handle, max_read_size)?
            {
                let pem_cert = pem::encode(&pem::Pem::new("CERTIFICATE", cert_bytes));
                writeln!(context.writer, "{pem_cert}")?;
            } else {
                log::warn!("{handle:08x}: no certificate");
            }
            Ok(())
        })
    }
}
