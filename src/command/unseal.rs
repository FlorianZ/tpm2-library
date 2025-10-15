// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use super::CommandError;
use crate::{
    cli::{build_auth_list, SubCommand},
    context::ContextCache,
    device::{self, Device, DeviceError},
    uri::Uri,
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc, str::FromStr};
use tpm2_protocol::{data::TpmCc, message::TpmUnsealCommand};

/// Retrieves data from a sealed data object.
#[derive(FromArgs, Debug)]
#[argh(
    subcommand,
    name = "unseal",
    note = "Retrieves data from a sealed data object."
)]
pub struct Unseal {
    /// input: 'tpm:<handle>' or 'key:<grip>'
    #[argh(positional)]
    pub input: String,

    /// auth for the sealed object: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<String>,

    /// hmac auth: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_HMAC_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'm', long = "hmac-auth")]
    pub hmac_auth: Option<String>,
}

impl SubCommand for Unseal {
    /// `unseal` requires authorization for the sealed object itself.
    ///
    /// 1.  The sealed object's context is loaded into the TPM if it is not
    ///     already active. This step does not require authorization.
    /// 2.  The data is retrieved using `TPM2_Unseal`. This command must be
    ///     authorized by the sealed object's own authorization policy. The
    ///     session provided via `--auth` is used for this step.
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        _plain: bool,
    ) -> Result<(), CommandError> {
        let auth_list = build_auth_list(
            self.auth.as_ref(),
            self.hmac_auth.as_ref(),
            &context.session_map,
        )?;
        device::with_device(device, |device| {
            let input_uri = Uri::from_str(&self.input)?;

            if matches!(input_uri, Uri::Path(_) | Uri::Password(_)) {
                return Err(CommandError::InvalidInput("{input_uri}".to_string()));
            }

            let item_handle = context.load_context(device, &input_uri)?;

            let unseal_cmd = TpmUnsealCommand {
                item_handle: item_handle.0.into(),
            };
            let unseal_handles = [item_handle.0];

            let (unseal_resp, _) =
                context.execute(device, &unseal_cmd, &unseal_handles, &auth_list)?;

            let out_data = unseal_resp
                .Unseal()
                .map_err(|_| DeviceError::ResponseMismatch(TpmCc::Unseal))?
                .out_data;

            context.write_data(None, &out_data)?;

            Ok(())
        })
    }
}
