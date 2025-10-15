// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use super::CommandError;
use crate::{
    cli::{get_auth, SubCommand},
    context::ContextCache,
    convert::{from_input_to_bytes, from_tpm_key_to_output},
    device::{self, Device},
    uri::Uri,
};
use argh::FromArgs;
use std::{cell::RefCell, rc::Rc};
use tpm2_protocol::data::TpmSe;

/// Converts external key files to TPMKey files.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "convert")]
pub struct Convert {
    /// parent: 'tpm:<handle>', or 'key:<name grip>'
    #[argh(positional)]
    pub parent: Uri,

    /// input: PKCS#1, PKCS#8 or SEC1 key file
    #[argh(positional)]
    pub input: Option<Uri>,

    /// output: TPMKey file
    #[argh(option, short = 'o')]
    pub output: Option<Uri>,

    /// parent auth: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_PARENT_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'p')]
    pub parent_auth: Option<String>,

    /// auth: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'a')]
    pub auth: Option<String>,

    /// hmac auth: 'password:<hex>' or 'session:<handle>'
    /// Uses TPM2SH_HMAC_AUTH environment variable if not set.
    #[argh(option, arg_name = "auth", short = 'm', long = "hmac-auth")]
    pub hmac_auth: Option<String>,
}

impl SubCommand for Convert {
    fn run(
        &self,
        device: Option<Rc<RefCell<Device>>>,
        context: &mut ContextCache,
        _plain: bool,
    ) -> Result<(), CommandError> {
        let parent_auth = get_auth(
            self.parent_auth.as_ref(),
            "TPM2SH_PARENT_AUTH",
            &context.session_map,
            &[TpmSe::Policy],
        )?;
        device::with_device(device, |device| {
            let input_bytes = from_input_to_bytes(self.input.as_ref())?;
            let parent_handle = context.load_parent(device, &self.parent)?;
            let tpm_key =
                context.import_key(device, parent_handle, &input_bytes, &[parent_auth])?;
            from_tpm_key_to_output(context, &tpm_key, self.output.as_ref())
        })
    }
}
